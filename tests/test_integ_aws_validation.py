"""Integration test: validate our output with the AWS Security Lake OCSF tool.

This shells out to aws-samples/amazon-security-lake-ocsf-validation, the tool
AWS points custom sources at to confirm OCSF compatibility. It proves -- against
AWS's own validator, not just our internal checks -- that an emitted detection
finding is accepted.

The tool and its schema fetch require network access, so this test is skipped
unless ``OCSF_AWS_VALIDATION_DIR`` points at a checkout of the tool with its
dependencies importable (the CI job sets this up; see .github/workflows/ci.yml).
Run locally with:

    OCSF_AWS_VALIDATION_DIR=/path/to/amazon-security-lake-ocsf-validation \\
        uv run pytest tests/test_integ_aws_validation.py -v
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import ocsf_emitter
from ocsf_emitter import (
    Activity,
    Confidence,
    MitreAttack,
    Observable,
    ObservableType,
    RiskLevel,
    Severity,
    Status,
    build_detection_finding,
    emit,
)

TOOL_DIR = os.environ.get("OCSF_AWS_VALIDATION_DIR")

pytestmark = pytest.mark.skipif(
    not TOOL_DIR or not Path(TOOL_DIR, "validate.py").is_file(),
    reason="Set OCSF_AWS_VALIDATION_DIR to a checkout of the AWS OCSF validation tool.",
)


def _sample_payload() -> dict[str, object]:
    product = ocsf_emitter.make_product(
        name="Example Detector", vendor_name="Example, Inc.", version="1.0.0"
    )
    finding = build_detection_finding(
        uid="det-integ-001",
        title="Impossible-travel login",
        severity=Severity.HIGH,
        message="User alice logged in from two continents within 4 minutes.",
        status=Status.NEW,
        activity=Activity.CREATE,
        observables=[
            Observable(ObservableType.USER_NAME, "alice"),
            Observable(ObservableType.IP_ADDRESS, "203.0.113.7"),
        ],
        description="Geo-velocity rule R-42 fired.",
        data_sources=["okta.system_log"],
        confidence=Confidence.HIGH,
        risk_level=RiskLevel.HIGH,
        attacks=[MitreAttack("T1078", "Valid Accounts", "TA0001", "Initial Access")],
        time_ms=1_752_566_400_000,
        product=product,
    )
    return emit(finding)


def test_emitted_finding_is_valid_per_aws_tool(tmp_path: Path) -> None:
    assert TOOL_DIR is not None  # guarded by pytestmark
    target = tmp_path / "records"
    target.mkdir()
    (target / "finding.json").write_text(json.dumps(_sample_payload()))

    result = subprocess.run(  # noqa: S603
        [sys.executable, "validate.py", "-i", str(target)],
        cwd=TOOL_DIR,
        capture_output=True,
        text=True,
        timeout=180,
    )

    combined = result.stdout + result.stderr
    # The tool prints "VALID OCSF." to stdout and "INVALID OCSF." when it fails;
    # it also sys.exit()s (traceback) on structural/version problems.
    assert "INVALID OCSF" not in combined, f"AWS tool reported INVALID:\n{combined}"
    assert "VALID OCSF" in combined, f"AWS tool did not report VALID:\n{combined}"
    assert result.returncode == 0, f"AWS tool exited {result.returncode}:\n{combined}"
