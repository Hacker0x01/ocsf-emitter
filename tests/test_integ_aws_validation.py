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
    ApiCall,
    ComplianceRef,
    Confidence,
    DeviceRef,
    EndpointRef,
    FileRef,
    MitreAttack,
    Observable,
    ObservableType,
    RiskLevel,
    Severity,
    Status,
    UserRef,
    WebResourceRef,
    build_account_change,
    build_api_activity,
    build_authentication,
    build_compliance_finding,
    build_detection_finding,
    build_file_hosting,
    build_patch_state,
    build_web_resources_activity,
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


def _all_class_payloads() -> dict[str, dict[str, object]]:
    """One emitted payload per supported OCSF class, keyed by a short name.

    NOTE: AWS Security Lake historically maps only ``detection_finding`` for
    custom sources; the other classes are validated here for OCSF-schema
    conformance via the same tool, which validates any class it can resolve.
    """
    product = ocsf_emitter.make_product(
        name="Example Detector", vendor_name="Example, Inc.", version="1.0.0"
    )
    sev = Severity.MEDIUM
    when = 1_752_566_400_000
    return {
        "detection_finding": _sample_payload(),
        "compliance_finding": emit(
            build_compliance_finding(
                title="NTP not synchronized",
                compliance=ComplianceRef(standards=["CIS"], control="2.1"),
                severity=sev,
                product=product,
                time_ms=when,
            )
        ),
        "authentication": emit(
            build_authentication(
                user=UserRef(name="alice", email="a@example.com"),
                severity=sev,
                product=product,
                time_ms=when,
            )
        ),
        "account_change": emit(
            build_account_change(
                user=UserRef(name="bob"), severity=sev, product=product, time_ms=when
            )
        ),
        "patch_state": emit(
            build_patch_state(
                device=DeviceRef(hostname="web01", os_name="ubuntu", os_version="22.04"),
                severity=sev,
                product=product,
                time_ms=when,
            )
        ),
        "api_activity": emit(
            build_api_activity(
                api=ApiCall(operation="CreateAccessKey", service="iam.amazonaws.com"),
                src_endpoint=EndpointRef(ip="203.0.113.7"),
                actor_user=UserRef(name="root"),
                severity=sev,
                product=product,
                time_ms=when,
            )
        ),
        "web_resources_activity": emit(
            build_web_resources_activity(
                web_resources=[WebResourceRef(name="report-123", type="report")],
                severity=sev,
                product=product,
                time_ms=when,
            )
        ),
        "file_hosting": emit(
            build_file_hosting(
                file=FileRef(name="secret.pdf", mime_type="application/pdf"),
                src_endpoint=EndpointRef(ip="198.51.100.9"),
                # OCSF `user` requires anyOf(name|uid|account); supply a name.
                actor_user=UserRef(name="alice", email="a@example.com"),
                severity=sev,
                product=product,
                time_ms=when,
            )
        ),
    }


def _run_validator(target: Path) -> str:
    assert TOOL_DIR is not None  # guarded by pytestmark
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
    return combined


def test_emitted_finding_is_valid_per_aws_tool(tmp_path: Path) -> None:
    target = tmp_path / "records"
    target.mkdir()
    (target / "finding.json").write_text(json.dumps(_sample_payload()))
    _run_validator(target)


# Two classes fail the pinned AWS validator (commit 3811c95e, the latest as of
# 2025-02) through bugs *in the tool*, not in our output -- confirmed by fetching
# the same live schema the tool uses and running jsonschema directly:
#
#   * patch_state (5004): the tool's hardcoded ocsf_class_dictionary maps 5004 to
#     class_name "Device Config State Change". Real OCSF 1.1.0 names 5004
#     "Operating System Patch State" (5019 is "Device Config State Change"); the
#     tool copied the wrong name into the 5004 row, so its sibling check exits.
#   * api_activity (6003): the schema the tool fetches from
#     schema.ocsf.io/schema/1.1.0/classes/api_activity omits the `api` property
#     entirely, yet `api` is a required base attribute per the OCSF metaschema and
#     the class docs. With additionalProperties=False, our (correct) `api` field
#     is rejected as unexpected.
#
# We emit spec-correct OCSF for both, so we xfail rather than distort the output.
# strict=True flips these to a hard failure if a future tool bump fixes them --
# the signal to remove this marker. AWS Security Lake custom sources have
# historically mapped only detection_finding anyway.
_AWS_TOOL_BROKEN_CLASSES = {"patch_state", "api_activity"}


def _class_param(class_name: str) -> object:
    if class_name in _AWS_TOOL_BROKEN_CLASSES:
        return pytest.param(
            class_name,
            marks=pytest.mark.xfail(
                strict=True,
                reason=(
                    "Pinned AWS validation tool (3811c95e) is wrong for this class: "
                    "5004 has the wrong class_name in its table / 6003's served schema "
                    "omits the required `api` field. Our OCSF output is correct."
                ),
            ),
        )
    return class_name


@pytest.mark.parametrize("class_name", [_class_param(name) for name in _all_class_payloads()])
def test_every_class_is_valid_per_aws_tool(class_name: str, tmp_path: Path) -> None:
    target = tmp_path / "records"
    target.mkdir()
    (target / f"{class_name}.json").write_text(json.dumps(_all_class_payloads()[class_name]))
    _run_validator(target)
