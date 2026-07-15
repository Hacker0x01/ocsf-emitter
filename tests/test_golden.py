"""Golden-sample test.

``tests/golden_detection_finding.json`` is a human-readable OCSF Detection
Finding a reviewer can eyeball against the class_uid 2004 spec. This test proves
the builder still produces exactly that payload, and that the payload validates.
"""

from __future__ import annotations

import json
from pathlib import Path

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
from ocsf_emitter._models import DetectionFinding

GOLDEN_PATH = Path(__file__).parent / "golden_detection_finding.json"


def _golden_finding() -> DetectionFinding:
    return build_detection_finding(
        uid="det-2026-0715-001",
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
        confidence_score=95,
        risk_level=RiskLevel.HIGH,
        risk_score=80,
        attacks=[MitreAttack("T1078", "Valid Accounts", "TA0001", "Initial Access")],
        count=1,
        time_ms=1_752_566_400_000,
        product=ocsf_emitter.make_product(
            name="Example Detector", vendor_name="Example, Inc.", version="1.0.0"
        ),
    )


def test_matches_golden_sample() -> None:
    payload = emit(_golden_finding())
    expected = json.loads(GOLDEN_PATH.read_text())
    assert payload == expected, (
        "Emitted payload drifted from the golden sample. If this change is "
        "intended, regenerate tests/golden_detection_finding.json and review the diff."
    )
