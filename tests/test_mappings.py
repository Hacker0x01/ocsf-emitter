"""Unit tests for each enum -> OCSF *_id mapping function."""

from __future__ import annotations

import pytest

from ocsf_emitter import defaults
from ocsf_emitter.defaults import Activity, Confidence, RiskLevel, Severity, Status


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        (Severity.UNKNOWN, 0),
        (Severity.INFORMATIONAL, 1),
        (Severity.LOW, 2),
        (Severity.MEDIUM, 3),
        (Severity.HIGH, 4),
        (Severity.CRITICAL, 5),
        (Severity.FATAL, 6),
    ],
)
def test_severity_id(severity: Severity, expected: int) -> None:
    assert defaults.severity_id(severity).value == expected


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (Status.UNKNOWN, 0),
        (Status.NEW, 1),
        (Status.IN_PROGRESS, 2),
        (Status.SUPPRESSED, 3),
        (Status.RESOLVED, 4),
    ],
)
def test_status_id(status: Status, expected: int) -> None:
    assert defaults.status_id(status).value == expected


@pytest.mark.parametrize(
    ("activity", "expected"),
    [
        (Activity.UNKNOWN, 0),
        (Activity.CREATE, 1),
        (Activity.UPDATE, 2),
        (Activity.CLOSE, 3),
    ],
)
def test_activity_id(activity: Activity, expected: int) -> None:
    assert defaults.activity_id(activity).value == expected


@pytest.mark.parametrize(
    ("confidence", "expected"),
    [
        (Confidence.UNKNOWN, 0),
        (Confidence.LOW, 1),
        (Confidence.MEDIUM, 2),
        (Confidence.HIGH, 3),
    ],
)
def test_confidence_id(confidence: Confidence, expected: int) -> None:
    assert defaults.confidence_id(confidence).value == expected


@pytest.mark.parametrize(
    ("risk", "expected"),
    [
        (RiskLevel.INFO, 0),
        (RiskLevel.LOW, 1),
        (RiskLevel.MEDIUM, 2),
        (RiskLevel.HIGH, 3),
        (RiskLevel.CRITICAL, 4),
    ],
)
def test_risk_level_id(risk: RiskLevel, expected: int) -> None:
    assert defaults.risk_level_id(risk).value == expected


@pytest.mark.parametrize(
    ("activity", "expected"),
    [
        (Activity.CREATE, 200401),
        (Activity.UPDATE, 200402),
        (Activity.CLOSE, 200403),
    ],
)
def test_type_uid(activity: Activity, expected: int) -> None:
    assert defaults.type_uid(activity) == expected


def test_every_domain_enum_member_is_mapped() -> None:
    # A missing mapping should raise KeyError, so this proves totality.
    for s in Severity:
        defaults.severity_id(s)
    for st in Status:
        defaults.status_id(st)
    for a in Activity:
        defaults.activity_id(a)
    for c in Confidence:
        defaults.confidence_id(c)
    for r in RiskLevel:
        defaults.risk_level_id(r)
