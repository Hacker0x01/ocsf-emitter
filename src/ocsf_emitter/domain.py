"""Our internal domain shapes -- the *input* side of the builder.

Callers construct these from their own data and hand them to
``build_detection_finding``. They deliberately use our vocabulary (the enums in
``defaults``) and hide OCSF's ``*_id`` integers, so producing services never
touch OCSF field names directly.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from .defaults import Activity, Confidence, RiskLevel, Severity, Status


class ObservableType(enum.Enum):
    """The observable kinds we currently emit, mapped to OCSF observable type_id.

    (OCSF defines ~48 types; we expose the subset our detectors produce. Add
    members here and to ``_OBSERVABLE_TYPE_TO_ID`` in ``builders`` as needed.)
    """

    UNKNOWN = "unknown"
    HOSTNAME = "hostname"
    IP_ADDRESS = "ip_address"
    URL = "url"
    FILE_HASH = "file_hash"
    FILE_NAME = "file_name"
    USER_NAME = "user_name"
    EMAIL_ADDRESS = "email_address"
    PROCESS_NAME = "process_name"
    RESOURCE_UID = "resource_uid"


@dataclass(frozen=True, slots=True)
class Observable:
    """An entity a finding refers to (host, IP, user, hash, ...)."""

    type: ObservableType
    value: str
    name: str | None = None


@dataclass(frozen=True, slots=True)
class MitreAttack:
    """A MITRE ATT&CK reference (technique, optionally its tactic).

    Maps to an entry in OCSF ``finding_info.attacks``.
    """

    technique_uid: str  # e.g. "T1078"
    technique_name: str | None = None
    tactic_uid: str | None = None  # e.g. "TA0001"
    tactic_name: str | None = None


@dataclass(frozen=True, slots=True)
class DetectionSignal:
    """A detection our services produce, in our own terms.

    This is the single input shape ``build_detection_finding`` maps from. It is
    intentionally small and OCSF-agnostic; the builder is responsible for the
    translation to class_uid 2004.
    """

    # Identity + human-facing summary.
    uid: str
    title: str
    severity: Severity
    message: str

    # What kind of lifecycle event this is (drives activity_id / type_uid).
    activity: Activity = Activity.CREATE
    # Triage state (drives status_id).
    status: Status = Status.NEW

    # Entities involved in the detection.
    observables: list[Observable] = field(default_factory=list)

    # Optional richer detail.
    description: str | None = None
    # Event time as a UNIX epoch in **milliseconds** (OCSF's convention). When
    # None, the builder stamps it from an injected clock.
    time_ms: int | None = None
    # Free-form provenance surfaced under finding_info.data_sources.
    data_sources: list[str] = field(default_factory=list)

    # --- common extras ---
    # Detector confidence in this finding (-> confidence_id / confidence_score).
    confidence: Confidence | None = None
    confidence_score: int | None = None
    # Risk assessment (-> risk_level_id / risk_score).
    risk_level: RiskLevel | None = None
    risk_score: int | None = None
    # MITRE ATT&CK references (-> finding_info.attacks).
    attacks: list[MitreAttack] = field(default_factory=list)
    # Number of times this detection has been observed (-> count).
    count: int | None = None
    # First/last time the underlying activity was seen, epoch ms
    # (-> finding_info.first_seen_time / last_seen_time).
    first_seen_ms: int | None = None
    last_seen_ms: int | None = None
