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
class UserRef:
    """A user/principal a finding refers to. Maps to an OCSF ``user`` object.

    Used by the IAM classes (Authentication 3002, Account Change 3001) and,
    where relevant, other classes. All fields optional -- OCSF ``user`` has no
    required attributes.
    """

    name: str | None = None
    uid: str | None = None
    email: str | None = None
    domain: str | None = None
    full_name: str | None = None


@dataclass(frozen=True, slots=True)
class DeviceRef:
    """A device/host a finding refers to. Maps to an OCSF ``device`` object.

    Used by Operating System Patch State (5004), which additionally constrains
    "at least one of os.sp_name / os.sp_ver / os.version". Supply ``os_version``
    (and/or the sp fields) to satisfy it. OCSF ``device`` requires ``type_id``;
    it defaults to 0 (Unknown) when not given.
    """

    hostname: str | None = None
    uid: str | None = None
    type_id: int = 0
    os_name: str | None = None
    os_version: str | None = None
    os_type_id: int = 0
    os_sp_name: str | None = None
    os_sp_ver: str | None = None


@dataclass(frozen=True, slots=True)
class FileRef:
    """A file a finding refers to. Maps to an OCSF ``file`` object.

    Used by File Hosting Activity (6006). OCSF ``file`` requires ``name`` and
    ``type_id`` (1 = Regular File by default).
    """

    name: str
    type_id: int = 1
    mime_type: str | None = None
    uid: str | None = None
    path: str | None = None


@dataclass(frozen=True, slots=True)
class ApiCall:
    """An API operation a finding refers to. Maps to an OCSF ``api`` object.

    Used by API Activity (6003). OCSF ``api`` requires ``operation``.
    """

    operation: str
    service: str | None = None
    version: str | None = None


@dataclass(frozen=True, slots=True)
class WebResourceRef:
    """A web resource a finding refers to. Maps to an OCSF ``web_resource`` object.

    Used by Web Resources Activity (6001). All fields optional in OCSF.
    """

    name: str | None = None
    type: str | None = None
    uid: str | None = None
    url_string: str | None = None


@dataclass(frozen=True, slots=True)
class EndpointRef:
    """A network endpoint a finding refers to. Maps to an OCSF ``network_endpoint``.

    Used as ``src_endpoint`` by API Activity (6003) and File Hosting (6006). All
    fields optional in OCSF.
    """

    ip: str | None = None
    hostname: str | None = None
    port: int | None = None
    uid: str | None = None


@dataclass(frozen=True, slots=True)
class ComplianceRef:
    """A compliance assessment. Maps to an OCSF ``compliance`` object.

    Used by Compliance Finding (2003). OCSF ``compliance`` requires
    ``standards`` (a list of standard identifiers, e.g. ``["CIS", "PCI DSS"]``).
    """

    standards: list[str]
    control: str | None = None
    status: str | None = None


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
