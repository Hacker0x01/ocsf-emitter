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
    """Every OCSF observable ``type_id`` (schema 1.5.0), by our vocabulary name.

    Members mirror the full ``observable.type_id`` enum; each maps to its OCSF
    ``type_id`` int in ``_OBSERVABLE_TYPE_TO_ID`` (``builders``). The member value
    is the human name used as the fallback ``observable.name`` when a caller
    doesn't supply one. Kept in sync with the schema by
    ``tests/test_observables.py``.
    """

    # "Observable by Dictionary Type" (0-12, 45-46) + core scalars.
    UNKNOWN = "unknown"  # 0
    HOSTNAME = "hostname"  # 1
    IP_ADDRESS = "ip_address"  # 2
    MAC_ADDRESS = "mac_address"  # 3
    USER_NAME = "user_name"  # 4
    EMAIL_ADDRESS = "email_address"  # 5
    URL = "url"  # 6 (URL String)
    FILE_NAME = "file_name"  # 7
    FILE_HASH = "file_hash"  # 8 (Hash)
    PROCESS_NAME = "process_name"  # 9
    RESOURCE_UID = "resource_uid"  # 10
    PORT = "port"  # 11
    SUBNET = "subnet"  # 12
    # "Observable by Dictionary Attribute" (13-16, 19, 36-37, 42, 45-46).
    COMMAND_LINE = "command_line"  # 13
    COUNTRY = "country"  # 14
    PROCESS_ID = "process_id"  # 15
    HTTP_USER_AGENT = "http_user_agent"  # 16
    USER_CREDENTIAL_ID = "user_credential_id"  # 19
    SCRIPT_CONTENT = "script_content"  # 36
    SERIAL_NUMBER = "serial_number"  # 37
    MESSAGE_UID = "message_uid"  # 42
    FILE_PATH = "file_path"  # 45
    REGISTRY_KEY_PATH = "registry_key_path"  # 46
    # "Observable by Object-Specific Attribute" (17-18, 31-35, 38-41, 43-44).
    CWE_UID = "cwe_uid"  # 17
    CVE_UID = "cve_uid"  # 18
    USER_UID = "user_uid"  # 31
    GROUP_NAME = "group_name"  # 32
    GROUP_UID = "group_uid"  # 33
    ACCOUNT_NAME = "account_name"  # 34
    ACCOUNT_UID = "account_uid"  # 35
    RESOURCE_DETAILS_NAME = "resource_details_name"  # 38
    PROCESS_ENTITY_UID = "process_entity_uid"  # 39
    EMAIL_SUBJECT = "email_subject"  # 40
    EMAIL_UID = "email_uid"  # 41
    REGISTRY_VALUE_NAME = "registry_value_name"  # 43
    ADVISORY_UID = "advisory_uid"  # 44
    # "Observable by Object" (20-30).
    ENDPOINT = "endpoint"  # 20
    USER = "user"  # 21
    EMAIL = "email"  # 22
    URL_OBJECT = "url_object"  # 23 (Uniform Resource Locator object)
    FILE = "file"  # 24
    PROCESS = "process"  # 25
    GEO_LOCATION = "geo_location"  # 26
    CONTAINER = "container"  # 27
    REGISTRY_KEY = "registry_key"  # 28
    REGISTRY_VALUE = "registry_value"  # 29
    FINGERPRINT = "fingerprint"  # 30
    # Catch-all.
    OTHER = "other"  # 99


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


# --------------------------------------------------------------------------- #
# Domain refs for the wider class set. Each maps to an OCSF object; required
# sub-fields are carried (``*_id`` default to 0/Unknown -- set them for real
# events). Fields are the common-case subset, not every OCSF attribute.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class ProcessRef:
    """A process. Maps to an OCSF ``process`` object (no required sub-fields)."""

    name: str | None = None
    pid: int | None = None
    cmd_line: str | None = None
    uid: str | None = None


@dataclass(frozen=True, slots=True)
class EmailRef:
    """An email message. Maps to an OCSF ``email`` object (no required sub-fields)."""

    from_addr: str | None = None
    to: list[str] | None = None
    subject: str | None = None
    uid: str | None = None


@dataclass(frozen=True, slots=True)
class VulnerabilityRef:
    """A vulnerability. Maps to an OCSF ``vulnerability`` object (no required sub-fields)."""

    title: str | None = None
    severity: str | None = None
    desc: str | None = None
    cve_uid: str | None = None


@dataclass(frozen=True, slots=True)
class ConnectionInfoRef:
    """A network connection. Maps to ``network_connection_info`` (requires ``direction_id``)."""

    direction_id: int = 0
    protocol_name: str | None = None
    uid: str | None = None


@dataclass(frozen=True, slots=True)
class GroupRef:
    """A group. Maps to an OCSF ``group`` object (no required sub-fields)."""

    name: str | None = None
    uid: str | None = None
    type: str | None = None


@dataclass(frozen=True, slots=True)
class JobRef:
    """A scheduled job. Maps to an OCSF ``job`` object (requires ``name`` and ``file``)."""

    name: str
    file: FileRef
    cmd_line: str | None = None
    desc: str | None = None


@dataclass(frozen=True, slots=True)
class KernelRef:
    """A kernel resource. Maps to an OCSF ``kernel`` object (requires ``name``, ``type_id``)."""

    name: str
    type_id: int = 0
    path: str | None = None


@dataclass(frozen=True, slots=True)
class ModuleRef:
    """A loaded module. Maps to an OCSF ``module`` object (requires ``load_type_id``)."""

    load_type_id: int = 0
    base_address: str | None = None
    file: FileRef | None = None


@dataclass(frozen=True, slots=True)
class ScriptRef:
    """A script. Maps to an OCSF ``script`` object (requires ``script_content``, ``type_id``)."""

    script_content: str
    type_id: int = 0
    name: str | None = None


@dataclass(frozen=True, slots=True)
class ScanRef:
    """A scan. Maps to an OCSF ``scan`` object (requires ``type_id``)."""

    type_id: int = 0
    name: str | None = None
    uid: str | None = None


@dataclass(frozen=True, slots=True)
class OsintRef:
    """OSINT indicator. Maps to an OCSF ``osint`` object (requires ``type_id``, ``value``)."""

    value: str
    type_id: int = 0
    desc: str | None = None


@dataclass(frozen=True, slots=True)
class ManagedEntityRef:
    """A managed entity. Maps to an OCSF ``managed_entity`` object (no required sub-fields)."""

    name: str | None = None
    uid: str | None = None
    type: str | None = None
    type_id: int | None = None


@dataclass(frozen=True, slots=True)
class QueryEvidenceRef:
    """Live-evidence query result. Maps to ``query_evidence`` (requires ``query_type_id``)."""

    query_type_id: int = 0
    query_type: str | None = None


@dataclass(frozen=True, slots=True)
class KernelDriverRef:
    """A kernel driver. Maps to an OCSF ``kernel_driver`` object (requires ``file``)."""

    file: FileRef


@dataclass(frozen=True, slots=True)
class UasRef:
    """An unmanned aerial system. Maps to ``unmanned_aerial_system`` (no required sub-fields)."""

    uid: str | None = None
    name: str | None = None
    model: str | None = None
    serial_number: str | None = None


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
