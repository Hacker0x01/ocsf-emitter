"""Consistent defaults and enum mappings for OCSF Detection Findings.

Everything version- or product-specific lives here, so that pinning/bumping the
OCSF schema version and adjusting our house defaults is a one-file change.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from . import _models as _m

# --------------------------------------------------------------------------- #
# OCSF version pin.
#
# Bumping the target OCSF version is a ONE-LINE change here -- then regenerate
# the models with `uv run --extra codegen python scripts/gen_models.py <version>`
# so the committed _models.py matches.
#
# Pinned to 1.1.0 for AWS Security Lake compatibility: custom sources accept
# OCSF 1.1.0 / 1.0.0-rc.2, and the AWS OCSF validation tool only validates those
# (detection_finding is mapped only under 1.1.0). See README.
# --------------------------------------------------------------------------- #
OCSF_SCHEMA_VERSION = "1.1.0"

# Detection Finding class identity (OCSF Findings category). Fixed by the OCSF
# spec for class_uid 2004. In the generated model these are IntEnums, so we hold
# the ints here and coerce at build time.
CLASS_UID = 2004
CATEGORY_UID = 2
# type_uid = class_uid * 100 + activity_id (OCSF convention).
TYPE_UID_BASE = CLASS_UID * 100

# Sibling name fields for the *_uid enums. These are the human-readable labels
# OCSF pairs with class_uid/category_uid. AWS Security Lake (and its OCSF
# validation tool) expect category_name to be present and class_name, if set, to
# match the class. Values are fixed by the OCSF 2004 spec.
#
# These module-level constants are retained for backward compatibility and refer
# to the Detection Finding class; the multi-class machinery below derives the
# same values from the class registry.
CLASS_NAME = "Detection Finding"
CATEGORY_NAME = "Findings"


# --------------------------------------------------------------------------- #
# Supported OCSF classes and their identity registry.
#
# The library builds/validates/emits each class below. Every class's identity
# (class_uid, category_uid, and the sibling name fields) lives here so adding a
# class is a registry entry plus a builder. Keep ``ROOT_CLASSES`` in
# ``scripts/gen_models.py`` in sync with the keys here.
# --------------------------------------------------------------------------- #
class OcsfClass(enum.Enum):
    """The OCSF classes this library supports, keyed by metaschema name."""

    DETECTION_FINDING = "detection_finding"
    COMPLIANCE_FINDING = "compliance_finding"
    AUTHENTICATION = "authentication"
    ACCOUNT_CHANGE = "account_change"
    PATCH_STATE = "patch_state"
    API_ACTIVITY = "api_activity"
    WEB_RESOURCES_ACTIVITY = "web_resources_activity"
    FILE_HOSTING = "file_hosting"


@dataclass(frozen=True, slots=True)
class ClassSpec:
    """Fixed OCSF identity for one class (uids + sibling name fields)."""

    ocsf_class: OcsfClass
    class_uid: int
    category_uid: int
    class_name: str
    category_name: str

    def type_uid(self, activity_id_value: int) -> int:
        """OCSF ``type_uid`` = class_uid * 100 + activity_id."""
        return self.class_uid * 100 + activity_id_value


# Category name siblings, per the OCSF 1.1.0 categories:
#   Findings (2), Identity & Access Management (3), Discovery (5),
#   Application Activity (6).
_CLASS_REGISTRY: dict[OcsfClass, ClassSpec] = {
    OcsfClass.DETECTION_FINDING: ClassSpec(
        OcsfClass.DETECTION_FINDING, 2004, 2, "Detection Finding", "Findings"
    ),
    OcsfClass.COMPLIANCE_FINDING: ClassSpec(
        OcsfClass.COMPLIANCE_FINDING, 2003, 2, "Compliance Finding", "Findings"
    ),
    OcsfClass.AUTHENTICATION: ClassSpec(
        OcsfClass.AUTHENTICATION, 3002, 3, "Authentication", "Identity & Access Management"
    ),
    OcsfClass.ACCOUNT_CHANGE: ClassSpec(
        OcsfClass.ACCOUNT_CHANGE, 3001, 3, "Account Change", "Identity & Access Management"
    ),
    OcsfClass.PATCH_STATE: ClassSpec(
        OcsfClass.PATCH_STATE, 5004, 5, "Operating System Patch State", "Discovery"
    ),
    OcsfClass.API_ACTIVITY: ClassSpec(
        OcsfClass.API_ACTIVITY, 6003, 6, "API Activity", "Application Activity"
    ),
    OcsfClass.WEB_RESOURCES_ACTIVITY: ClassSpec(
        OcsfClass.WEB_RESOURCES_ACTIVITY, 6001, 6, "Web Resources Activity", "Application Activity"
    ),
    OcsfClass.FILE_HOSTING: ClassSpec(
        OcsfClass.FILE_HOSTING, 6006, 6, "File Hosting Activity", "Application Activity"
    ),
}

# Reverse index for validation (look a finding's class up by its class_uid int).
_CLASS_BY_UID: dict[int, ClassSpec] = {spec.class_uid: spec for spec in _CLASS_REGISTRY.values()}


def class_spec(ocsf_class: OcsfClass) -> ClassSpec:
    """Return the :class:`ClassSpec` for a supported OCSF class."""
    return _CLASS_REGISTRY[ocsf_class]


def class_spec_by_uid(class_uid_value: int) -> ClassSpec | None:
    """Return the :class:`ClassSpec` for a ``class_uid`` int, or None if unsupported."""
    return _CLASS_BY_UID.get(class_uid_value)


# --------------------------------------------------------------------------- #
# Product identity.
#
# This library is not tied to any one service, so the emitting product is
# configurable rather than hardcoded. Set it once at process startup with
# ``configure_product(...)``, or pass ``product=`` per call to the builder.
# Until configured it is None, and building a finding without an explicit
# product raises a clear error (rather than mislabelling the source).
# --------------------------------------------------------------------------- #
_DEFAULT_PRODUCT: _m.Product | None = None


def configure_product(
    *,
    name: str,
    vendor_name: str,
    version: str | None = None,
    uid: str | None = None,
) -> _m.Product:
    """Set the process-wide default Product stamped onto findings.

    Call once at startup. ``version`` defaults to the pinned OCSF schema version
    if omitted. Returns the constructed Product for convenience.
    """
    global _DEFAULT_PRODUCT
    _DEFAULT_PRODUCT = make_product(name=name, vendor_name=vendor_name, version=version, uid=uid)
    return _DEFAULT_PRODUCT


def make_product(
    *,
    name: str,
    vendor_name: str,
    version: str | None = None,
    uid: str | None = None,
) -> _m.Product:
    """Construct an OCSF Product block from our fields (does not set the default)."""
    return _m.Product(
        name=name,
        vendor_name=vendor_name,
        version=version if version is not None else OCSF_SCHEMA_VERSION,
        uid=uid,
    )


def default_product() -> _m.Product | None:
    """Return the process-wide default Product, or None if unconfigured."""
    return _DEFAULT_PRODUCT


def default_metadata(product: _m.Product) -> _m.Metadata:
    """Metadata block carrying the pinned schema version and the given product."""
    return _m.Metadata(product=product, version=OCSF_SCHEMA_VERSION)


# --------------------------------------------------------------------------- #
# Our domain enums -> OCSF *_id mappings.
#
# These are the single source of truth for how our vocabulary maps onto OCSF.
# --------------------------------------------------------------------------- #
class Severity(enum.Enum):
    """Our severity vocabulary. Maps to OCSF severity_id (0,1,2..6,99)."""

    UNKNOWN = "unknown"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    FATAL = "fatal"


class Status(enum.Enum):
    """Our finding status vocabulary. Maps to OCSF status_id."""

    UNKNOWN = "unknown"
    NEW = "new"
    IN_PROGRESS = "in_progress"
    SUPPRESSED = "suppressed"
    RESOLVED = "resolved"


class Activity(enum.Enum):
    """Our finding activity vocabulary (Findings classes). Maps to OCSF activity_id.

    Shared by Detection Finding (2004) and Compliance Finding (2003), whose
    activity_id enums are identical: 1 Create, 2 Update, 3 Close.
    """

    UNKNOWN = "unknown"
    CREATE = "create"
    UPDATE = "update"
    CLOSE = "close"


# Per-class action enums for the non-Findings classes. Each is an IntEnum whose
# *value is the OCSF activity_id*, so no name->id table is needed: pass the
# member straight into the builder and its ``.value`` becomes activity_id (and
# feeds type_uid). Named ``...Action`` (not ``Activity``) to avoid clashing with
# the generated model class names (ApiActivity, WebResourcesActivity, ...).
# Values are fixed by the OCSF 1.1.0 spec for each class.
class AuthAction(enum.IntEnum):
    """Authentication (3002) activity_id."""

    UNKNOWN = 0
    LOGON = 1
    LOGOFF = 2
    AUTHENTICATION_TICKET = 3
    SERVICE_TICKET_REQUEST = 4
    SERVICE_TICKET_RENEW = 5
    OTHER = 99


class AccountChangeAction(enum.IntEnum):
    """Account Change (3001) activity_id."""

    UNKNOWN = 0
    CREATE = 1
    ENABLE = 2
    PASSWORD_CHANGE = 3
    PASSWORD_RESET = 4
    DISABLE = 5
    DELETE = 6
    ATTACH_POLICY = 7
    DETACH_POLICY = 8
    LOCK = 9
    MFA_FACTOR_ENABLE = 10
    MFA_FACTOR_DISABLE = 11
    OTHER = 99


class PatchStateAction(enum.IntEnum):
    """Operating System Patch State (5004) activity_id."""

    UNKNOWN = 0
    LOG = 1
    COLLECT = 2
    OTHER = 99


class ApiAction(enum.IntEnum):
    """API Activity (6003) activity_id."""

    UNKNOWN = 0
    CREATE = 1
    READ = 2
    UPDATE = 3
    DELETE = 4
    OTHER = 99


class WebResourceAction(enum.IntEnum):
    """Web Resources Activity (6001) activity_id."""

    UNKNOWN = 0
    CREATE = 1
    READ = 2
    UPDATE = 3
    DELETE = 4
    SEARCH = 5
    IMPORT = 6
    EXPORT = 7
    SHARE = 8
    OTHER = 99


class FileHostingAction(enum.IntEnum):
    """File Hosting Activity (6006) activity_id."""

    UNKNOWN = 0
    UPLOAD = 1
    DOWNLOAD = 2
    UPDATE = 3
    DELETE = 4
    RENAME = 5
    COPY = 6
    MOVE = 7
    RESTORE = 8
    PREVIEW = 9
    LOCK = 10
    UNLOCK = 11
    SHARE = 12
    UNSHARE = 13
    OPEN = 14
    SYNC = 15
    UNSYNC = 16
    OTHER = 99


class Confidence(enum.Enum):
    """Our confidence vocabulary. Maps to OCSF confidence_id."""

    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RiskLevel(enum.Enum):
    """Our risk-level vocabulary. Maps to OCSF risk_level_id."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# OCSF severity_id values (see the Detection Finding spec):
#   0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical, 6 Fatal, 99 Other
_SEVERITY_TO_ID: dict[Severity, int] = {
    Severity.UNKNOWN: 0,
    Severity.INFORMATIONAL: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
    Severity.FATAL: 6,
}

# OCSF status_id: 0 Unknown, 1 New, 2 In Progress, 3 Suppressed, 4 Resolved, 99 Other
_STATUS_TO_ID: dict[Status, int] = {
    Status.UNKNOWN: 0,
    Status.NEW: 1,
    Status.IN_PROGRESS: 2,
    Status.SUPPRESSED: 3,
    Status.RESOLVED: 4,
}

# OCSF Detection Finding activity_id: 0 Unknown, 1 Create, 2 Update, 3 Close, 99 Other
_ACTIVITY_TO_ID: dict[Activity, int] = {
    Activity.UNKNOWN: 0,
    Activity.CREATE: 1,
    Activity.UPDATE: 2,
    Activity.CLOSE: 3,
}

# OCSF confidence_id: 0 Unknown, 1 Low, 2 Medium, 3 High, 99 Other
_CONFIDENCE_TO_ID: dict[Confidence, int] = {
    Confidence.UNKNOWN: 0,
    Confidence.LOW: 1,
    Confidence.MEDIUM: 2,
    Confidence.HIGH: 3,
}

# OCSF risk_level_id: 0 Info, 1 Low, 2 Medium, 3 High, 4 Critical, 99 Other
_RISK_LEVEL_TO_ID: dict[RiskLevel, int] = {
    RiskLevel.INFO: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


def severity_id(severity: Severity) -> _m.SeverityId:
    """Map our Severity enum to an OCSF severity_id enum member."""
    return _m.SeverityId(_SEVERITY_TO_ID[severity])


def status_id(status: Status) -> _m.StatusId:
    """Map our Status enum to an OCSF status_id enum member."""
    return _m.StatusId(_STATUS_TO_ID[status])


def activity_id(activity: Activity) -> _m.ActivityId:
    """Map our Activity enum to an OCSF activity_id enum member."""
    return _m.ActivityId(_ACTIVITY_TO_ID[activity])


def confidence_id(confidence: Confidence) -> _m.ConfidenceId:
    """Map our Confidence enum to an OCSF confidence_id enum member."""
    return _m.ConfidenceId(_CONFIDENCE_TO_ID[confidence])


def risk_level_id(risk_level: RiskLevel) -> _m.RiskLevelId:
    """Map our RiskLevel enum to an OCSF risk_level_id enum member."""
    return _m.RiskLevelId(_RISK_LEVEL_TO_ID[risk_level])


def class_uid() -> _m.ClassUid:
    """Return the OCSF class_uid enum member for Detection Finding (2004)."""
    return _m.ClassUid(CLASS_UID)


def category_uid() -> _m.CategoryUid:
    """Return the OCSF category_uid enum member for Findings (2)."""
    return _m.CategoryUid(CATEGORY_UID)


def type_uid(activity: Activity) -> _m.TypeUid:
    """Compute OCSF type_uid enum member = class_uid * 100 + activity_id."""
    return _m.TypeUid(TYPE_UID_BASE + _ACTIVITY_TO_ID[activity])


def type_uid_int(activity: Activity) -> int:
    """Return the integer type_uid value (for invariant checks/logging)."""
    return TYPE_UID_BASE + _ACTIVITY_TO_ID[activity]


# --------------------------------------------------------------------------- #
# Generic, class-agnostic identity helpers.
#
# The generated model uses a *distinct* IntEnum type per class (ClassUid,
# ClassUid1, ...), so there is no single shared enum to target. These helpers
# return plain ints; Pydantic coerces them into whichever per-class enum the
# target model field expects. This is what the multi-class builders use.
# --------------------------------------------------------------------------- #
def class_identity(ocsf_class: OcsfClass) -> tuple[int, int, str, str]:
    """Return ``(class_uid, category_uid, class_name, category_name)`` for a class."""
    spec = _CLASS_REGISTRY[ocsf_class]
    return spec.class_uid, spec.category_uid, spec.class_name, spec.category_name


def type_uid_for(ocsf_class: OcsfClass, activity_id_value: int) -> int:
    """Compute ``type_uid = class_uid * 100 + activity_id`` for a class."""
    return _CLASS_REGISTRY[ocsf_class].type_uid(activity_id_value)


def activity_id_int(activity: Activity) -> int:
    """Return the integer OCSF activity_id for a shared Findings ``Activity``."""
    return _ACTIVITY_TO_ID[activity]
