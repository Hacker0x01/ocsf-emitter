"""Generated OCSF class catalog for schema version 1.5.0.

DO NOT EDIT BY HAND. Regenerate with:
    uv run --extra codegen python scripts/gen_models.py 1.5.0

Derived from the OCSF metaschema (ocsf-lib): the class identity registry,
one activity_id IntEnum per class, and the SupportedEvent union.
"""

from __future__ import annotations

import enum

from . import _models as _m


class OcsfClass(enum.Enum):
    """The OCSF classes this library supports, keyed by metaschema name."""

    FILE_ACTIVITY = "file_activity"
    KERNEL_EXTENSION_ACTIVITY = "kernel_extension_activity"
    KERNEL_ACTIVITY = "kernel_activity"
    MEMORY_ACTIVITY = "memory_activity"
    MODULE_ACTIVITY = "module_activity"
    SCHEDULED_JOB_ACTIVITY = "scheduled_job_activity"
    PROCESS_ACTIVITY = "process_activity"
    EVENT_LOG_ACTVITY = "event_log_actvity"
    SCRIPT_ACTIVITY = "script_activity"
    VULNERABILITY_FINDING = "vulnerability_finding"
    COMPLIANCE_FINDING = "compliance_finding"
    DETECTION_FINDING = "detection_finding"
    INCIDENT_FINDING = "incident_finding"
    DATA_SECURITY_FINDING = "data_security_finding"
    APPLICATION_SECURITY_POSTURE_FINDING = "application_security_posture_finding"
    ACCOUNT_CHANGE = "account_change"
    AUTHENTICATION = "authentication"
    AUTHORIZE_SESSION = "authorize_session"
    ENTITY_MANAGEMENT = "entity_management"
    USER_ACCESS = "user_access"
    GROUP_MANAGEMENT = "group_management"
    NETWORK_ACTIVITY = "network_activity"
    HTTP_ACTIVITY = "http_activity"
    DNS_ACTIVITY = "dns_activity"
    DHCP_ACTIVITY = "dhcp_activity"
    RDP_ACTIVITY = "rdp_activity"
    SMB_ACTIVITY = "smb_activity"
    SSH_ACTIVITY = "ssh_activity"
    FTP_ACTIVITY = "ftp_activity"
    EMAIL_ACTIVITY = "email_activity"
    NTP_ACTIVITY = "ntp_activity"
    TUNNEL_ACTIVITY = "tunnel_activity"
    INVENTORY_INFO = "inventory_info"
    USER_INVENTORY = "user_inventory"
    PATCH_STATE = "patch_state"
    DEVICE_CONFIG_STATE_CHANGE = "device_config_state_change"
    SOFTWARE_INFO = "software_info"
    OSINT_INVENTORY_INFO = "osint_inventory_info"
    CLOUD_RESOURCES_INVENTORY_INFO = "cloud_resources_inventory_info"
    EVIDENCE_INFO = "evidence_info"
    WEB_RESOURCES_ACTIVITY = "web_resources_activity"
    APPLICATION_LIFECYCLE = "application_lifecycle"
    API_ACTIVITY = "api_activity"
    DATASTORE_ACTIVITY = "datastore_activity"
    FILE_HOSTING = "file_hosting"
    SCAN_ACTIVITY = "scan_activity"
    APPLICATION_ERROR = "application_error"
    REMEDIATION_ACTIVITY = "remediation_activity"
    FILE_REMEDIATION_ACTIVITY = "file_remediation_activity"
    PROCESS_REMEDIATION_ACTIVITY = "process_remediation_activity"
    NETWORK_REMEDIATION_ACTIVITY = "network_remediation_activity"
    DRONE_FLIGHTS_ACTIVITY = "drone_flights_activity"
    AIRBORNE_BROADCAST_ACTIVITY = "airborne_broadcast_activity"


class FileActivityAction(enum.IntEnum):
    """File System Activity (activity_id)."""

    UNKNOWN = 0
    CREATE = 1
    READ = 2
    UPDATE = 3
    DELETE = 4
    RENAME = 5
    SET_ATTRIBUTES = 6
    SET_SECURITY = 7
    GET_ATTRIBUTES = 8
    GET_SECURITY = 9
    ENCRYPT = 10
    DECRYPT = 11
    MOUNT = 12
    UNMOUNT = 13
    OPEN = 14
    OTHER = 99


class KernelExtensionActivityAction(enum.IntEnum):
    """Kernel Extension Activity (activity_id)."""

    UNKNOWN = 0
    LOAD = 1
    UNLOAD = 2
    OTHER = 99


class KernelActivityAction(enum.IntEnum):
    """Kernel Activity (activity_id)."""

    UNKNOWN = 0
    CREATE = 1
    READ = 2
    DELETE = 3
    INVOKE = 4
    OTHER = 99


class MemoryActivityAction(enum.IntEnum):
    """Memory Activity (activity_id)."""

    UNKNOWN = 0
    ALLOCATE_PAGE = 1
    MODIFY_PAGE = 2
    DELETE_PAGE = 3
    BUFFER_OVERFLOW = 4
    DISABLE_DEP = 5
    ENABLE_DEP = 6
    READ = 7
    WRITE = 8
    MAP_VIEW = 9
    OTHER = 99


class ModuleActivityAction(enum.IntEnum):
    """Module Activity (activity_id)."""

    UNKNOWN = 0
    LOAD = 1
    UNLOAD = 2
    OTHER = 99


class ScheduledJobActivityAction(enum.IntEnum):
    """Scheduled Job Activity (activity_id)."""

    UNKNOWN = 0
    CREATE = 1
    UPDATE = 2
    DELETE = 3
    ENABLE = 4
    DISABLE = 5
    START = 6
    OTHER = 99


class ProcessActivityAction(enum.IntEnum):
    """Process Activity (activity_id)."""

    UNKNOWN = 0
    LAUNCH = 1
    TERMINATE = 2
    OPEN = 3
    INJECT = 4
    SET_USER_ID = 5
    OTHER = 99


class EventLogActvityAction(enum.IntEnum):
    """Event Log Activity (activity_id)."""

    UNKNOWN = 0
    CLEAR = 1
    DELETE = 2
    EXPORT = 3
    ARCHIVE = 4
    ROTATE = 5
    START = 6
    STOP = 7
    RESTART = 8
    ENABLE = 9
    DISABLE = 10
    OTHER = 99


class ScriptActivityAction(enum.IntEnum):
    """Script Activity (activity_id)."""

    UNKNOWN = 0
    EXECUTE = 1
    OTHER = 99


class VulnerabilityFindingAction(enum.IntEnum):
    """Vulnerability Finding (activity_id)."""

    UNKNOWN = 0
    CREATE = 1
    UPDATE = 2
    CLOSE = 3
    OTHER = 99


class ComplianceFindingAction(enum.IntEnum):
    """Compliance Finding (activity_id)."""

    UNKNOWN = 0
    CREATE = 1
    UPDATE = 2
    CLOSE = 3
    OTHER = 99


class DetectionFindingAction(enum.IntEnum):
    """Detection Finding (activity_id)."""

    UNKNOWN = 0
    CREATE = 1
    UPDATE = 2
    CLOSE = 3
    OTHER = 99


class IncidentFindingAction(enum.IntEnum):
    """Incident Finding (activity_id)."""

    UNKNOWN = 0
    CREATE = 1
    UPDATE = 2
    CLOSE = 3
    OTHER = 99


class DataSecurityFindingAction(enum.IntEnum):
    """Data Security Finding (activity_id)."""

    UNKNOWN = 0
    CREATE = 1
    UPDATE = 2
    CLOSE = 3
    SUPPRESSED = 4
    OTHER = 99


class ApplicationSecurityPostureFindingAction(enum.IntEnum):
    """Application Security Posture Finding (activity_id)."""

    UNKNOWN = 0
    CREATE = 1
    UPDATE = 2
    CLOSE = 3
    OTHER = 99


class AccountChangeAction(enum.IntEnum):
    """Account Change (activity_id)."""

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
    UNLOCK = 12
    OTHER = 99


class AuthenticationAction(enum.IntEnum):
    """Authentication (activity_id)."""

    UNKNOWN = 0
    LOGON = 1
    LOGOFF = 2
    AUTHENTICATION_TICKET = 3
    SERVICE_TICKET_REQUEST = 4
    SERVICE_TICKET_RENEW = 5
    PREAUTH = 6
    OTHER = 99


class AuthorizeSessionAction(enum.IntEnum):
    """Authorize Session (activity_id)."""

    UNKNOWN = 0
    ASSIGN_PRIVILEGES = 1
    ASSIGN_GROUPS = 2
    OTHER = 99


class EntityManagementAction(enum.IntEnum):
    """Entity Management (activity_id)."""

    UNKNOWN = 0
    CREATE = 1
    READ = 2
    UPDATE = 3
    DELETE = 4
    MOVE = 5
    ENROLL = 6
    UNENROLL = 7
    ENABLE = 8
    DISABLE = 9
    ACTIVATE = 10
    DEACTIVATE = 11
    SUSPEND = 12
    RESUME = 13
    OTHER = 99


class UserAccessAction(enum.IntEnum):
    """User Access Management (activity_id)."""

    UNKNOWN = 0
    ASSIGN_PRIVILEGES = 1
    REVOKE_PRIVILEGES = 2
    OTHER = 99


class GroupManagementAction(enum.IntEnum):
    """Group Management (activity_id)."""

    UNKNOWN = 0
    ASSIGN_PRIVILEGES = 1
    REVOKE_PRIVILEGES = 2
    ADD_USER = 3
    REMOVE_USER = 4
    DELETE = 5
    CREATE = 6
    OTHER = 99


class NetworkActivityAction(enum.IntEnum):
    """Network Activity (activity_id)."""

    UNKNOWN = 0
    OPEN = 1
    CLOSE = 2
    RESET = 3
    FAIL = 4
    REFUSE = 5
    TRAFFIC = 6
    LISTEN = 7
    OTHER = 99


class HttpActivityAction(enum.IntEnum):
    """HTTP Activity (activity_id)."""

    UNKNOWN = 0
    CONNECT = 1
    DELETE = 2
    GET = 3
    HEAD = 4
    OPTIONS = 5
    POST = 6
    PUT = 7
    TRACE = 8
    OTHER = 99


class DnsActivityAction(enum.IntEnum):
    """DNS Activity (activity_id)."""

    UNKNOWN = 0
    QUERY = 1
    RESPONSE = 2
    TRAFFIC = 6
    OTHER = 99


class DhcpActivityAction(enum.IntEnum):
    """DHCP Activity (activity_id)."""

    UNKNOWN = 0
    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    DECLINE = 4
    ACK = 5
    NAK = 6
    RELEASE = 7
    INFORM = 8
    EXPIRE = 9
    OTHER = 99


class RdpActivityAction(enum.IntEnum):
    """RDP Activity (activity_id)."""

    UNKNOWN = 0
    INITIAL_REQUEST = 1
    INITIAL_RESPONSE = 2
    CONNECT_REQUEST = 3
    CONNECT_RESPONSE = 4
    TLS_HANDSHAKE = 5
    TRAFFIC = 6
    OTHER = 99


class SmbActivityAction(enum.IntEnum):
    """SMB Activity (activity_id)."""

    UNKNOWN = 0
    FILE_SUPERSEDE = 1
    FILE_OPEN = 2
    FILE_CREATE = 3
    FILE_OPEN_IF = 4
    FILE_OVERWRITE = 5
    FILE_OVERWRITE_IF = 6
    OTHER = 99


class SshActivityAction(enum.IntEnum):
    """SSH Activity (activity_id)."""

    UNKNOWN = 0
    OPEN = 1
    CLOSE = 2
    RESET = 3
    FAIL = 4
    REFUSE = 5
    TRAFFIC = 6
    LISTEN = 7
    OTHER = 99


class FtpActivityAction(enum.IntEnum):
    """FTP Activity (activity_id)."""

    UNKNOWN = 0
    PUT = 1
    GET = 2
    POLL = 3
    DELETE = 4
    RENAME = 5
    LIST = 6
    OTHER = 99


class EmailActivityAction(enum.IntEnum):
    """Email Activity (activity_id)."""

    UNKNOWN = 0
    SEND = 1
    RECEIVE = 2
    SCAN = 3
    TRACE = 4
    OTHER = 99


class NtpActivityAction(enum.IntEnum):
    """NTP Activity (activity_id)."""

    UNKNOWN = 0
    SYMMETRIC_ACTIVE_EXCHANGE = 1
    SYMMETRIC_PASSIVE_RESPONSE = 2
    CLIENT_SYNCHRONIZATION = 3
    SERVER_RESPONSE = 4
    BROADCAST = 5
    CONTROL = 6
    PRIVATE_USE_CASE = 7
    OTHER = 99


class TunnelActivityAction(enum.IntEnum):
    """Tunnel Activity (activity_id)."""

    UNKNOWN = 0
    OPEN = 1
    CLOSE = 2
    RENEW = 3
    OTHER = 99


class InventoryInfoAction(enum.IntEnum):
    """Device Inventory Info (activity_id)."""

    UNKNOWN = 0
    LOG = 1
    COLLECT = 2
    OTHER = 99


class UserInventoryAction(enum.IntEnum):
    """User Inventory Info (activity_id)."""

    UNKNOWN = 0
    LOG = 1
    COLLECT = 2
    OTHER = 99


class PatchStateAction(enum.IntEnum):
    """Operating System Patch State (activity_id)."""

    UNKNOWN = 0
    LOG = 1
    COLLECT = 2
    OTHER = 99


class DeviceConfigStateChangeAction(enum.IntEnum):
    """Device Config State Change (activity_id)."""

    UNKNOWN = 0
    LOG = 1
    COLLECT = 2
    OTHER = 99


class SoftwareInfoAction(enum.IntEnum):
    """Software Inventory Info (activity_id)."""

    UNKNOWN = 0
    LOG = 1
    COLLECT = 2
    OTHER = 99


class OsintInventoryInfoAction(enum.IntEnum):
    """OSINT Inventory Info (activity_id)."""

    UNKNOWN = 0
    LOG = 1
    COLLECT = 2
    OTHER = 99


class CloudResourcesInventoryInfoAction(enum.IntEnum):
    """Cloud Resources Inventory Info (activity_id)."""

    UNKNOWN = 0
    LOG = 1
    COLLECT = 2
    OTHER = 99


class EvidenceInfoAction(enum.IntEnum):
    """Live Evidence Info (activity_id)."""

    UNKNOWN = 0
    QUERY = 1
    OTHER = 99


class WebResourcesActivityAction(enum.IntEnum):
    """Web Resources Activity (activity_id)."""

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


class ApplicationLifecycleAction(enum.IntEnum):
    """Application Lifecycle (activity_id)."""

    UNKNOWN = 0
    INSTALL = 1
    REMOVE = 2
    START = 3
    STOP = 4
    RESTART = 5
    ENABLE = 6
    DISABLE = 7
    UPDATE = 8
    OTHER = 99


class ApiActivityAction(enum.IntEnum):
    """API Activity (activity_id)."""

    UNKNOWN = 0
    CREATE = 1
    READ = 2
    UPDATE = 3
    DELETE = 4
    OTHER = 99


class DatastoreActivityAction(enum.IntEnum):
    """Datastore Activity (activity_id)."""

    UNKNOWN = 0
    READ = 1
    UPDATE = 2
    CONNECT = 3
    QUERY = 4
    WRITE = 5
    CREATE = 6
    DELETE = 7
    LIST = 8
    ENCRYPT = 9
    DECRYPT = 10
    OTHER = 99


class FileHostingAction(enum.IntEnum):
    """File Hosting Activity (activity_id)."""

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
    ACCESS_CHECK = 17
    OTHER = 99


class ScanActivityAction(enum.IntEnum):
    """Scan Activity (activity_id)."""

    UNKNOWN = 0
    STARTED = 1
    COMPLETED = 2
    CANCELLED = 3
    DURATION_VIOLATION = 4
    PAUSE_VIOLATION = 5
    ERROR = 6
    PAUSED = 7
    RESUMED = 8
    RESTARTED = 9
    DELAYED = 10
    OTHER = 99


class ApplicationErrorAction(enum.IntEnum):
    """Application Error (activity_id)."""

    UNKNOWN = 0
    GENERAL_ERROR = 1
    TRANSLATION_ERROR = 2
    OTHER = 99


class RemediationActivityAction(enum.IntEnum):
    """Remediation Activity (activity_id)."""

    UNKNOWN = 0
    ISOLATE = 1
    EVICT = 2
    RESTORE = 3
    HARDEN = 4
    DETECT = 5
    OTHER = 99


class FileRemediationActivityAction(enum.IntEnum):
    """File Remediation Activity (activity_id)."""

    UNKNOWN = 0
    ISOLATE = 1
    EVICT = 2
    RESTORE = 3
    HARDEN = 4
    DETECT = 5
    OTHER = 99


class ProcessRemediationActivityAction(enum.IntEnum):
    """Process Remediation Activity (activity_id)."""

    UNKNOWN = 0
    ISOLATE = 1
    EVICT = 2
    RESTORE = 3
    HARDEN = 4
    DETECT = 5
    OTHER = 99


class NetworkRemediationActivityAction(enum.IntEnum):
    """Network Remediation Activity (activity_id)."""

    UNKNOWN = 0
    ISOLATE = 1
    EVICT = 2
    RESTORE = 3
    HARDEN = 4
    DETECT = 5
    OTHER = 99


class DroneFlightsActivityAction(enum.IntEnum):
    """Drone Flights Activity (activity_id)."""

    UNKNOWN = 0
    CAPTURE = 1
    RECORD = 2
    OTHER = 99


class AirborneBroadcastActivityAction(enum.IntEnum):
    """Airborne Broadcast Activity (activity_id)."""

    UNKNOWN = 0
    CAPTURE = 1
    RECORD = 2
    OTHER = 99


CLASS_REGISTRY: dict[OcsfClass, tuple[int, int, str, str, str, type[enum.IntEnum]]] = {
    OcsfClass.FILE_ACTIVITY: (
        1001,
        1,
        "File System Activity",
        "System Activity",
        "FileActivity",
        FileActivityAction,
    ),
    OcsfClass.KERNEL_EXTENSION_ACTIVITY: (
        1002,
        1,
        "Kernel Extension Activity",
        "System Activity",
        "KernelExtensionActivity",
        KernelExtensionActivityAction,
    ),
    OcsfClass.KERNEL_ACTIVITY: (
        1003,
        1,
        "Kernel Activity",
        "System Activity",
        "KernelActivity",
        KernelActivityAction,
    ),
    OcsfClass.MEMORY_ACTIVITY: (
        1004,
        1,
        "Memory Activity",
        "System Activity",
        "MemoryActivity",
        MemoryActivityAction,
    ),
    OcsfClass.MODULE_ACTIVITY: (
        1005,
        1,
        "Module Activity",
        "System Activity",
        "ModuleActivity",
        ModuleActivityAction,
    ),
    OcsfClass.SCHEDULED_JOB_ACTIVITY: (
        1006,
        1,
        "Scheduled Job Activity",
        "System Activity",
        "ScheduledJobActivity",
        ScheduledJobActivityAction,
    ),
    OcsfClass.PROCESS_ACTIVITY: (
        1007,
        1,
        "Process Activity",
        "System Activity",
        "ProcessActivity",
        ProcessActivityAction,
    ),
    OcsfClass.EVENT_LOG_ACTVITY: (
        1008,
        1,
        "Event Log Activity",
        "System Activity",
        "EventLogActvity",
        EventLogActvityAction,
    ),
    OcsfClass.SCRIPT_ACTIVITY: (
        1009,
        1,
        "Script Activity",
        "System Activity",
        "ScriptActivity",
        ScriptActivityAction,
    ),
    OcsfClass.VULNERABILITY_FINDING: (
        2002,
        2,
        "Vulnerability Finding",
        "Findings",
        "VulnerabilityFinding",
        VulnerabilityFindingAction,
    ),
    OcsfClass.COMPLIANCE_FINDING: (
        2003,
        2,
        "Compliance Finding",
        "Findings",
        "ComplianceFinding",
        ComplianceFindingAction,
    ),
    OcsfClass.DETECTION_FINDING: (
        2004,
        2,
        "Detection Finding",
        "Findings",
        "DetectionFinding",
        DetectionFindingAction,
    ),
    OcsfClass.INCIDENT_FINDING: (
        2005,
        2,
        "Incident Finding",
        "Findings",
        "IncidentFinding",
        IncidentFindingAction,
    ),
    OcsfClass.DATA_SECURITY_FINDING: (
        2006,
        2,
        "Data Security Finding",
        "Findings",
        "DataSecurityFinding",
        DataSecurityFindingAction,
    ),
    OcsfClass.APPLICATION_SECURITY_POSTURE_FINDING: (
        2007,
        2,
        "Application Security Posture Finding",
        "Findings",
        "ApplicationSecurityPostureFinding",
        ApplicationSecurityPostureFindingAction,
    ),
    OcsfClass.ACCOUNT_CHANGE: (
        3001,
        3,
        "Account Change",
        "Identity & Access Management",
        "AccountChange",
        AccountChangeAction,
    ),
    OcsfClass.AUTHENTICATION: (
        3002,
        3,
        "Authentication",
        "Identity & Access Management",
        "Authentication",
        AuthenticationAction,
    ),
    OcsfClass.AUTHORIZE_SESSION: (
        3003,
        3,
        "Authorize Session",
        "Identity & Access Management",
        "AuthorizeSession",
        AuthorizeSessionAction,
    ),
    OcsfClass.ENTITY_MANAGEMENT: (
        3004,
        3,
        "Entity Management",
        "Identity & Access Management",
        "EntityManagement",
        EntityManagementAction,
    ),
    OcsfClass.USER_ACCESS: (
        3005,
        3,
        "User Access Management",
        "Identity & Access Management",
        "UserAccess",
        UserAccessAction,
    ),
    OcsfClass.GROUP_MANAGEMENT: (
        3006,
        3,
        "Group Management",
        "Identity & Access Management",
        "GroupManagement",
        GroupManagementAction,
    ),
    OcsfClass.NETWORK_ACTIVITY: (
        4001,
        4,
        "Network Activity",
        "Network Activity",
        "NetworkActivity",
        NetworkActivityAction,
    ),
    OcsfClass.HTTP_ACTIVITY: (
        4002,
        4,
        "HTTP Activity",
        "Network Activity",
        "HttpActivity",
        HttpActivityAction,
    ),
    OcsfClass.DNS_ACTIVITY: (
        4003,
        4,
        "DNS Activity",
        "Network Activity",
        "DnsActivity",
        DnsActivityAction,
    ),
    OcsfClass.DHCP_ACTIVITY: (
        4004,
        4,
        "DHCP Activity",
        "Network Activity",
        "DhcpActivity",
        DhcpActivityAction,
    ),
    OcsfClass.RDP_ACTIVITY: (
        4005,
        4,
        "RDP Activity",
        "Network Activity",
        "RdpActivity",
        RdpActivityAction,
    ),
    OcsfClass.SMB_ACTIVITY: (
        4006,
        4,
        "SMB Activity",
        "Network Activity",
        "SmbActivity",
        SmbActivityAction,
    ),
    OcsfClass.SSH_ACTIVITY: (
        4007,
        4,
        "SSH Activity",
        "Network Activity",
        "SshActivity",
        SshActivityAction,
    ),
    OcsfClass.FTP_ACTIVITY: (
        4008,
        4,
        "FTP Activity",
        "Network Activity",
        "FtpActivity",
        FtpActivityAction,
    ),
    OcsfClass.EMAIL_ACTIVITY: (
        4009,
        4,
        "Email Activity",
        "Network Activity",
        "EmailActivity",
        EmailActivityAction,
    ),
    OcsfClass.NTP_ACTIVITY: (
        4013,
        4,
        "NTP Activity",
        "Network Activity",
        "NtpActivity",
        NtpActivityAction,
    ),
    OcsfClass.TUNNEL_ACTIVITY: (
        4014,
        4,
        "Tunnel Activity",
        "Network Activity",
        "TunnelActivity",
        TunnelActivityAction,
    ),
    OcsfClass.INVENTORY_INFO: (
        5001,
        5,
        "Device Inventory Info",
        "Discovery",
        "InventoryInfo",
        InventoryInfoAction,
    ),
    OcsfClass.USER_INVENTORY: (
        5003,
        5,
        "User Inventory Info",
        "Discovery",
        "UserInventory",
        UserInventoryAction,
    ),
    OcsfClass.PATCH_STATE: (
        5004,
        5,
        "Operating System Patch State",
        "Discovery",
        "PatchState",
        PatchStateAction,
    ),
    OcsfClass.DEVICE_CONFIG_STATE_CHANGE: (
        5019,
        5,
        "Device Config State Change",
        "Discovery",
        "DeviceConfigStateChange",
        DeviceConfigStateChangeAction,
    ),
    OcsfClass.SOFTWARE_INFO: (
        5020,
        5,
        "Software Inventory Info",
        "Discovery",
        "SoftwareInfo",
        SoftwareInfoAction,
    ),
    OcsfClass.OSINT_INVENTORY_INFO: (
        5021,
        5,
        "OSINT Inventory Info",
        "Discovery",
        "OsintInventoryInfo",
        OsintInventoryInfoAction,
    ),
    OcsfClass.CLOUD_RESOURCES_INVENTORY_INFO: (
        5023,
        5,
        "Cloud Resources Inventory Info",
        "Discovery",
        "CloudResourcesInventoryInfo",
        CloudResourcesInventoryInfoAction,
    ),
    OcsfClass.EVIDENCE_INFO: (
        5040,
        5,
        "Live Evidence Info",
        "Discovery",
        "EvidenceInfo",
        EvidenceInfoAction,
    ),
    OcsfClass.WEB_RESOURCES_ACTIVITY: (
        6001,
        6,
        "Web Resources Activity",
        "Application Activity",
        "WebResourcesActivity",
        WebResourcesActivityAction,
    ),
    OcsfClass.APPLICATION_LIFECYCLE: (
        6002,
        6,
        "Application Lifecycle",
        "Application Activity",
        "ApplicationLifecycle",
        ApplicationLifecycleAction,
    ),
    OcsfClass.API_ACTIVITY: (
        6003,
        6,
        "API Activity",
        "Application Activity",
        "ApiActivity",
        ApiActivityAction,
    ),
    OcsfClass.DATASTORE_ACTIVITY: (
        6005,
        6,
        "Datastore Activity",
        "Application Activity",
        "DatastoreActivity",
        DatastoreActivityAction,
    ),
    OcsfClass.FILE_HOSTING: (
        6006,
        6,
        "File Hosting Activity",
        "Application Activity",
        "FileHosting",
        FileHostingAction,
    ),
    OcsfClass.SCAN_ACTIVITY: (
        6007,
        6,
        "Scan Activity",
        "Application Activity",
        "ScanActivity",
        ScanActivityAction,
    ),
    OcsfClass.APPLICATION_ERROR: (
        6008,
        6,
        "Application Error",
        "Application Activity",
        "ApplicationError",
        ApplicationErrorAction,
    ),
    OcsfClass.REMEDIATION_ACTIVITY: (
        7001,
        7,
        "Remediation Activity",
        "Remediation",
        "RemediationActivity",
        RemediationActivityAction,
    ),
    OcsfClass.FILE_REMEDIATION_ACTIVITY: (
        7002,
        7,
        "File Remediation Activity",
        "Remediation",
        "FileRemediationActivity",
        FileRemediationActivityAction,
    ),
    OcsfClass.PROCESS_REMEDIATION_ACTIVITY: (
        7003,
        7,
        "Process Remediation Activity",
        "Remediation",
        "ProcessRemediationActivity",
        ProcessRemediationActivityAction,
    ),
    OcsfClass.NETWORK_REMEDIATION_ACTIVITY: (
        7004,
        7,
        "Network Remediation Activity",
        "Remediation",
        "NetworkRemediationActivity",
        NetworkRemediationActivityAction,
    ),
    OcsfClass.DRONE_FLIGHTS_ACTIVITY: (
        8001,
        8,
        "Drone Flights Activity",
        "Unmanned Systems",
        "DroneFlightsActivity",
        DroneFlightsActivityAction,
    ),
    OcsfClass.AIRBORNE_BROADCAST_ACTIVITY: (
        8002,
        8,
        "Airborne Broadcast Activity",
        "Unmanned Systems",
        "AirborneBroadcastActivity",
        AirborneBroadcastActivityAction,
    ),
}

SupportedEvent = (
    _m.FileActivity
    | _m.KernelExtensionActivity
    | _m.KernelActivity
    | _m.MemoryActivity
    | _m.ModuleActivity
    | _m.ScheduledJobActivity
    | _m.ProcessActivity
    | _m.EventLogActvity
    | _m.ScriptActivity
    | _m.VulnerabilityFinding
    | _m.ComplianceFinding
    | _m.DetectionFinding
    | _m.IncidentFinding
    | _m.DataSecurityFinding
    | _m.ApplicationSecurityPostureFinding
    | _m.AccountChange
    | _m.Authentication
    | _m.AuthorizeSession
    | _m.EntityManagement
    | _m.UserAccess
    | _m.GroupManagement
    | _m.NetworkActivity
    | _m.HttpActivity
    | _m.DnsActivity
    | _m.DhcpActivity
    | _m.RdpActivity
    | _m.SmbActivity
    | _m.SshActivity
    | _m.FtpActivity
    | _m.EmailActivity
    | _m.NtpActivity
    | _m.TunnelActivity
    | _m.InventoryInfo
    | _m.UserInventory
    | _m.PatchState
    | _m.DeviceConfigStateChange
    | _m.SoftwareInfo
    | _m.OsintInventoryInfo
    | _m.CloudResourcesInventoryInfo
    | _m.EvidenceInfo
    | _m.WebResourcesActivity
    | _m.ApplicationLifecycle
    | _m.ApiActivity
    | _m.DatastoreActivity
    | _m.FileHosting
    | _m.ScanActivity
    | _m.ApplicationError
    | _m.RemediationActivity
    | _m.FileRemediationActivity
    | _m.ProcessRemediationActivity
    | _m.NetworkRemediationActivity
    | _m.DroneFlightsActivity
    | _m.AirborneBroadcastActivity
)

SUPPORTED_MODELS: tuple[type, ...] = (
    _m.FileActivity,
    _m.KernelExtensionActivity,
    _m.KernelActivity,
    _m.MemoryActivity,
    _m.ModuleActivity,
    _m.ScheduledJobActivity,
    _m.ProcessActivity,
    _m.EventLogActvity,
    _m.ScriptActivity,
    _m.VulnerabilityFinding,
    _m.ComplianceFinding,
    _m.DetectionFinding,
    _m.IncidentFinding,
    _m.DataSecurityFinding,
    _m.ApplicationSecurityPostureFinding,
    _m.AccountChange,
    _m.Authentication,
    _m.AuthorizeSession,
    _m.EntityManagement,
    _m.UserAccess,
    _m.GroupManagement,
    _m.NetworkActivity,
    _m.HttpActivity,
    _m.DnsActivity,
    _m.DhcpActivity,
    _m.RdpActivity,
    _m.SmbActivity,
    _m.SshActivity,
    _m.FtpActivity,
    _m.EmailActivity,
    _m.NtpActivity,
    _m.TunnelActivity,
    _m.InventoryInfo,
    _m.UserInventory,
    _m.PatchState,
    _m.DeviceConfigStateChange,
    _m.SoftwareInfo,
    _m.OsintInventoryInfo,
    _m.CloudResourcesInventoryInfo,
    _m.EvidenceInfo,
    _m.WebResourcesActivity,
    _m.ApplicationLifecycle,
    _m.ApiActivity,
    _m.DatastoreActivity,
    _m.FileHosting,
    _m.ScanActivity,
    _m.ApplicationError,
    _m.RemediationActivity,
    _m.FileRemediationActivity,
    _m.ProcessRemediationActivity,
    _m.NetworkRemediationActivity,
    _m.DroneFlightsActivity,
    _m.AirborneBroadcastActivity,
)
