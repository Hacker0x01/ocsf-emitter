"""One minimal-but-valid build call per supported OCSF class.

Keyed by :class:`ocsf_emitter.OcsfClass`, reused by the all-classes round-trip
test and the OCSF-schema conformance test so we exercise every class (including
its OCSF ``at_least_one``/``just_one`` constraints) without a bespoke test each.
Each callable returns a built (not-yet-emitted) model; the product must be
configured by the caller (the ``conftest`` autouse fixture does this).
"""

from __future__ import annotations

from collections.abc import Callable

import ocsf_emitter as o
from ocsf_emitter import OcsfClass as C
from ocsf_emitter import SupportedEvent

_S = o.Severity.MEDIUM
_EP = o.EndpointRef(ip="203.0.113.7")  # a constraint-satisfying network endpoint
_DEV = o.DeviceRef(hostname="web01")  # a constraint-satisfying device
_USER = o.UserRef(name="alice")

EXAMPLES: dict[o.OcsfClass, Callable[[], SupportedEvent]] = {
    # System Activity -- all require actor(empty ok) + device + a specific object.
    C.FILE_ACTIVITY: lambda: o.build_file_activity(
        file=o.FileRef(name="a.exe"), device=_DEV, severity=_S, activity=o.FileActivityAction(1)
    ),
    C.KERNEL_EXTENSION_ACTIVITY: lambda: o.build_kernel_extension_activity(
        driver=o.KernelDriverRef(file=o.FileRef(name="d.sys")),
        device=_DEV,
        severity=_S,
        activity=o.KernelExtensionActivityAction(1),
    ),
    C.KERNEL_ACTIVITY: lambda: o.build_kernel_activity(
        kernel=o.KernelRef(name="ntoskrnl", type_id=1),
        device=_DEV,
        severity=_S,
        activity=o.KernelActivityAction(1),
    ),
    C.MEMORY_ACTIVITY: lambda: o.build_memory_activity(
        process=o.ProcessRef(name="sh", pid=1),
        device=_DEV,
        severity=_S,
        activity=o.MemoryActivityAction(1),
    ),
    C.MODULE_ACTIVITY: lambda: o.build_module_activity(
        module=o.ModuleRef(load_type_id=1),
        device=_DEV,
        severity=_S,
        activity=o.ModuleActivityAction(1),
    ),
    C.SCHEDULED_JOB_ACTIVITY: lambda: o.build_scheduled_job_activity(
        job=o.JobRef(name="j", file=o.FileRef(name="j.sh")),
        device=_DEV,
        severity=_S,
        activity=o.ScheduledJobActivityAction(1),
    ),
    C.PROCESS_ACTIVITY: lambda: o.build_process_activity(
        process=o.ProcessRef(name="sh", pid=1),
        device=_DEV,
        severity=_S,
        activity=o.ProcessActivityAction(1),
    ),
    C.EVENT_LOG_ACTVITY: lambda: o.build_event_log_activity(
        log_name="Security", severity=_S, activity=o.EventLogActvityAction(1)
    ),
    C.SCRIPT_ACTIVITY: lambda: o.build_script_activity(
        script=o.ScriptRef(script_content="echo hi", type_id=1),
        device=_DEV,
        severity=_S,
        activity=o.ScriptActivityAction(1),
    ),
    # Findings
    C.VULNERABILITY_FINDING: lambda: o.build_vulnerability_finding(
        title="v",
        vulnerabilities=[o.VulnerabilityRef(title="CVE-1", severity="High", cve_uid="CVE-2026-1")],
        severity=o.Severity.HIGH,
        activity=o.VulnerabilityFindingAction(1),
    ),
    C.COMPLIANCE_FINDING: lambda: o.build_compliance_finding(
        title="NTP", compliance=o.ComplianceRef(standards=["CIS"]), severity=_S
    ),
    C.DETECTION_FINDING: lambda: o.build_detection_finding(
        title="det", severity=o.Severity.HIGH, message="m"
    ),
    C.INCIDENT_FINDING: lambda: o.build_incident_finding(
        title="inc", assignee=_USER, severity=o.Severity.HIGH, activity=o.IncidentFindingAction(1)
    ),
    C.DATA_SECURITY_FINDING: lambda: o.build_data_security_finding(
        title="dsf", severity=_S, activity=o.DataSecurityFindingAction(1)
    ),
    C.APPLICATION_SECURITY_POSTURE_FINDING: lambda: o.build_application_security_posture_finding(
        title="aspf",
        compliance=o.ComplianceRef(standards=["OWASP"]),
        severity=_S,
        activity=o.ApplicationSecurityPostureFindingAction(1),
    ),
    # Identity & Access Management
    C.ACCOUNT_CHANGE: lambda: o.build_account_change(
        user=_USER, severity=_S, activity=o.AccountChangeAction(1)
    ),
    C.AUTHENTICATION: lambda: o.build_authentication(
        user=_USER, severity=_S, activity=o.AuthenticationAction(1)
    ),
    C.AUTHORIZE_SESSION: lambda: o.build_authorize_session(
        user=_USER, privileges=["admin"], severity=_S, activity=o.AuthorizeSessionAction(1)
    ),
    C.ENTITY_MANAGEMENT: lambda: o.build_entity_management(
        entity=o.ManagedEntityRef(name="e"), severity=_S, activity=o.EntityManagementAction(1)
    ),
    C.USER_ACCESS: lambda: o.build_user_access(
        user=_USER, privileges=["admin"], severity=_S, activity=o.UserAccessAction(1)
    ),
    C.GROUP_MANAGEMENT: lambda: o.build_group_management(
        group=o.GroupRef(name="g"), severity=_S, activity=o.GroupManagementAction(1)
    ),
    # Network Activity -- require a src/dst endpoint (http via http_request).
    C.NETWORK_ACTIVITY: lambda: o.build_network_activity(
        src_endpoint=_EP, severity=_S, activity=o.NetworkActivityAction(1)
    ),
    C.HTTP_ACTIVITY: lambda: o.build_http_activity(severity=_S, activity=o.HttpActivityAction(1)),
    C.DNS_ACTIVITY: lambda: o.build_dns_activity(
        src_endpoint=_EP, severity=_S, activity=o.DnsActivityAction(1)
    ),
    C.DHCP_ACTIVITY: lambda: o.build_dhcp_activity(
        src_endpoint=_EP, severity=_S, activity=o.DhcpActivityAction(1)
    ),
    C.RDP_ACTIVITY: lambda: o.build_rdp_activity(
        src_endpoint=_EP, severity=_S, activity=o.RdpActivityAction(1)
    ),
    C.SMB_ACTIVITY: lambda: o.build_smb_activity(
        src_endpoint=_EP, severity=_S, activity=o.SmbActivityAction(1)
    ),
    C.SSH_ACTIVITY: lambda: o.build_ssh_activity(
        src_endpoint=_EP, severity=_S, activity=o.SshActivityAction(1)
    ),
    C.FTP_ACTIVITY: lambda: o.build_ftp_activity(
        src_endpoint=_EP, severity=_S, activity=o.FtpActivityAction(1)
    ),
    C.EMAIL_ACTIVITY: lambda: o.build_email_activity(
        email=o.EmailRef(from_addr="a@x.com"),
        direction_id=1,
        severity=_S,
        activity=o.EmailActivityAction(1),
    ),
    C.NTP_ACTIVITY: lambda: o.build_ntp_activity(
        version="4", src_endpoint=_EP, severity=_S, activity=o.NtpActivityAction(1)
    ),
    C.TUNNEL_ACTIVITY: lambda: o.build_tunnel_activity(
        src_endpoint=_EP, severity=_S, activity=o.TunnelActivityAction(1)
    ),
    # Discovery
    C.INVENTORY_INFO: lambda: o.build_inventory_info(
        device=_DEV, severity=_S, activity=o.InventoryInfoAction(1)
    ),
    C.USER_INVENTORY: lambda: o.build_user_inventory(
        user=_USER, severity=_S, activity=o.UserInventoryAction(1)
    ),
    C.PATCH_STATE: lambda: o.build_patch_state(
        device=o.DeviceRef(hostname="web01", os_version="22.04"),
        severity=_S,
        activity=o.PatchStateAction.LOG,
    ),
    C.DEVICE_CONFIG_STATE_CHANGE: lambda: o.build_device_config_state_change(
        device=_DEV, severity=_S, activity=o.DeviceConfigStateChangeAction(1)
    ),
    C.SOFTWARE_INFO: lambda: o.build_software_info(
        device=_DEV, severity=_S, activity=o.SoftwareInfoAction(1)
    ),
    C.OSINT_INVENTORY_INFO: lambda: o.build_osint_inventory_info(
        osint=[o.OsintRef(value="1.2.3.4", type_id=1)],
        severity=_S,
        activity=o.OsintInventoryInfoAction(1),
    ),
    C.CLOUD_RESOURCES_INVENTORY_INFO: lambda: o.build_cloud_resources_inventory_info(
        resources=[o.ResourceDetailsRef(name="i-123")],
        severity=_S,
        activity=o.CloudResourcesInventoryInfoAction(1),
    ),
    C.EVIDENCE_INFO: lambda: o.build_evidence_info(
        query_evidence=o.QueryEvidenceRef(query_type_id=1, user=_USER),
        query_result_id=1,
        device=_DEV,
        severity=_S,
        activity=o.EvidenceInfoAction(1),
    ),
    # Application Activity
    C.WEB_RESOURCES_ACTIVITY: lambda: o.build_web_resources_activity(
        web_resources=[o.WebResourceRef(name="report-123", type="report")],
        severity=_S,
        activity=o.WebResourcesActivityAction(1),
    ),
    C.APPLICATION_LIFECYCLE: lambda: o.build_application_lifecycle(
        app_name="svc", severity=_S, activity=o.ApplicationLifecycleAction(1)
    ),
    C.API_ACTIVITY: lambda: o.build_api_activity(
        api=o.ApiCall(operation="Get"),
        src_endpoint=_EP,
        severity=_S,
        activity=o.ApiActivityAction(1),
    ),
    C.DATASTORE_ACTIVITY: lambda: o.build_datastore_activity(
        database=o.DatabaseRef(name="orders"),
        src_endpoint=_EP,
        severity=_S,
        activity=o.DatastoreActivityAction(1),
    ),
    C.FILE_HOSTING: lambda: o.build_file_hosting(
        file=o.FileRef(name="s.pdf"),
        src_endpoint=_EP,
        severity=_S,
        activity=o.FileHostingAction.SHARE,
    ),
    C.SCAN_ACTIVITY: lambda: o.build_scan_activity(
        scan=o.ScanRef(type_id=1, name="nightly"), severity=_S, activity=o.ScanActivityAction(1)
    ),
    C.APPLICATION_ERROR: lambda: o.build_application_error(
        severity=_S, activity=o.ApplicationErrorAction(1)
    ),
    # Remediation
    C.REMEDIATION_ACTIVITY: lambda: o.build_remediation_activity(
        command_uid="c1", severity=_S, activity=o.RemediationActivityAction(1)
    ),
    C.FILE_REMEDIATION_ACTIVITY: lambda: o.build_file_remediation_activity(
        command_uid="c1",
        file=o.FileRef(name="a.exe"),
        severity=_S,
        activity=o.FileRemediationActivityAction(1),
    ),
    C.PROCESS_REMEDIATION_ACTIVITY: lambda: o.build_process_remediation_activity(
        command_uid="c1",
        process=o.ProcessRef(name="sh", pid=1),
        severity=_S,
        activity=o.ProcessRemediationActivityAction(1),
    ),
    C.NETWORK_REMEDIATION_ACTIVITY: lambda: o.build_network_remediation_activity(
        command_uid="c1",
        connection_info=o.ConnectionInfoRef(direction_id=1),
        severity=_S,
        activity=o.NetworkRemediationActivityAction(1),
    ),
    # Unmanned Systems
    C.DRONE_FLIGHTS_ACTIVITY: lambda: o.build_drone_flights_activity(
        uas=o.UasRef(uid="d1"),
        operator=o.UserRef(name="pilot"),
        dst_endpoint=_EP,
        severity=_S,
        activity=o.DroneFlightsActivityAction(1),
    ),
    C.AIRBORNE_BROADCAST_ACTIVITY: lambda: o.build_airborne_broadcast_activity(
        uas=o.UasRef(uid="d1"),
        operator=o.UserRef(name="pilot"),
        severity=_S,
        activity=o.AirborneBroadcastActivityAction(1),
    ),
}
