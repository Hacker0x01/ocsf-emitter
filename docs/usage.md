# Usage guide

## Configure the product (once)

Every finding is stamped with a `metadata.product`. The emitting product is
**configurable**, not hardcoded — set it once at startup:

```python
import ocsf_emitter

ocsf_emitter.configure_product(name="My Service", vendor_name="My Org")
```

Or pass `product=ocsf_emitter.make_product(...)` per call. Building a finding
with no product configured raises
[`OcsfEmitterError`][ocsf_emitter.errors.OcsfEmitterError].

## Build a finding

[`build_detection_finding`][ocsf_emitter.builders.build_detection_finding] is the
primary entry point. Only `title`, `severity`, and `message` are required; a
`uid` is auto-generated if omitted (prefer passing a stable one for dedup).

```python
from ocsf_emitter import (
    build_detection_finding,
    Severity, Status, Activity, Confidence, RiskLevel,
    Observable, ObservableType, MitreAttack,
)

finding = build_detection_finding(
    uid="det-2026-0715-001",
    title="Impossible-travel login",
    severity=Severity.HIGH,          # -> severity_id
    message="User alice logged in from two continents within 4 minutes.",
    status=Status.NEW,               # -> status_id
    activity=Activity.CREATE,        # -> activity_id + type_uid
    observables=[
        Observable(ObservableType.USER_NAME, "alice"),
        Observable(ObservableType.IP_ADDRESS, "203.0.113.7"),
    ],
    description="Geo-velocity rule R-42 fired.",
    data_sources=["okta.system_log"],
    confidence=Confidence.HIGH,      # -> confidence_id
    risk_level=RiskLevel.HIGH,       # -> risk_level_id
    attacks=[MitreAttack("T1078", "Valid Accounts", "TA0001", "Initial Access")],
)
```

Our vocabulary enums ([`Severity`][ocsf_emitter.defaults.Severity],
[`Status`][ocsf_emitter.defaults.Status], etc.) are mapped to OCSF `*_id`
integers by the functions in [`defaults`](api/defaults.md).

## Supported OCSF classes

The library builds/validates/emits **all 53 base OCSF 1.5.0 classes** across all
eight categories. Each has a dedicated `build_*` builder sharing the same keyword
shape (`severity`, `activity`, `message`, `time_ms`, `observables`, `product`,
`clock`) plus that class's required OCSF objects. `emit`/`validate` accept any of
them.

Each class carries its own activity vocabulary generated from the OCSF schema and
named `<ModelClass>Action` (e.g. `AuthenticationAction`, `FileHostingAction`,
`NetworkActivityAction`); the shared
[`Activity`][ocsf_emitter.defaults.Activity] (Create/Update/Close) covers the two
Findings builders `build_detection_finding` / `build_compliance_finding`. The
class registry (`OcsfClass`,
[`class_spec`][ocsf_emitter.defaults.class_spec]) is the single source of truth
for each class's `class_uid`/`category_uid` and name siblings.

**System Activity [1]**

| Class | `class_uid` | Builder |
| --- | --- | --- |
| File System Activity | 1001 | `build_file_activity` |
| Kernel Extension Activity | 1002 | `build_kernel_extension_activity` |
| Kernel Activity | 1003 | `build_kernel_activity` |
| Memory Activity | 1004 | `build_memory_activity` |
| Module Activity | 1005 | `build_module_activity` |
| Scheduled Job Activity | 1006 | `build_scheduled_job_activity` |
| Process Activity | 1007 | `build_process_activity` |
| Event Log Activity | 1008 | `build_event_log_activity` |
| Script Activity | 1009 | `build_script_activity` |

**Findings [2]**

| Class | `class_uid` | Builder |
| --- | --- | --- |
| Vulnerability Finding | 2002 | `build_vulnerability_finding` |
| Compliance Finding | 2003 | `build_compliance_finding` |
| Detection Finding | 2004 | `build_detection_finding` |
| Incident Finding | 2005 | `build_incident_finding` |
| Data Security Finding | 2006 | `build_data_security_finding` |
| Application Security Posture Finding | 2007 | `build_application_security_posture_finding` |

**Identity & Access Management [3]**

| Class | `class_uid` | Builder |
| --- | --- | --- |
| Account Change | 3001 | `build_account_change` |
| Authentication | 3002 | `build_authentication` |
| Authorize Session | 3003 | `build_authorize_session` |
| Entity Management | 3004 | `build_entity_management` |
| User Access Management | 3005 | `build_user_access` |
| Group Management | 3006 | `build_group_management` |

**Network Activity [4]**

| Class | `class_uid` | Builder |
| --- | --- | --- |
| Network Activity | 4001 | `build_network_activity` |
| HTTP Activity | 4002 | `build_http_activity` |
| DNS Activity | 4003 | `build_dns_activity` |
| DHCP Activity | 4004 | `build_dhcp_activity` |
| RDP Activity | 4005 | `build_rdp_activity` |
| SMB Activity | 4006 | `build_smb_activity` |
| SSH Activity | 4007 | `build_ssh_activity` |
| FTP Activity | 4008 | `build_ftp_activity` |
| Email Activity | 4009 | `build_email_activity` |
| NTP Activity | 4013 | `build_ntp_activity` |
| Tunnel Activity | 4014 | `build_tunnel_activity` |

**Discovery [5]**

| Class | `class_uid` | Builder |
| --- | --- | --- |
| Device Inventory Info | 5001 | `build_inventory_info` |
| User Inventory Info | 5003 | `build_user_inventory` |
| Operating System Patch State | 5004 | `build_patch_state` |
| Device Config State Change | 5019 | `build_device_config_state_change` |
| Software Inventory Info | 5020 | `build_software_info` |
| OSINT Inventory Info | 5021 | `build_osint_inventory_info` |
| Cloud Resources Inventory Info | 5023 | `build_cloud_resources_inventory_info` |
| Live Evidence Info | 5040 | `build_evidence_info` |

**Application Activity [6]**

| Class | `class_uid` | Builder |
| --- | --- | --- |
| Web Resources Activity | 6001 | `build_web_resources_activity` |
| Application Lifecycle | 6002 | `build_application_lifecycle` |
| API Activity | 6003 | `build_api_activity` |
| Datastore Activity | 6005 | `build_datastore_activity` |
| File Hosting Activity | 6006 | `build_file_hosting` |
| Scan Activity | 6007 | `build_scan_activity` |
| Application Error | 6008 | `build_application_error` |

**Remediation [7]**

| Class | `class_uid` | Builder |
| --- | --- | --- |
| Remediation Activity | 7001 | `build_remediation_activity` |
| File Remediation Activity | 7002 | `build_file_remediation_activity` |
| Process Remediation Activity | 7003 | `build_process_remediation_activity` |
| Network Remediation Activity | 7004 | `build_network_remediation_activity` |

**Unmanned Systems [8]**

| Class | `class_uid` | Builder |
| --- | --- | --- |
| Drone Flights Activity | 8001 | `build_drone_flights_activity` |
| Airborne Broadcast Activity | 8002 | `build_airborne_broadcast_activity` |

```python
from ocsf_emitter import (
    build_file_hosting, build_authentication,
    FileRef, UserRef, EndpointRef, Severity, FileHostingAction, AuthenticationAction,
)

# Slack file share -> File Hosting Activity (6006)
share = build_file_hosting(
    file=FileRef(name="q3-earnings.xlsx", mime_type="application/vnd.ms-excel"),
    severity=Severity.MEDIUM,
    activity=FileHostingAction.SHARE,
    actor_user=UserRef(email="alice@example.com"),
)

# Okta SSO logon -> Authentication (3002)
logon = build_authentication(
    user=UserRef(name="alice", email="alice@example.com"),
    severity=Severity.LOW,
    activity=AuthenticationAction.LOGON,
    dst_endpoint=EndpointRef(hostname="sso.example.com"),
)
```

## Emit and validate

```python
from ocsf_emitter import emit, emit_json

payload = emit(finding)          # dict, validated
text = emit_json(finding, indent=2)   # JSON string
```

Validation runs automatically inside `emit`/`emit_json` and is also callable
standalone via [`validate`][ocsf_emitter.validate.validate]. On failure it raises
[`InvalidFindingError`][ocsf_emitter.errors.InvalidFindingError], whose message
and `field_errors` name the offending field(s):

```
InvalidFindingError: DetectionFinding failed OCSF schema validation
  - severity_id: Input should be 0, 1, 2, 3, 4, 5, 6 or 99
```

## Building from a domain object

If you'd rather assemble the domain object yourself, construct a
[`DetectionSignal`][ocsf_emitter.domain.DetectionSignal] and call
[`build_from_signal`][ocsf_emitter.builders.build_from_signal].
