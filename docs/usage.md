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

Beyond Detection Finding, the library builds/validates/emits the OCSF classes
below (all OCSF 1.1.0). Each has a dedicated builder with the same keyword shape
(`severity`, `message`, `time_ms`, `product`, `clock`) plus that class's
required objects. `emit`/`validate` accept any of them.

| Class | `class_uid` | Category | Builder | Required input |
| --- | --- | --- | --- | --- |
| Detection Finding | 2004 | Findings | [`build_detection_finding`][ocsf_emitter.builders.build_detection_finding] | `title`, `severity`, `message` |
| Compliance Finding | 2003 | Findings | [`build_compliance_finding`][ocsf_emitter.builders.build_compliance_finding] | `title`, `compliance` (a `ComplianceRef`) |
| Authentication | 3002 | Identity & Access Management | [`build_authentication`][ocsf_emitter.builders.build_authentication] | `user` (a `UserRef`) |
| Account Change | 3001 | Identity & Access Management | [`build_account_change`][ocsf_emitter.builders.build_account_change] | `user` |
| Operating System Patch State | 5004 | Discovery | [`build_patch_state`][ocsf_emitter.builders.build_patch_state] | `device` (a `DeviceRef` with an `os_*` field) |
| API Activity | 6003 | Application Activity | [`build_api_activity`][ocsf_emitter.builders.build_api_activity] | `api` (an `ApiCall`) |
| Web Resources Activity | 6001 | Application Activity | [`build_web_resources_activity`][ocsf_emitter.builders.build_web_resources_activity] | `web_resources` (a list of `WebResourceRef`) |
| File Hosting Activity | 6006 | Application Activity | [`build_file_hosting`][ocsf_emitter.builders.build_file_hosting] | `file` (a `FileRef`) |

Each class carries its own activity vocabulary
([`AuthAction`][ocsf_emitter.defaults.AuthAction],
[`FileHostingAction`][ocsf_emitter.defaults.FileHostingAction], …); the shared
[`Activity`][ocsf_emitter.defaults.Activity] (Create/Update/Close) covers the two
Findings classes. The class registry
([`OcsfClass`][ocsf_emitter.defaults.OcsfClass],
[`class_spec`][ocsf_emitter.defaults.class_spec]) is the single source of truth
for each class's `class_uid`/`category_uid` and name siblings.

```python
from ocsf_emitter import (
    build_file_hosting, build_authentication,
    FileRef, UserRef, EndpointRef, Severity, FileHostingAction, AuthAction,
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
    activity=AuthAction.LOGON,
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
