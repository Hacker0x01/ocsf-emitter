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
InvalidFindingError: Detection finding failed OCSF schema validation
  - severity_id: Input should be 0, 1, 2, 3, 4, 5, 6 or 99
```

## Building from a domain object

If you'd rather assemble the domain object yourself, construct a
[`DetectionSignal`][ocsf_emitter.domain.DetectionSignal] and call
[`build_from_signal`][ocsf_emitter.builders.build_from_signal].
