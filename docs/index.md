# ocsf-emitter

Construct, validate, and emit **OCSF 1.5.0** events with a consistent shape and
mandatory runtime validation. Covers **all 53 base OCSF classes across all eight
categories** — each with a typed builder.

This is an internal library. Other services import it to turn their own
detection signals into valid OCSF events; the library owns the OCSF field
names, the schema-version pin, the house defaults, and validation. **Transport
is deliberately out of scope** — [`emit`][ocsf_emitter.emit.emit] returns a
validated, JSON-serializable payload and the caller ships it however it likes.

## Highlights

- **A builder per class.** [`build_detection_finding`][ocsf_emitter.builders.build_detection_finding],
  [`build_authentication`][ocsf_emitter.builders.build_authentication],
  [`build_file_hosting`][ocsf_emitter.builders.build_file_hosting], and more map
  our domain fields onto typed, valid OCSF models. See the
  [usage guide](usage.md) for the full class table.
- **Validation is mandatory.** [`emit`][ocsf_emitter.emit.emit] validates every
  event (schema + OCSF invariants, keyed by the event's own `class_uid`) and
  raises [`InvalidFindingError`][ocsf_emitter.errors.InvalidFindingError] naming
  the offending field(s).
- **Fully typed.** Complete type hints, `mypy --strict` clean, ships `py.typed`.
- **Schema-conformant.** Pinned to OCSF 1.5.0; emitted events are checked against
  the official OCSF JSON Schema in CI (`tests/test_integ_ocsf_schema.py`).

## Install

```bash
pip install ocsf-emitter   # runtime: pydantic only
```

## Quickstart

```python
import ocsf_emitter
from ocsf_emitter import (
    build_detection_finding, emit, Severity, Observable, ObservableType,
)

ocsf_emitter.configure_product(name="Example Detector", vendor_name="Example, Inc.")

finding = build_detection_finding(
    uid="det-123",
    title="Impossible-travel login",
    severity=Severity.HIGH,
    message="User alice logged in from two continents within 4 minutes.",
    observables=[Observable(ObservableType.USER_NAME, "alice")],
)

payload = emit(finding)  # validates; raises InvalidFindingError if invalid
```

See the [Usage guide](usage.md) for the full field set and the
[API reference](api/builders.md) generated from the source docstrings.
