# ocsf-emitter

Construct, validate, and emit **OCSF 1.1.0** events with a consistent shape and
mandatory runtime validation. Supports eight classes — Detection Finding (2004),
Compliance Finding (2003), Authentication (3002), Account Change (3001),
Operating System Patch State (5004), API Activity (6003), Web Resources Activity
(6001), and File Hosting Activity (6006).

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
- **AWS Security Lake ready.** Pinned to OCSF 1.1.0 and proven against AWS's own
  OCSF validation tool; an optional Parquet writer packages findings for
  ingestion. See [AWS Security Lake](security-lake.md).

## Install

```bash
pip install ocsf-emitter                  # runtime: pydantic only
pip install "ocsf-emitter[securitylake]"  # + pyarrow, for the Parquet writer
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
