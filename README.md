# ocsf-emitter

Construct, validate, and emit **OCSF 1.5.0** events with a consistent shape and
mandatory runtime validation. Supports eight classes: Detection Finding (2004),
Compliance Finding (2003), Authentication (3002), Account Change (3001),
Operating System Patch State (5004), API Activity (6003), Web Resources Activity
(6001), and File Hosting Activity (6006).

This is an internal library. Other services import it to turn their own
detection signals into valid OCSF events; the library owns the OCSF field
names, the schema-version pin, the house defaults, and validation. **Transport
is deliberately out of scope** -- `emit()` returns a validated,
JSON-serializable payload and the caller ships it however it likes.

Each class has a builder (`build_detection_finding`, `build_authentication`,
`build_file_hosting`, …) sharing a common keyword shape; `emit()`/`validate()`
accept any supported class. See the [usage guide](docs/usage.md) for the full
class table and examples.

## Install

```bash
uv pip install -e .              # runtime: pydantic only
uv pip install -e ".[codegen]"   # + tools to regenerate the OCSF models
uv sync                          # dev + docs groups (mypy, pytest, ruff, jsonschema, mkdocs)
```

## Usage

```python
import ocsf_emitter
from ocsf_emitter import (
    build_detection_finding, emit,
    Severity, Status, Activity, Confidence, RiskLevel,
    Observable, ObservableType, MitreAttack,
)

# Configure the emitting product once at startup (see "Product identity").
ocsf_emitter.configure_product(name="Example Detector", vendor_name="Example, Inc.")

finding = build_detection_finding(
    uid="det-2026-0715-001",             # stable id -> finding_info.uid
    title="Impossible-travel login",
    severity=Severity.HIGH,              # our enum -> OCSF severity_id
    message="User alice logged in from two continents within 4 minutes.",
    status=Status.NEW,                   # -> status_id
    activity=Activity.CREATE,            # -> activity_id + type_uid
    observables=[
        Observable(ObservableType.USER_NAME, "alice"),
        Observable(ObservableType.IP_ADDRESS, "203.0.113.7"),
    ],
    confidence=Confidence.HIGH,          # -> confidence_id
    risk_level=RiskLevel.HIGH,           # -> risk_level_id
    attacks=[MitreAttack("T1078", "Valid Accounts", "TA0001", "Initial Access")],
)

payload = emit(finding)   # validates, returns dict; raises InvalidFindingError if invalid
```

`build_detection_finding(...)` returns a **typed, already-valid**
`DetectionFinding` model instance. `emit(...)` runs full validation and returns
a `dict`; `emit_json(...)` returns a JSON string. `build_from_signal(signal)`
takes a `DetectionSignal` dataclass if you'd rather build the domain object
yourself.

See [`tests/golden_detection_finding.json`](tests/golden_detection_finding.json)
for a full sample payload you can eyeball against the OCSF `detection_finding`
spec.

## How validation behaves

Validation is **mandatory and automatic** inside `emit()`/`emit_json()`, and is
also callable standalone via `validate(finding)`. It does two things:

1. **Schema validation** -- re-runs Pydantic validation over the finding's
   current field values (catching any mutation after construction).
2. **OCSF invariant checks** -- looks the event's class up in the class registry
   by its `class_uid` and verifies `category_uid`, the `class_name`/
   `category_name` siblings, `type_uid == class_uid*100 + activity_id`, and that
   `metadata.version` matches the pinned schema version.

On failure it raises `InvalidFindingError`, whose message and `.field_errors`
list **name the offending field(s)**:

```
ocsf_emitter.errors.InvalidFindingError: Detection finding failed OCSF schema validation
  - severity_id: Input should be 0, 1, 2, 3, 4, 5, 6 or 99
```

## Model layer: chosen path and rationale

We generate a **full Pydantic v2 model tree** from OCSF's JSON Schema using
[`datamodel-code-generator`](https://github.com/koxudaxi/datamodel-code-generator),
and **commit the result** to
[`src/ocsf_emitter/_models.py`](src/ocsf_emitter/_models.py). At runtime the
package depends only on `pydantic` -- no network access, no code generation.

Why this rather than `py-ocsf-models`? The task allowed either; we chose
schema-generation for two reasons:

- **Exact fidelity to a pinned OCSF version.** The models come straight from
  the OCSF schema for the exact version we pin -- no dependency on a third
  party's release cadence for class coverage.
- **Self-contained and auditable.** The generated module is committed and
  reviewable, and regeneration is a single script.

### How the pinned version is generated

We pin an exact OCSF version and generate models from its **metaschema** (the
JSON Schema HTTP endpoint only serves the *latest* deployed version, so we don't
use it for codegen). `scripts/gen_models.py`:

1. Fetches the pinned version's **metaschema** with `ocsf-lib`
   (`OcsfApiClient().get_schema("1.5.0")`) -- this works for any version.
2. Converts that metaschema (every class in `ROOT_CLASSES` plus the **union** of
   their transitive object closures) into a self-contained draft **JSON Schema**,
   where each root class and shared object is a `$def` so codegen emits one
   Pydantic model each. Attributes tagged with an OCSF `profile` (e.g. `cloud`,
   `osint`) are dropped so we get the **base** classes -- mirroring the schema
   server's `?profiles=` selector, and keeping profile-only fields out of the
   required list.
3. Feeds that JSON Schema to `datamodel-code-generator` -> Pydantic v2.

## Bumping the OCSF schema version

1. Regenerate the models for the desired version:

   ```bash
   uv run --extra codegen python scripts/gen_models.py 1.5.0
   ```

2. Update the **one-line** pin in
   [`src/ocsf_emitter/defaults.py`](src/ocsf_emitter/defaults.py) to match
   (keep `DEFAULT_VERSION` in `scripts/gen_models.py` in sync):

   ```python
   OCSF_SCHEMA_VERSION = "1.5.0"   # <- change this
   ```

3. Run the suite and review the golden diff:

   ```bash
   uv run pytest && uv run mypy && uv run ruff check .
   ```

   If the emitted shape changed intentionally, regenerate
   `tests/golden_detection_finding.json` and review the diff. Note that a newer
   version may reintroduce `RootModel`/union wrappers on some objects, which
   would require builder adjustments.

## OCSF schema conformance

Beyond the library's own runtime `validate()` (Pydantic + registry invariants),
CI validates one emitted event **per supported class** against a JSON Schema
built from the OCSF **metaschema** (via `ocsf-lib`) for the pinned version -- the
same authoritative source the models are generated from. This is a **blocking**
job ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) and is self-contained
-- no third-party validator. Run it locally:

```bash
OCSF_SCHEMA_VALIDATION=1 uv run pytest tests/test_integ_ocsf_schema.py -v
```

Without `OCSF_SCHEMA_VALIDATION=1` the test is skipped (it fetches the metaschema
over the network).

## Product identity

The emitting product is **configurable**, not hardcoded, so any service can use
this library. Set it once at startup:

```python
ocsf_emitter.configure_product(name="My Service", vendor_name="My Org")
```

or pass `product=ocsf_emitter.make_product(...)` per call. Building a finding
with no product configured raises `OcsfEmitterError` rather than emitting an
unattributed finding.

## Package layout

```
src/ocsf_emitter/
  __init__.py     public API: build_detection_finding, build_from_signal, emit, ...
  domain.py       our domain shapes: DetectionSignal, Observable, MitreAttack, enums
  builders.py     domain signal  ->  OCSF DetectionFinding
  defaults.py     schema-version pin, metadata/product, severity/status/... mappings
  validate.py     runtime validation; raises InvalidFindingError
  emit.py         serialize to JSON dict/str (transport-agnostic)
  errors.py       OcsfEmitterError, InvalidFindingError
  _models.py      GENERATED OCSF Pydantic models (do not edit by hand)
scripts/gen_models.py   regenerate _models.py (metaschema -> JSON Schema -> Pydantic)
tests/                  mappings, builder/emit, validation-rejection, golden, multiclass
tests/test_integ_ocsf_schema.py   validates emitted events vs the OCSF JSON Schema (CI-gated)
.github/workflows/ci.yml           unit job + blocking OCSF-schema-conformance job
```

## Development

```bash
uv run pytest        # tests
uv run mypy          # strict type-checking
uv run ruff check .  # lint
uv run ruff format . # format
```
