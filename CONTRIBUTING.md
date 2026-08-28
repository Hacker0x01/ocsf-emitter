# Contributing to ocsf-emitter

Thanks for your interest in improving `ocsf-emitter`. This guide covers local
setup, the quality gates, and how to make changes that touch the generated OCSF
models.

## Development setup

The project uses [uv](https://docs.astral.sh/uv/). With uv installed:

```bash
uv sync                         # runtime + dev/docs groups
```

Or, with plain pip:

```bash
pip install -e .
pip install mypy pytest ruff jsonschema
```

## Quality gates

Every change must pass all four gates locally (CI enforces the same):

```bash
uv run ruff check .        # lint (incl. docstring + annotation rules)
uv run ruff format --check .  # formatting
uv run mypy                # strict type-checking
uv run pytest -q \
  --ignore=tests/test_integ_ocsf_schema.py \
  --ignore=tests/test_schema_completeness.py   # unit tests (network tests excluded)
```

### Docstrings and type hints

- Every public module, class, and function needs a **Google-style docstring**
  and **complete type hints**. This is enforced by ruff's `D` and `ANN` rule
  sets and by `mypy --strict`.
- Tests and the codegen script are exempt from docstring rules (see
  `[tool.ruff.lint.per-file-ignores]`).

## Running the OCSF schema tests (conformance + completeness)

Two network-gated test modules cross-check the library against the OCSF
metaschema (via `ocsf-lib`, the source schema.ocsf.io is generated from) for the
pinned version, with `at_least_one`/`just_one` constraints enforced:

- `tests/test_integ_ocsf_schema.py` — every emitted class **conforms** to the schema.
- `tests/test_schema_completeness.py` — coverage is **complete and accurate**:
  every non-deprecated base class is supported (no missing, none extra), and each
  class's uid / category / name / activity enum and the observable type set match
  the schema exactly.

Both are skipped unless `OCSF_SCHEMA_VALIDATION=1` is set (they need network):

```bash
OCSF_SCHEMA_VALIDATION=1 uv run pytest \
  tests/test_integ_ocsf_schema.py tests/test_schema_completeness.py -v
```

CI runs both as a **blocking** job.

## Changing the OCSF version or regenerating models

`src/ocsf_emitter/_models.py` is **generated — do not edit it by hand**.

1. Regenerate for a version (keep `DEFAULT_VERSION` in `scripts/gen_models.py`
   and the pin below in sync):
   ```bash
   uv run --extra codegen python scripts/gen_models.py 1.5.0
   ```
2. Update the one-line pin `OCSF_SCHEMA_VERSION` in `src/ocsf_emitter/defaults.py`.
3. If the emitted shape changed intentionally, regenerate the golden sample
   `tests/golden_detection_finding.json` and review the diff.
4. Run the schema conformance test (above) to confirm the new version validates.

## Documentation

Docs are built with MkDocs + mkdocstrings (API reference is generated from
docstrings):

```bash
uv run --group docs mkdocs serve   # live preview at http://127.0.0.1:8000
uv run --group docs mkdocs build --strict
```

Docs deploy to GitHub Pages automatically on push to `main`.

## Pull requests

1. Branch off `main`.
2. Keep changes focused; add or update tests for behavior changes.
3. Ensure all four gates pass and, if relevant, the OCSF schema conformance test.
4. Write a clear PR description explaining the change and its rationale.

## Releasing

Releases publish to PyPI automatically when a **GitHub Release is published**
(via PyPI Trusted Publishing / OIDC — no API token needed). Bump the `version`
in `pyproject.toml`, tag, and publish a Release.
