# Contributing to ocsf-emitter

Thanks for your interest in improving `ocsf-emitter`. This guide covers local
setup, the quality gates, and how to make changes that touch the generated OCSF
models or the AWS Security Lake compatibility surface.

## Development setup

The project uses [uv](https://docs.astral.sh/uv/). With uv installed:

```bash
uv sync --all-extras            # runtime + securitylake extra + dev/docs groups
```

Or, with plain pip:

```bash
pip install -e ".[securitylake]"
pip install mypy pytest ruff
```

## Quality gates

Every change must pass all four gates locally (CI enforces the same):

```bash
uv run ruff check .        # lint (incl. docstring + annotation rules)
uv run ruff format --check .  # formatting
uv run mypy                # strict type-checking
uv run pytest -q --ignore=tests/test_integ_aws_validation.py   # unit tests
```

### Docstrings and type hints

- Every public module, class, and function needs a **Google-style docstring**
  and **complete type hints**. This is enforced by ruff's `D` and `ANN` rule
  sets and by `mypy --strict`.
- Tests and the codegen script are exempt from docstring rules (see
  `[tool.ruff.lint.per-file-ignores]`).

## Running the AWS Security Lake validation test

The integration test in `tests/test_integ_aws_validation.py` runs AWS's own
[OCSF validation tool](https://github.com/aws-samples/amazon-security-lake-ocsf-validation)
against an emitted finding. It is skipped unless `OCSF_AWS_VALIDATION_DIR` points
at a checkout of that tool:

```bash
git clone https://github.com/aws-samples/amazon-security-lake-ocsf-validation.git /tmp/aws-ocsf
uv pip install -r /tmp/aws-ocsf/requirements.txt pytest
OCSF_AWS_VALIDATION_DIR=/tmp/aws-ocsf uv run pytest tests/test_integ_aws_validation.py -v
```

CI runs this as a **blocking** job.

## Changing the OCSF version or regenerating models

`src/ocsf_emitter/_models.py` is **generated — do not edit it by hand**.

1. Regenerate for a version:
   ```bash
   uv run --extra codegen python scripts/gen_models.py 1.1.0
   ```
2. Update the one-line pin `OCSF_SCHEMA_VERSION` in `src/ocsf_emitter/defaults.py`.
3. If the emitted shape changed intentionally, regenerate the golden sample
   `tests/golden_detection_finding.json` and review the diff.

> Security Lake accepts OCSF 1.1.0 / 1.0.0-rc.2 only. Bumping past that will fail
> the blocking `aws-validation` CI job. See the README's Security Lake section.

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
3. Ensure all four gates pass and, if relevant, the AWS validation test.
4. Write a clear PR description explaining the change and its rationale.

## Releasing

Releases publish to PyPI automatically when a **GitHub Release is published**
(via PyPI Trusted Publishing / OIDC — no API token needed). Bump the `version`
in `pyproject.toml`, tag, and publish a Release.
