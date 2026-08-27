"""Integration test: validate emitted events against the official OCSF schema.

For every supported class this builds one event (from ``tests/examples.py``),
emits it, and validates the payload against a JSON Schema derived from the OCSF
**metaschema** for the pinned version -- the same authoritative source
``scripts/gen_models.py`` generates the models from (fetched via ``ocsf-lib``).
This is a self-contained conformance check: it does not depend on the
``schema.ocsf.io/.../classes/<name>`` endpoint, which is slow and frequently
unavailable.

It fetches the metaschema over the network, so it is skipped unless
``OCSF_SCHEMA_VALIDATION=1`` is set (the CI ``ocsf-schema-validation`` job sets
it). Run locally with:

    OCSF_SCHEMA_VALIDATION=1 uv run pytest tests/test_integ_ocsf_schema.py -v
"""

from __future__ import annotations

import functools
import os
from typing import Any

import jsonschema
import pytest

import ocsf_emitter as o
from ocsf_emitter import OCSF_SCHEMA_VERSION, emit
from tests.examples import EXAMPLES

pytestmark = pytest.mark.skipif(
    os.environ.get("OCSF_SCHEMA_VALIDATION") != "1",
    reason="Set OCSF_SCHEMA_VALIDATION=1 to fetch the OCSF metaschema and run this test.",
)


@functools.cache
def _class_schemas() -> dict[str, dict[str, Any]]:
    """Build one self-contained JSON Schema per class from the OCSF metaschema.

    Fetches the metaschema once via ``ocsf-lib`` and converts the union of all
    root classes with ``scripts/gen_models.py`` (the code that generates the
    models). Each class's ``$def`` is returned as a standalone schema carrying
    the shared ``$defs`` so ``#/$defs/...`` refs resolve. Cached for the session.
    """
    from ocsf.api import OcsfApiClient
    from scripts.gen_models import ROOT_CLASSES, metaschema_to_json_schema

    schema = OcsfApiClient().get_schema(OCSF_SCHEMA_VERSION)
    doc = metaschema_to_json_schema(schema, ROOT_CLASSES)
    defs: dict[str, Any] = doc["$defs"]
    # Key by class_uid so we can line up with each emitted payload.
    by_uid: dict[str, dict[str, Any]] = {}
    for oc in o.OcsfClass:
        spec = o.class_spec(oc)
        key = oc.value
        by_uid[str(spec.class_uid)] = {**defs[key], "$defs": defs}
    return by_uid


@pytest.mark.parametrize("ocsf_class", list(o.OcsfClass), ids=lambda c: c.value)
def test_emitted_event_conforms_to_ocsf_schema(ocsf_class: o.OcsfClass) -> None:
    payload = emit(EXAMPLES[ocsf_class]())
    schema = _class_schemas()[str(payload["class_uid"])]

    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(payload),
        key=lambda e: list(e.absolute_path),
    )
    assert not errors, "OCSF schema validation failed for {}:\n{}".format(
        ocsf_class.value,
        "\n".join(f"  - {list(e.absolute_path)}: {e.message}" for e in errors),
    )
