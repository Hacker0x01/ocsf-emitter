"""Every supported OCSF class builds, emits, and validates (offline).

Parametrized over the whole class registry via ``tests/examples.py`` so all 53
classes are exercised without a bespoke test each. Also asserts the example set
is complete and that emitted identity matches the registry.
"""

from __future__ import annotations

import pytest

import ocsf_emitter as o
from tests.examples import EXAMPLES


def test_examples_cover_every_class() -> None:
    assert set(EXAMPLES) == set(o.OcsfClass), "tests/examples.py is missing OCSF classes"


@pytest.mark.parametrize("ocsf_class", list(o.OcsfClass), ids=lambda c: c.value)
def test_build_emit_validate(ocsf_class: o.OcsfClass) -> None:
    event = EXAMPLES[ocsf_class]()
    spec = o.class_spec(ocsf_class)

    # Identity matches the registry.
    assert int(event.class_uid) == spec.class_uid
    assert int(event.category_uid) == spec.category_uid
    assert int(event.type_uid) == spec.type_uid(int(event.activity_id.value))

    # emit() runs validate() (schema re-check + OCSF invariants) and serializes.
    payload = o.emit(event)
    assert payload["class_uid"] == spec.class_uid
    assert payload["type_uid"] == spec.type_uid(int(event.activity_id.value))
    assert payload["metadata"]["version"] == o.OCSF_SCHEMA_VERSION
