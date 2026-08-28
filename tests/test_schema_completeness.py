"""Completeness + accuracy of our coverage vs the authoritative OCSF 1.5 schema.

Cross-checks the library against the OCSF metaschema fetched with ``ocsf-lib``
(the same source schema.ocsf.io is generated from). These tests fail if OCSF
adds/renames/renumbers anything we don't reflect, guaranteeing "100% of the
base schema" stays true over time:

* every non-deprecated, non-extension base class is supported (no missing, none
  extra);
* each class's uid / category_uid / class_name match the schema exactly;
* each class's activity_id vocabulary matches the schema exactly;
* the observable type_id set is fully covered;
* every supported class has a build example.

Fetches the metaschema over the network, so skipped unless
``OCSF_SCHEMA_VALIDATION=1`` (the CI ``ocsf-schema-validation`` job sets it).
"""

from __future__ import annotations

import functools
import os
from typing import Any

import pytest

import ocsf_emitter as o
from ocsf_emitter import OCSF_SCHEMA_VERSION
from tests.examples import EXAMPLES

pytestmark = pytest.mark.skipif(
    os.environ.get("OCSF_SCHEMA_VALIDATION") != "1",
    reason="Set OCSF_SCHEMA_VALIDATION=1 to fetch the OCSF metaschema and run this test.",
)


@functools.cache
def _schema() -> Any:
    from ocsf.api import OcsfApiClient

    return OcsfApiClient().get_schema(OCSF_SCHEMA_VERSION)


def _base_nondeprecated_classes() -> dict[str, Any]:
    """All real, non-deprecated base classes (excludes base_event + win/ extension)."""
    out = {}
    for key, cls in _schema().classes.items():
        uid = getattr(cls, "uid", None)
        if uid is None or uid == 0:  # base_event has uid 0
            continue
        if getattr(cls, "deprecated", None):
            continue
        if "/" in key or uid >= 100000:  # extension classes (e.g. win/...)
            continue
        out[key] = cls
    return out


def test_metaschema_is_the_pinned_version() -> None:
    assert _schema().version == OCSF_SCHEMA_VERSION


def test_supports_every_base_class_no_more_no_less() -> None:
    expected = set(_base_nondeprecated_classes())
    ours = {oc.value for oc in o.OcsfClass}
    assert ours == expected, (
        f"missing: {sorted(expected - ours)}; unexpected extra: {sorted(ours - expected)}"
    )


def test_all_eight_categories_present() -> None:
    cats = {o.class_spec(oc).category_uid for oc in o.OcsfClass}
    assert cats == {1, 2, 3, 4, 5, 6, 7, 8}


@pytest.mark.parametrize("ocsf_class", list(o.OcsfClass), ids=lambda c: c.value)
def test_class_identity_matches_schema(ocsf_class: o.OcsfClass) -> None:
    spec = o.class_spec(ocsf_class)
    cls = _schema().classes[ocsf_class.value]
    assert spec.class_uid == int(cls.uid)
    assert spec.category_uid == int(cls.uid) // 1000
    assert spec.class_name == cls.caption


@pytest.mark.parametrize("ocsf_class", list(o.OcsfClass), ids=lambda c: c.value)
def test_activity_enum_matches_schema(ocsf_class: o.OcsfClass) -> None:
    spec = o.class_spec(ocsf_class)
    schema_ids = {
        int(k) for k in _schema().classes[ocsf_class.value].attributes["activity_id"].enum
    }
    our_ids = {int(m.value) for m in spec.action}
    assert our_ids == schema_ids


def test_observable_types_match_schema() -> None:
    from ocsf_emitter.builders import _OBSERVABLE_TYPE_TO_ID

    schema_ids = {int(k) for k in _schema().objects["observable"].attributes["type_id"].enum}
    assert set(_OBSERVABLE_TYPE_TO_ID.values()) == schema_ids


def test_every_supported_class_has_an_example() -> None:
    assert set(EXAMPLES) == set(o.OcsfClass)
