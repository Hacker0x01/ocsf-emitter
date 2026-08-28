"""Observable type coverage: every OCSF 1.5.0 observable type_id is exposed.

Guards that ``ObservableType`` + ``_OBSERVABLE_TYPE_TO_ID`` stay in sync with the
generated observable model's ``type_id`` enum (the authoritative set), so an
OCSF version bump that shifts the ids can't silently drift.
"""

from __future__ import annotations

import pytest

import ocsf_emitter as o
from ocsf_emitter import _models as m
from ocsf_emitter.builders import _OBSERVABLE_TYPE_TO_ID, build_observable
from ocsf_emitter.domain import Observable, ObservableType


def _model_type_ids() -> set[int]:
    """The set of valid observable ``type_id`` values in the generated model."""
    ann = m.Observable.model_fields["type_id"].annotation
    enum_t = next(a for a in getattr(ann, "__args__", [ann]) if hasattr(a, "__members__"))
    return {int(v.value) for v in enum_t}


def test_every_observable_type_is_mapped() -> None:
    # Totality: no ObservableType missing an id (a missing key would KeyError).
    assert set(_OBSERVABLE_TYPE_TO_ID) == set(ObservableType)


def test_mapping_matches_full_ocsf_type_id_set() -> None:
    # We expose the *entire* observable type_id enum, and every id is valid.
    assert set(_OBSERVABLE_TYPE_TO_ID.values()) == _model_type_ids()


def test_ids_are_unique() -> None:
    ids = list(_OBSERVABLE_TYPE_TO_ID.values())
    assert len(ids) == len(set(ids))


def test_known_ids_are_correct_for_1_5() -> None:
    # Spot-check ids that shifted between OCSF versions / are easy to get wrong.
    assert _OBSERVABLE_TYPE_TO_ID[ObservableType.PROCESS_NAME] == 9  # was 20 in 1.1.0
    assert _OBSERVABLE_TYPE_TO_ID[ObservableType.ENDPOINT] == 20
    assert _OBSERVABLE_TYPE_TO_ID[ObservableType.OTHER] == 99


@pytest.mark.parametrize("obs_type", list(ObservableType), ids=lambda t: t.name)
def test_build_observable_round_trips_every_type(obs_type: ObservableType) -> None:
    ocsf = build_observable(Observable(obs_type, "some-value"))
    payload = ocsf.model_dump(by_alias=True, exclude_none=True)
    assert payload["type_id"] == _OBSERVABLE_TYPE_TO_ID[obs_type]
    # Falls back to the type's name when no explicit observable name is given.
    assert payload["name"] == obs_type.value
    assert payload["value"] == "some-value"


def test_observable_on_a_finding_validates() -> None:
    o.configure_product(name="t", vendor_name="v")
    finding = o.build_detection_finding(
        title="t",
        severity=o.Severity.LOW,
        message="m",
        observables=[
            Observable(ObservableType.ENDPOINT, "web01"),
            Observable(ObservableType.MAC_ADDRESS, "00:11:22:33:44:55"),
        ],
    )
    payload = o.emit(finding)
    assert {obs["type_id"] for obs in payload["observables"]} == {20, 3}
