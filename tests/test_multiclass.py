"""Edge-case tests for the multi-class builders.

Per-class build->emit->validate round-trips live in ``test_all_classes.py``
(parametrized over the whole registry). This module keeps the behavioral edge
cases that aren't just "one of each".
"""

from __future__ import annotations

import pytest

import ocsf_emitter
import ocsf_emitter as o
from ocsf_emitter import emit, validate
from ocsf_emitter.errors import InvalidFindingError


def test_authentication_default_service_satisfies_constraint() -> None:
    # OCSF Authentication requires at least one of service / dst_endpoint; the
    # builder synthesizes a default service when neither is given.
    payload = emit(o.build_authentication(user=o.UserRef(name="a"), severity=o.Severity.LOW))
    assert payload.get("service") or payload.get("dst_endpoint")


def test_authentication_dst_endpoint_satisfies_constraint() -> None:
    payload = emit(
        o.build_authentication(
            user=o.UserRef(name="bob"),
            severity=o.Severity.LOW,
            dst_endpoint=o.EndpointRef(hostname="sso.example.com"),
        )
    )
    assert payload["dst_endpoint"]["hostname"] == "sso.example.com"
    assert "service" not in payload


def test_api_activity_synthesizes_empty_actor_and_endpoint() -> None:
    # actor + src_endpoint are required; empty objects are synthesized when the
    # caller supplies neither, so the event still validates.
    payload = emit(
        o.build_api_activity(
            api=o.ApiCall(operation="X"), severity=o.Severity.LOW, activity=o.ApiActivityAction.READ
        )
    )
    assert "actor" in payload and "src_endpoint" in payload


def test_validate_rejects_tampered_type_uid() -> None:
    evt = o.build_file_hosting(
        file=o.FileRef(name="f.pdf"), severity=o.Severity.LOW, activity=o.FileHostingAction.SHARE
    )
    object.__setattr__(evt, "type_uid", 600699)  # inconsistent with activity_id
    with pytest.raises(InvalidFindingError) as exc:
        validate(evt)
    assert any("type_uid" in e for e in exc.value.field_errors)


def test_validate_rejects_unsupported_class_uid() -> None:
    evt = o.build_detection_finding(title="t", severity=o.Severity.LOW, message="m")
    object.__setattr__(evt, "class_uid", 9999)
    with pytest.raises(InvalidFindingError):
        validate(evt)


def test_missing_product_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ocsf_emitter.defaults, "_DEFAULT_PRODUCT", None)
    with pytest.raises(o.OcsfEmitterError):
        o.build_authentication(user=o.UserRef(name="a"), severity=o.Severity.LOW)
