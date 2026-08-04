"""Build → validate → emit round-trips for every non-DetectionFinding class.

Each test builds one OCSF class with its class-specific required objects, emits
it (which validates), and asserts the class identity, ``type_uid``, and that the
class-specific required attributes survived to the payload. A parametrized
invariant test proves the registry-driven ``validate`` accepts every class.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

import ocsf_emitter
import ocsf_emitter as o
from ocsf_emitter import emit, validate
from ocsf_emitter.errors import InvalidFindingError


def test_authentication_round_trip(fixed_clock: Callable[[], int]) -> None:
    evt = o.build_authentication(
        user=o.UserRef(name="alice", email="alice@example.com"),
        severity=o.Severity.MEDIUM,
        activity=o.AuthAction.LOGON,
        is_mfa=False,
        message="SSO logon without MFA",
        clock=fixed_clock,
    )
    payload = emit(evt)
    assert payload["class_uid"] == 3002
    assert payload["category_uid"] == 3
    assert payload["type_uid"] == 300201
    assert payload["user"]["name"] == "alice"
    # Constraint: at least one of service / dst_endpoint. A default service fills in.
    assert "service" in payload or "dst_endpoint" in payload
    assert payload["is_mfa"] is False


def test_authentication_dst_endpoint_satisfies_constraint() -> None:
    evt = o.build_authentication(
        user=o.UserRef(name="bob"),
        severity=o.Severity.LOW,
        dst_endpoint=o.EndpointRef(hostname="sso.example.com"),
    )
    payload = emit(evt)
    # When dst_endpoint is supplied, no synthetic service is added.
    assert payload["dst_endpoint"]["hostname"] == "sso.example.com"
    assert "service" not in payload


def test_account_change_round_trip() -> None:
    evt = o.build_account_change(
        user=o.UserRef(name="carol", uid="U123"),
        severity=o.Severity.HIGH,
        activity=o.AccountChangeAction.CREATE,
    )
    payload = emit(evt)
    assert payload["class_uid"] == 3001
    assert payload["type_uid"] == 300101
    assert payload["user"]["uid"] == "U123"


def test_patch_state_round_trip() -> None:
    evt = o.build_patch_state(
        device=o.DeviceRef(hostname="web01", os_name="ubuntu", os_version="22.04"),
        severity=o.Severity.LOW,
        activity=o.PatchStateAction.LOG,
    )
    payload = emit(evt)
    assert payload["class_uid"] == 5004
    assert payload["type_uid"] == 500401
    # Constraint: at least one of os.sp_name / os.sp_ver / os.version.
    assert payload["device"]["os"]["version"] == "22.04"


def test_api_activity_round_trip() -> None:
    evt = o.build_api_activity(
        api=o.ApiCall(operation="CreateAccessKey", service="iam.amazonaws.com"),
        severity=o.Severity.HIGH,
        activity=o.ApiAction.CREATE,
        src_endpoint=o.EndpointRef(ip="203.0.113.7"),
        actor_user=o.UserRef(name="root"),
    )
    payload = emit(evt)
    assert payload["class_uid"] == 6003
    assert payload["type_uid"] == 600301
    assert payload["api"]["operation"] == "CreateAccessKey"
    assert payload["src_endpoint"]["ip"] == "203.0.113.7"
    assert payload["actor"]["user"]["name"] == "root"


def test_web_resources_activity_round_trip() -> None:
    evt = o.build_web_resources_activity(
        web_resources=[o.WebResourceRef(name="report-123", type="report")],
        severity=o.Severity.MEDIUM,
        activity=o.WebResourceAction.READ,
    )
    payload = emit(evt)
    assert payload["class_uid"] == 6001
    assert payload["type_uid"] == 600102
    assert payload["web_resources"][0]["name"] == "report-123"


def test_file_hosting_round_trip() -> None:
    evt = o.build_file_hosting(
        file=o.FileRef(name="secret.pdf", mime_type="application/pdf"),
        severity=o.Severity.HIGH,
        activity=o.FileHostingAction.SHARE,
        actor_user=o.UserRef(email="alice@example.com"),
        src_endpoint=o.EndpointRef(ip="198.51.100.9"),
    )
    payload = emit(evt)
    assert payload["class_uid"] == 6006
    assert payload["type_uid"] == 600612
    assert payload["file"]["name"] == "secret.pdf"
    assert payload["actor"]["user"]["email_addr"] == "alice@example.com"


def test_compliance_finding_round_trip() -> None:
    evt = o.build_compliance_finding(
        title="NTP not synchronized",
        compliance=o.ComplianceRef(standards=["CIS"], control="2.1"),
        severity=o.Severity.LOW,
        activity=o.Activity.CREATE,
        uid="cmp-001",
    )
    payload = emit(evt)
    assert payload["class_uid"] == 2003
    assert payload["type_uid"] == 200301
    assert payload["compliance"]["standards"] == ["CIS"]
    assert payload["finding_info"]["uid"] == "cmp-001"


# One builder thunk per class. Built lazily (inside the test) so the autouse
# product fixture has run by the time each is called.
_BUILDERS: list[Callable[[], object]] = [
    lambda: o.build_authentication(user=o.UserRef(name="a"), severity=o.Severity.LOW),
    lambda: o.build_account_change(user=o.UserRef(name="b"), severity=o.Severity.LOW),
    lambda: o.build_patch_state(
        device=o.DeviceRef(hostname="h", os_version="1.0"), severity=o.Severity.LOW
    ),
    lambda: o.build_api_activity(api=o.ApiCall(operation="X"), severity=o.Severity.LOW),
    lambda: o.build_web_resources_activity(
        web_resources=[o.WebResourceRef(name="r")], severity=o.Severity.LOW
    ),
    lambda: o.build_file_hosting(file=o.FileRef(name="f.pdf"), severity=o.Severity.LOW),
    lambda: o.build_compliance_finding(
        title="t", compliance=o.ComplianceRef(standards=["CIS"]), severity=o.Severity.LOW
    ),
    lambda: o.build_detection_finding(title="t", severity=o.Severity.LOW, message="m"),
]


@pytest.mark.parametrize("make_event", _BUILDERS)
def test_validate_accepts_every_supported_class(make_event: Callable[[], object]) -> None:
    # validate re-runs schema + invariant checks and returns an equal instance.
    event = make_event()
    validated = validate(event)  # type: ignore[arg-type]
    assert int(validated.class_uid) == int(event.class_uid)  # type: ignore[attr-defined]
    assert validated.model_dump(by_alias=True) == event.model_dump(by_alias=True)  # type: ignore[attr-defined]


def test_validate_rejects_tampered_type_uid() -> None:
    evt = o.build_file_hosting(file=o.FileRef(name="f.pdf"), severity=o.Severity.LOW)
    object.__setattr__(evt, "type_uid", 600699)  # inconsistent with activity_id
    with pytest.raises(InvalidFindingError) as exc:
        validate(evt)
    assert any("type_uid" in e for e in exc.value.field_errors)


def test_missing_product_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    # Clear the process-wide product so the builder has no identity to stamp.
    monkeypatch.setattr(ocsf_emitter.defaults, "_DEFAULT_PRODUCT", None)
    with pytest.raises(o.OcsfEmitterError):
        o.build_authentication(user=o.UserRef(name="a"), severity=o.Severity.LOW)
