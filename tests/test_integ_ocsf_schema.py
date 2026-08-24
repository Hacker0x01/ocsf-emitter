"""Integration test: validate emitted events against the official OCSF schema.

For each supported class this builds one event, emits it, fetches that class's
JSON Schema from ``schema.ocsf.io`` for the pinned OCSF version (matching the
event's ``metadata.profiles``), and validates the payload with ``jsonschema``.
This is a self-contained conformance check -- no third-party validator.

It needs network access to fetch schemas, so it is skipped unless
``OCSF_SCHEMA_VALIDATION=1`` is set (the CI ``ocsf-schema-validation`` job sets
it). Run locally with:

    OCSF_SCHEMA_VALIDATION=1 uv run pytest tests/test_integ_ocsf_schema.py -v
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import jsonschema
import pytest

import ocsf_emitter
from ocsf_emitter import (
    OCSF_SCHEMA_VERSION,
    ApiCall,
    ComplianceRef,
    DeviceRef,
    EndpointRef,
    FileRef,
    Observable,
    ObservableType,
    Severity,
    UserRef,
    WebResourceRef,
    build_account_change,
    build_api_activity,
    build_authentication,
    build_compliance_finding,
    build_detection_finding,
    build_file_hosting,
    build_patch_state,
    build_web_resources_activity,
    emit,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("OCSF_SCHEMA_VALIDATION") != "1",
    reason="Set OCSF_SCHEMA_VALIDATION=1 to fetch OCSF schemas and run this test.",
)

# metaschema key (== schema.ocsf.io URL segment) per supported class.
_URL_BY_CLASS_UID = {
    2004: "detection_finding",
    2003: "compliance_finding",
    3002: "authentication",
    3001: "account_change",
    5004: "patch_state",
    6003: "api_activity",
    6001: "web_resources_activity",
    6006: "file_hosting",
}


def _payloads() -> dict[str, dict[str, Any]]:
    product = ocsf_emitter.make_product(
        name="Example Detector", vendor_name="Example, Inc.", version="1.0.0"
    )
    sev = Severity.MEDIUM
    when = 1_752_566_400_000
    return {
        "detection_finding": emit(
            build_detection_finding(
                uid="det-1",
                title="Impossible-travel login",
                severity=Severity.HIGH,
                message="alice logged in from two continents within 4 minutes.",
                observables=[
                    Observable(ObservableType.USER_NAME, "alice"),
                    Observable(ObservableType.IP_ADDRESS, "203.0.113.7"),
                ],
                time_ms=when,
                product=product,
            )
        ),
        "compliance_finding": emit(
            build_compliance_finding(
                title="NTP not synchronized",
                compliance=ComplianceRef(standards=["CIS"], control="2.1"),
                severity=sev,
                product=product,
                time_ms=when,
            )
        ),
        "authentication": emit(
            build_authentication(
                user=UserRef(name="alice", email="a@example.com"),
                severity=sev,
                product=product,
                time_ms=when,
            )
        ),
        "account_change": emit(
            build_account_change(
                user=UserRef(name="bob"), severity=sev, product=product, time_ms=when
            )
        ),
        "patch_state": emit(
            build_patch_state(
                device=DeviceRef(hostname="web01", os_name="ubuntu", os_version="22.04"),
                severity=sev,
                product=product,
                time_ms=when,
            )
        ),
        "api_activity": emit(
            build_api_activity(
                api=ApiCall(operation="CreateAccessKey", service="iam.amazonaws.com"),
                src_endpoint=EndpointRef(ip="203.0.113.7"),
                actor_user=UserRef(name="root"),
                severity=sev,
                product=product,
                time_ms=when,
            )
        ),
        "web_resources_activity": emit(
            build_web_resources_activity(
                web_resources=[WebResourceRef(name="report-123", type="report")],
                severity=sev,
                product=product,
                time_ms=when,
            )
        ),
        "file_hosting": emit(
            build_file_hosting(
                file=FileRef(name="secret.pdf", mime_type="application/pdf"),
                src_endpoint=EndpointRef(ip="198.51.100.9"),
                # OCSF `user` requires anyOf(name|uid|account); supply a name.
                actor_user=UserRef(name="alice", email="a@example.com"),
                severity=sev,
                product=product,
                time_ms=when,
            )
        ),
    }


# Cache fetched schemas for the process so re-runs and shared profiles don't
# re-hit the (slow) schema server.
_SCHEMA_CACHE: dict[str, dict[str, Any]] = {}
_FETCH_ATTEMPTS = 5
_FETCH_TIMEOUT_S = 45


def _fetch_schema(url_class: str, profiles: list[str]) -> dict[str, Any]:
    prof = ",".join(profiles)
    url = (
        f"https://schema.ocsf.io/schema/{OCSF_SCHEMA_VERSION}/classes/"
        f"{url_class}?profiles={urllib.parse.quote(prof)}"
    )
    if url in _SCHEMA_CACHE:
        return _SCHEMA_CACHE[url]

    # schema.ocsf.io is slow and occasionally times out; retry with backoff so a
    # transient failure doesn't fail the gate.
    last_exc: Exception | None = None
    for attempt in range(_FETCH_ATTEMPTS):
        try:
            with urllib.request.urlopen(url, timeout=_FETCH_TIMEOUT_S) as resp:  # noqa: S310
                schema: dict[str, Any] = json.loads(resp.read())
            _SCHEMA_CACHE[url] = schema
            return schema
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            last_exc = exc
            if attempt < _FETCH_ATTEMPTS - 1:
                time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"Could not fetch OCSF schema after {_FETCH_ATTEMPTS} tries: {url}") from (
        last_exc
    )


@pytest.mark.parametrize("class_name", list(_payloads()))
def test_emitted_event_conforms_to_ocsf_schema(class_name: str) -> None:
    payload = _payloads()[class_name]
    class_uid = int(payload["class_uid"])
    metadata: dict[str, Any] = payload.get("metadata", {})
    profiles: list[str] = list(metadata.get("profiles", []))
    schema = _fetch_schema(_URL_BY_CLASS_UID[class_uid], profiles)

    errors = sorted(
        jsonschema.Draft7Validator(schema).iter_errors(payload),
        key=lambda e: list(e.absolute_path),
    )
    assert not errors, "OCSF schema validation failed for {}:\n{}".format(
        class_name,
        "\n".join(f"  - {list(e.absolute_path)}: {e.message}" for e in errors),
    )
