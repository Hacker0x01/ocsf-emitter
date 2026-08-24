"""Integration test: validate emitted events against the official OCSF schema.

For each supported class this builds one event, emits it, and validates the
payload against a JSON Schema derived from the OCSF **metaschema** for the pinned
version -- the same authoritative source ``scripts/gen_models.py`` generates the
models from (fetched via ``ocsf-lib``). This is a self-contained conformance
check: it does not depend on the ``schema.ocsf.io/.../classes/<name>`` endpoint,
which is slow and frequently unavailable.

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
    reason="Set OCSF_SCHEMA_VALIDATION=1 to fetch the OCSF metaschema and run this test.",
)

# metaschema class key (== ROOT_CLASSES in gen_models) per supported class_uid.
_ROOT_KEY_BY_CLASS_UID = {
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


@functools.cache
def _class_schemas() -> dict[str, dict[str, Any]]:
    """Build one self-contained JSON Schema per supported class from the metaschema.

    Fetches the OCSF metaschema once via ``ocsf-lib`` and converts the union of
    all root classes with ``scripts/gen_models.py`` (the same code that generates
    the models). Each class's ``$def`` is returned as a standalone schema carrying
    the shared ``$defs`` so ``#/$defs/...`` refs resolve. Cached for the session.
    """
    from ocsf.api import OcsfApiClient
    from scripts.gen_models import metaschema_to_json_schema

    schema = OcsfApiClient().get_schema(OCSF_SCHEMA_VERSION)
    roots = list(_ROOT_KEY_BY_CLASS_UID.values())
    doc = metaschema_to_json_schema(schema, roots)
    defs: dict[str, Any] = doc["$defs"]
    return {key: {**defs[key], "$defs": defs} for key in roots}


@pytest.mark.parametrize("class_name", list(_ROOT_KEY_BY_CLASS_UID.values()))
def test_emitted_event_conforms_to_ocsf_schema(class_name: str) -> None:
    payload = _payloads()[class_name]
    schema = _class_schemas()[class_name]

    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(payload),
        key=lambda e: list(e.absolute_path),
    )
    assert not errors, "OCSF schema validation failed for {}:\n{}".format(
        class_name,
        "\n".join(f"  - {list(e.absolute_path)}: {e.message}" for e in errors),
    )
