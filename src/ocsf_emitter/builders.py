"""Map our domain signals onto OCSF Detection Finding (class_uid 2004) models.

The builder returns a typed, already-valid ``DetectionFinding`` instance. All
OCSF-specific knowledge (field names, ``*_id`` integers, defaults) is confined
to this module and ``defaults``.
"""

from __future__ import annotations

import time as _time
import uuid
from collections.abc import Callable, Sequence

from . import _models as _m
from . import defaults
from .defaults import (
    AccountChangeAction,
    Activity,
    ApiAction,
    AuthAction,
    Confidence,
    FileHostingAction,
    OcsfClass,
    PatchStateAction,
    RiskLevel,
    Severity,
    Status,
    WebResourceAction,
)
from .domain import (
    ApiCall,
    ComplianceRef,
    DetectionSignal,
    DeviceRef,
    EndpointRef,
    FileRef,
    MitreAttack,
    Observable,
    ObservableType,
    UserRef,
    WebResourceRef,
)
from .errors import OcsfEmitterError

# Our observable kinds -> OCSF observable type_id. See the OCSF observable
# object spec for the full list; we map the subset we emit.
_OBSERVABLE_TYPE_TO_ID: dict[ObservableType, int] = {
    ObservableType.UNKNOWN: 0,
    ObservableType.HOSTNAME: 1,
    ObservableType.IP_ADDRESS: 2,
    ObservableType.URL: 6,
    ObservableType.FILE_HASH: 8,
    ObservableType.FILE_NAME: 7,
    ObservableType.USER_NAME: 4,
    ObservableType.EMAIL_ADDRESS: 5,
    ObservableType.PROCESS_NAME: 20,
    ObservableType.RESOURCE_UID: 10,
}


def _now_ms() -> int:
    return int(_time.time() * 1000)


def _new_uid() -> str:
    return str(uuid.uuid4())


def build_observable(observable: Observable) -> _m.Observable:
    """Map one domain Observable to an OCSF observable model.

    OCSF ``observable.name`` is the attribute name/path and is required. When the
    caller does not supply one we fall back to the observable type's label (e.g.
    ``"ip_address"``).
    """
    return _m.Observable(
        name=observable.name if observable.name is not None else observable.type.value,
        value=observable.value,
        # Pass the plain int; Pydantic coerces it into whichever per-object enum
        # the generated ``type_id`` field uses. Do NOT hardcode ``_m.TypeIdN`` --
        # datamodel-codegen renumbers those names across schema versions, and the
        # observable type enum is a wide one (0-10, 20-30, 99).
        type_id=_OBSERVABLE_TYPE_TO_ID[observable.type],
    )


def build_attack(attack: MitreAttack) -> _m.Attack:
    """Map a MitreAttack to an OCSF attack object (technique [+ tactic])."""
    technique = _m.Technique(uid=attack.technique_uid, name=attack.technique_name)
    tactics = None
    if attack.tactic_uid is not None:
        tactics = [_m.Tactic(uid=attack.tactic_uid, name=attack.tactic_name)]
    return _m.Attack(technique=technique, tactics=tactics)


def build_user(user: UserRef) -> _m.User:
    """Map a domain UserRef to an OCSF user object."""
    return _m.User(
        name=user.name,
        uid=user.uid,
        email_addr=user.email,
        domain=user.domain,
        full_name=user.full_name,
    )


def build_device(device: DeviceRef) -> _m.Device:
    """Map a domain DeviceRef to an OCSF device object (with nested os)."""
    os = None
    if device.os_name or device.os_version or device.os_sp_name or device.os_sp_ver:
        os = _m.Os(
            name=device.os_name if device.os_name is not None else "unknown",
            # Plain ints; Pydantic coerces into the field's per-object enum (see
            # build_observable -- generated enum names are not version-stable).
            type_id=device.os_type_id,
            version=device.os_version,
            sp_name=device.os_sp_name,
            sp_ver=device.os_sp_ver,
        )
    return _m.Device(
        hostname=device.hostname,
        uid=device.uid,
        type_id=device.type_id,
        os=os,
    )


def build_file(file: FileRef) -> _m.File:
    """Map a domain FileRef to an OCSF file object."""
    return _m.File(
        name=file.name,
        type_id=file.type_id,  # plain int; Pydantic coerces (see build_observable)
        mime_type=file.mime_type,
        uid=file.uid,
        path=file.path,
    )


def build_api(api: ApiCall) -> _m.Api:
    """Map a domain ApiCall to an OCSF api object."""
    service = _m.Service(name=api.service) if api.service is not None else None
    return _m.Api(operation=api.operation, service=service, version=api.version)


def build_web_resource(resource: WebResourceRef) -> _m.WebResource:
    """Map a domain WebResourceRef to an OCSF web_resource object."""
    return _m.WebResource(
        name=resource.name,
        type=resource.type,
        uid=resource.uid,
        url_string=resource.url_string,
    )


def build_endpoint(endpoint: EndpointRef) -> _m.NetworkEndpoint:
    """Map a domain EndpointRef to an OCSF network_endpoint object."""
    return _m.NetworkEndpoint(
        ip=endpoint.ip,
        hostname=endpoint.hostname,
        port=endpoint.port,
        uid=endpoint.uid,
    )


def build_compliance(compliance: ComplianceRef) -> _m.Compliance:
    """Map a domain ComplianceRef to an OCSF compliance object."""
    return _m.Compliance(
        standards=list(compliance.standards),
        control=compliance.control,
        status=compliance.status,
    )


def build_detection_finding(
    *,
    title: str,
    severity: Severity,
    message: str,
    uid: str | None = None,
    observables: Sequence[Observable] | None = None,
    activity: Activity = Activity.CREATE,
    status: Status = Status.NEW,
    description: str | None = None,
    time_ms: int | None = None,
    data_sources: Sequence[str] | None = None,
    confidence: Confidence | None = None,
    confidence_score: int | None = None,
    risk_level: RiskLevel | None = None,
    risk_score: int | None = None,
    attacks: Sequence[MitreAttack] | None = None,
    count: int | None = None,
    first_seen_ms: int | None = None,
    last_seen_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
    uid_factory: Callable[[], str] = _new_uid,
) -> _m.DetectionFinding:
    """Build a typed, valid OCSF Detection Finding from our fields.

    This is the primary entry point. It stamps house defaults (metadata,
    product, schema version, activity/severity/status mappings, event time) so
    every finding leaves with a consistent shape.

    Args:
        title: Short human-facing finding title.
        severity: Our severity; mapped to OCSF ``severity_id``.
        message: Human-readable description of the detection.
        uid: Stable unique id (OCSF ``finding_info.uid``). Auto-generated via
            ``uid_factory`` (uuid4 by default) when omitted -- prefer passing a
            stable id so downstream systems can deduplicate.
        observables: Entities the finding refers to.
        activity: Lifecycle activity; drives ``activity_id`` and ``type_uid``.
        status: Triage status; mapped to OCSF ``status_id``.
        description: Longer detail, stored on ``finding_info.desc``.
        time_ms: Event time (epoch ms). Defaults to ``clock()``.
        data_sources: Provenance, stored on ``finding_info.data_sources``.
        confidence: Detector confidence; mapped to ``confidence_id``.
        confidence_score: Numeric confidence (0-100), stored on ``confidence_score``.
        risk_level: Risk assessment; mapped to ``risk_level_id``.
        risk_score: Numeric risk score, stored on ``risk_score``.
        attacks: MITRE ATT&CK references, stored on ``finding_info.attacks``.
        count: Observation count, stored on ``count``.
        first_seen_ms: First observation time (epoch ms) -> finding_info.first_seen_time.
        last_seen_ms: Last observation time (epoch ms) -> finding_info.last_seen_time.
        product: OCSF Product to stamp; defaults to the process-wide product set
            via ``defaults.configure_product`` (see :func:`build_from_signal`).
        clock: Injectable time source (epoch ms) for deterministic tests.
        uid_factory: Injectable uid source for deterministic tests.

    Returns:
        A ``DetectionFinding`` model instance. Pydantic validates field types at
        construction; call :func:`ocsf_emitter.validate.validate` (or ``emit``)
        for the full pre-flight check.
    """
    signal = DetectionSignal(
        uid=uid if uid is not None else uid_factory(),
        title=title,
        severity=severity,
        message=message,
        activity=activity,
        status=status,
        observables=list(observables or []),
        description=description,
        time_ms=time_ms,
        data_sources=list(data_sources or []),
        confidence=confidence,
        confidence_score=confidence_score,
        risk_level=risk_level,
        risk_score=risk_score,
        attacks=list(attacks or []),
        count=count,
        first_seen_ms=first_seen_ms,
        last_seen_ms=last_seen_ms,
    )
    return build_from_signal(signal, product=product, clock=clock)


def build_from_signal(
    signal: DetectionSignal,
    *,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.DetectionFinding:
    """Build an OCSF Detection Finding from a fully-formed domain signal.

    ``product`` overrides the process-wide default set via
    ``defaults.configure_product``. If neither is set, raises
    :class:`OcsfEmitterError` rather than emitting an unattributed finding.
    """
    resolved_product = product if product is not None else defaults.default_product()
    if resolved_product is None:
        raise OcsfEmitterError(
            "No product configured. Call ocsf_emitter.configure_product(name=..., "
            "vendor_name=...) once at startup, or pass product= to the builder."
        )

    event_time = signal.time_ms if signal.time_ms is not None else clock()

    finding_info = _m.FindingInfo(
        uid=signal.uid,
        title=signal.title,
        desc=signal.description,
        data_sources=list(signal.data_sources) or None,
        attacks=[build_attack(a) for a in signal.attacks] or None,
        first_seen_time=signal.first_seen_ms,
        last_seen_time=signal.last_seen_ms,
    )

    ocsf_observables = [build_observable(o) for o in signal.observables] or None

    return _m.DetectionFinding(
        # Class identity (fixed for class_uid 2004).
        class_uid=defaults.class_uid(),
        category_uid=defaults.category_uid(),
        class_name=defaults.CLASS_NAME,
        category_name=defaults.CATEGORY_NAME,
        type_uid=defaults.type_uid(signal.activity),
        # Mapped enums.
        activity_id=defaults.activity_id(signal.activity),
        severity_id=defaults.severity_id(signal.severity),
        status_id=defaults.status_id(signal.status),
        confidence_id=(
            defaults.confidence_id(signal.confidence) if signal.confidence is not None else None
        ),
        risk_level_id=(
            defaults.risk_level_id(signal.risk_level) if signal.risk_level is not None else None
        ),
        # House defaults.
        metadata=defaults.default_metadata(resolved_product),
        # Payload.
        time=event_time,
        message=signal.message,
        finding_info=finding_info,
        observables=ocsf_observables,
        confidence_score=signal.confidence_score,
        risk_score=signal.risk_score,
        count=signal.count,
    )


# --------------------------------------------------------------------------- #
# Multi-class builders.
#
# Each builder below produces one OCSF class other than Detection Finding. They
# share ``_core_fields`` for the identity + house-default block every OCSF event
# carries (class/category uids and names, type_uid, activity_id, severity_id,
# metadata, time, and observables), then add their class-specific required
# objects. All follow the same keyword shape as ``build_detection_finding``
# (``severity``, ``message``, ``time_ms``, ``product``, ``clock``) and return the
# typed model instance; call :func:`ocsf_emitter.validate.validate` (or ``emit``)
# for the full pre-flight check.
# --------------------------------------------------------------------------- #
def _core_fields(
    ocsf_class: OcsfClass,
    *,
    activity_id_value: int,
    severity: Severity,
    message: str | None,
    time_ms: int | None,
    observables: Sequence[Observable] | None,
    product: _m.Product | None,
    clock: Callable[[], int],
) -> dict[str, object]:
    """Build the identity + house-default field block shared by every class.

    Returns a kwargs dict the per-class builders splat into their model. Resolves
    the product (raising if none is configured), stamps the class identity from
    the registry, and maps severity + observables. ``type_uid``/``activity_id``/
    ``class_uid``/``category_uid`` are plain ints -- Pydantic coerces them into
    the target model's per-class enum fields.
    """
    resolved_product = product if product is not None else defaults.default_product()
    if resolved_product is None:
        raise OcsfEmitterError(
            "No product configured. Call ocsf_emitter.configure_product(name=..., "
            "vendor_name=...) once at startup, or pass product= to the builder."
        )

    class_uid, category_uid, class_name, category_name = defaults.class_identity(ocsf_class)
    ocsf_observables = [build_observable(o) for o in (observables or [])] or None

    return {
        "class_uid": class_uid,
        "category_uid": category_uid,
        "class_name": class_name,
        "category_name": category_name,
        "type_uid": defaults.type_uid_for(ocsf_class, activity_id_value),
        "activity_id": activity_id_value,
        "severity_id": defaults.severity_id(severity),
        "metadata": defaults.default_metadata(resolved_product),
        "time": time_ms if time_ms is not None else clock(),
        "message": message,
        "observables": ocsf_observables,
    }


def build_authentication(
    *,
    user: UserRef,
    severity: Severity,
    activity: AuthAction = AuthAction.LOGON,
    message: str | None = None,
    service_name: str | None = None,
    dst_endpoint: EndpointRef | None = None,
    is_mfa: bool | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.Authentication:
    """Build an OCSF Authentication (3002) event.

    OCSF requires ``user`` and at least one of ``service``/``dst_endpoint``; a
    default ``service`` is synthesized from ``service_name`` (or "unknown") when
    neither is supplied so the constraint always holds.
    """
    core = _core_fields(
        OcsfClass.AUTHENTICATION,
        activity_id_value=int(activity),
        severity=severity,
        message=message,
        time_ms=time_ms,
        observables=observables,
        product=product,
        clock=clock,
    )
    service = None
    endpoint = build_endpoint(dst_endpoint) if dst_endpoint is not None else None
    if endpoint is None:
        service = _m.Service(name=service_name if service_name is not None else "unknown")
    return _m.Authentication(
        **core,
        user=build_user(user),
        service=service,
        dst_endpoint=endpoint,
        is_mfa=is_mfa,
    )


def build_account_change(
    *,
    user: UserRef,
    severity: Severity,
    activity: AccountChangeAction = AccountChangeAction.CREATE,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.AccountChange:
    """Build an OCSF Account Change (3001) event. Requires ``user``."""
    core = _core_fields(
        OcsfClass.ACCOUNT_CHANGE,
        activity_id_value=int(activity),
        severity=severity,
        message=message,
        time_ms=time_ms,
        observables=observables,
        product=product,
        clock=clock,
    )
    return _m.AccountChange(**core, user=build_user(user))


def build_patch_state(
    *,
    device: DeviceRef,
    severity: Severity,
    activity: PatchStateAction = PatchStateAction.LOG,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.PatchState:
    """Build an OCSF Operating System Patch State (5004) event.

    Requires ``device``; OCSF also constrains "at least one of os.sp_name /
    os.sp_ver / os.version", so populate one of the ``os_*`` fields on the
    :class:`DeviceRef`.
    """
    core = _core_fields(
        OcsfClass.PATCH_STATE,
        activity_id_value=int(activity),
        severity=severity,
        message=message,
        time_ms=time_ms,
        observables=observables,
        product=product,
        clock=clock,
    )
    return _m.PatchState(**core, device=build_device(device))


def build_api_activity(
    *,
    api: ApiCall,
    severity: Severity,
    activity: ApiAction = ApiAction.READ,
    src_endpoint: EndpointRef | None = None,
    actor_user: UserRef | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.ApiActivity:
    """Build an OCSF API Activity (6003) event.

    Requires ``api``, ``actor``, and ``src_endpoint`` -- an empty
    ``src_endpoint``/``actor`` is synthesized when not supplied so the OCSF base
    requirements hold; pass ``actor_user`` / ``src_endpoint`` to populate them.
    """
    core = _core_fields(
        OcsfClass.API_ACTIVITY,
        activity_id_value=int(activity),
        severity=severity,
        message=message,
        time_ms=time_ms,
        observables=observables,
        product=product,
        clock=clock,
    )
    actor = _m.Actor(user=build_user(actor_user)) if actor_user is not None else _m.Actor()
    endpoint = build_endpoint(src_endpoint) if src_endpoint is not None else _m.NetworkEndpoint()
    return _m.ApiActivity(**core, api=build_api(api), actor=actor, src_endpoint=endpoint)


def build_web_resources_activity(
    *,
    web_resources: Sequence[WebResourceRef],
    severity: Severity,
    activity: WebResourceAction = WebResourceAction.READ,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.WebResourcesActivity:
    """Build an OCSF Web Resources Activity (6001) event.

    Requires ``web_resources`` (a non-empty list).
    """
    core = _core_fields(
        OcsfClass.WEB_RESOURCES_ACTIVITY,
        activity_id_value=int(activity),
        severity=severity,
        message=message,
        time_ms=time_ms,
        observables=observables,
        product=product,
        clock=clock,
    )
    return _m.WebResourcesActivity(
        **core,
        web_resources=[build_web_resource(r) for r in web_resources],
    )


def build_file_hosting(
    *,
    file: FileRef,
    severity: Severity,
    activity: FileHostingAction = FileHostingAction.SHARE,
    src_endpoint: EndpointRef | None = None,
    actor_user: UserRef | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.FileHosting:
    """Build an OCSF File Hosting Activity (6006) event.

    Requires ``file``, ``actor``, and ``src_endpoint`` -- an empty
    ``actor``/``src_endpoint`` is synthesized when not supplied so the OCSF base
    requirements hold; pass ``actor_user`` / ``src_endpoint`` to populate them.
    """
    core = _core_fields(
        OcsfClass.FILE_HOSTING,
        activity_id_value=int(activity),
        severity=severity,
        message=message,
        time_ms=time_ms,
        observables=observables,
        product=product,
        clock=clock,
    )
    actor = _m.Actor(user=build_user(actor_user)) if actor_user is not None else _m.Actor()
    endpoint = build_endpoint(src_endpoint) if src_endpoint is not None else _m.NetworkEndpoint()
    return _m.FileHosting(**core, file=build_file(file), actor=actor, src_endpoint=endpoint)


def build_compliance_finding(
    *,
    title: str,
    compliance: ComplianceRef,
    severity: Severity,
    activity: Activity = Activity.CREATE,
    uid: str | None = None,
    message: str | None = None,
    description: str | None = None,
    observables: Sequence[Observable] | None = None,
    data_sources: Sequence[str] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
    uid_factory: Callable[[], str] = _new_uid,
) -> _m.ComplianceFinding:
    """Build an OCSF Compliance Finding (2003) event.

    Requires ``compliance`` (with at least one standard) and ``finding_info``.
    Shares the Findings ``Activity`` vocabulary (Create/Update/Close).
    """
    core = _core_fields(
        OcsfClass.COMPLIANCE_FINDING,
        activity_id_value=defaults.activity_id_int(activity),
        severity=severity,
        message=message,
        time_ms=time_ms,
        observables=observables,
        product=product,
        clock=clock,
    )
    finding_info = _m.FindingInfo(
        uid=uid if uid is not None else uid_factory(),
        title=title,
        desc=description,
        data_sources=list(data_sources or []) or None,
    )
    return _m.ComplianceFinding(
        **core,
        finding_info=finding_info,
        compliance=build_compliance(compliance),
    )
