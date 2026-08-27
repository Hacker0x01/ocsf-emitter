"""Map our domain signals onto OCSF event models (one typed builder per class).

Each ``build_*`` returns a typed, already-valid model instance. All OCSF-specific
knowledge (field names, ``*_id`` integers, defaults) is confined to this module,
``defaults``, and the generated ``_catalog`` (per-class activity enums).
"""

from __future__ import annotations

import time as _time
import uuid
from collections.abc import Callable, Sequence

from . import _models as _m
from . import defaults
from ._catalog import (
    AccountChangeAction,
    AirborneBroadcastActivityAction,
    ApiActivityAction,
    ApplicationErrorAction,
    ApplicationLifecycleAction,
    ApplicationSecurityPostureFindingAction,
    AuthenticationAction,
    AuthorizeSessionAction,
    CloudResourcesInventoryInfoAction,
    DataSecurityFindingAction,
    DatastoreActivityAction,
    DeviceConfigStateChangeAction,
    DhcpActivityAction,
    DnsActivityAction,
    DroneFlightsActivityAction,
    EmailActivityAction,
    EntityManagementAction,
    EventLogActvityAction,
    EvidenceInfoAction,
    FileActivityAction,
    FileHostingAction,
    FileRemediationActivityAction,
    FtpActivityAction,
    GroupManagementAction,
    HttpActivityAction,
    IncidentFindingAction,
    InventoryInfoAction,
    KernelActivityAction,
    KernelExtensionActivityAction,
    MemoryActivityAction,
    ModuleActivityAction,
    NetworkActivityAction,
    NetworkRemediationActivityAction,
    NtpActivityAction,
    OsintInventoryInfoAction,
    PatchStateAction,
    ProcessActivityAction,
    ProcessRemediationActivityAction,
    RdpActivityAction,
    RemediationActivityAction,
    ScanActivityAction,
    ScheduledJobActivityAction,
    ScriptActivityAction,
    SmbActivityAction,
    SoftwareInfoAction,
    SshActivityAction,
    TunnelActivityAction,
    UserAccessAction,
    UserInventoryAction,
    VulnerabilityFindingAction,
    WebResourcesActivityAction,
)
from .defaults import (
    Activity,
    Confidence,
    OcsfClass,
    RiskLevel,
    Severity,
    Status,
)
from .domain import (
    ApiCall,
    ComplianceRef,
    ConnectionInfoRef,
    DetectionSignal,
    DeviceRef,
    EmailRef,
    EndpointRef,
    FileRef,
    GroupRef,
    JobRef,
    KernelDriverRef,
    KernelRef,
    ManagedEntityRef,
    MitreAttack,
    ModuleRef,
    Observable,
    ObservableType,
    OsintRef,
    ProcessRef,
    QueryEvidenceRef,
    ScanRef,
    ScriptRef,
    UasRef,
    UserRef,
    VulnerabilityRef,
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


def build_process(process: ProcessRef) -> _m.Process:
    """Map a domain ProcessRef to an OCSF process object."""
    return _m.Process(
        name=process.name, pid=process.pid, cmd_line=process.cmd_line, uid=process.uid
    )


def build_email(email: EmailRef) -> _m.Email:
    """Map a domain EmailRef to an OCSF email object (``from`` is an aliased field)."""
    data: dict[str, object] = {}
    if email.from_addr is not None:
        data["from"] = email.from_addr
    if email.to is not None:
        data["to"] = list(email.to)
    if email.subject is not None:
        data["subject"] = email.subject
    if email.uid is not None:
        data["uid"] = email.uid
    return _m.Email.model_validate(data)


def build_vulnerability(vuln: VulnerabilityRef) -> _m.Vulnerability:
    """Map a domain VulnerabilityRef to an OCSF vulnerability object."""
    cve = _m.Cve(uid=vuln.cve_uid) if vuln.cve_uid is not None else None
    return _m.Vulnerability(title=vuln.title, severity=vuln.severity, desc=vuln.desc, cve=cve)


def build_connection_info(conn: ConnectionInfoRef) -> _m.NetworkConnectionInfo:
    """Map a domain ConnectionInfoRef to an OCSF network_connection_info object."""
    return _m.NetworkConnectionInfo(
        direction_id=conn.direction_id, protocol_name=conn.protocol_name, uid=conn.uid
    )


def build_group(group: GroupRef) -> _m.Group:
    """Map a domain GroupRef to an OCSF group object."""
    return _m.Group(name=group.name, uid=group.uid, type=group.type)


def build_job(job: JobRef) -> _m.Job:
    """Map a domain JobRef to an OCSF job object (requires name + file)."""
    return _m.Job(name=job.name, file=build_file(job.file), cmd_line=job.cmd_line, desc=job.desc)


def build_kernel(kernel: KernelRef) -> _m.Kernel:
    """Map a domain KernelRef to an OCSF kernel object (requires name + type_id)."""
    return _m.Kernel(name=kernel.name, type_id=kernel.type_id, path=kernel.path)


def build_module(module: ModuleRef) -> _m.Module:
    """Map a domain ModuleRef to an OCSF module object (requires load_type_id)."""
    file = build_file(module.file) if module.file is not None else None
    return _m.Module(load_type_id=module.load_type_id, base_address=module.base_address, file=file)


def build_script(script: ScriptRef) -> _m.Script:
    """Map a domain ScriptRef to an OCSF script object (requires script_content + type_id)."""
    return _m.Script(
        type_id=script.type_id,
        script_content=_m.LongString(value=script.script_content),
        name=script.name,
    )


def build_scan(scan: ScanRef) -> _m.Scan:
    """Map a domain ScanRef to an OCSF scan object (requires type_id)."""
    return _m.Scan(type_id=scan.type_id, name=scan.name, uid=scan.uid)


def build_osint(osint: OsintRef) -> _m.Osint:
    """Map a domain OsintRef to an OCSF osint object (requires type_id + value)."""
    return _m.Osint(type_id=osint.type_id, value=osint.value, desc=osint.desc)


def build_managed_entity(entity: ManagedEntityRef) -> _m.ManagedEntity:
    """Map a domain ManagedEntityRef to an OCSF managed_entity object."""
    return _m.ManagedEntity(
        name=entity.name, uid=entity.uid, type=entity.type, type_id=entity.type_id
    )


def build_query_evidence(query: QueryEvidenceRef) -> _m.QueryEvidence:
    """Map a domain QueryEvidenceRef to an OCSF query_evidence object (requires query_type_id)."""
    return _m.QueryEvidence(query_type_id=query.query_type_id, query_type=query.query_type)


def build_kernel_driver(driver: KernelDriverRef) -> _m.KernelDriver:
    """Map a domain KernelDriverRef to an OCSF kernel_driver object (requires file)."""
    return _m.KernelDriver(file=build_file(driver.file))


def build_uas(uas: UasRef) -> _m.UnmannedAerialSystem:
    """Map a domain UasRef to an OCSF unmanned_aerial_system object."""
    return _m.UnmannedAerialSystem(
        uid=uas.uid, name=uas.name, model=uas.model, serial_number=uas.serial_number
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
    activity: AuthenticationAction = AuthenticationAction.LOGON,
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
    activity: ApiActivityAction = ApiActivityAction.READ,
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
    activity: WebResourcesActivityAction = WebResourcesActivityAction.READ,
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


# --------------------------------------------------------------------------- #
# Full class coverage.
#
# The remaining OCSF classes, one typed builder each. They share ``_core_fields``
# and follow the same keyword shape (``severity``, ``activity``, ``message``,
# ``time_ms``, ``observables``, ``product``, ``clock``); ``activity`` is required
# (each class has a distinct vocabulary, so there's no safe default). Required
# OCSF objects with no required sub-fields (actor, device, endpoint) are
# synthesized empty when the caller passes nothing.
# --------------------------------------------------------------------------- #
def _actor(user: UserRef | None) -> _m.Actor:
    return _m.Actor(user=build_user(user)) if user is not None else _m.Actor()


def _device_or_empty(device: DeviceRef | None) -> _m.Device:
    return build_device(device) if device is not None else _m.Device(type_id=0)


def _endpoint_or_empty(endpoint: EndpointRef | None) -> _m.NetworkEndpoint:
    return build_endpoint(endpoint) if endpoint is not None else _m.NetworkEndpoint()


def _core(
    ocsf_class: OcsfClass,
    activity: int,
    severity: Severity,
    message: str | None,
    observables: Sequence[Observable] | None,
    time_ms: int | None,
    product: _m.Product | None,
    clock: Callable[[], int],
) -> dict[str, object]:
    """Thin positional wrapper over ``_core_fields`` to keep the builders terse."""
    return _core_fields(
        ocsf_class,
        activity_id_value=int(activity),
        severity=severity,
        message=message,
        time_ms=time_ms,
        observables=observables,
        product=product,
        clock=clock,
    )


# --- System Activity [1] ---------------------------------------------------- #
def build_file_activity(
    *,
    file: FileRef,
    severity: Severity,
    activity: FileActivityAction,
    device: DeviceRef | None = None,
    actor_user: UserRef | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.FileActivity:
    """Build an OCSF File System Activity (1001) event."""
    core = _core(
        OcsfClass.FILE_ACTIVITY, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.FileActivity(
        **core, actor=_actor(actor_user), device=_device_or_empty(device), file=build_file(file)
    )


def build_kernel_extension_activity(
    *,
    driver: KernelDriverRef,
    severity: Severity,
    activity: KernelExtensionActivityAction,
    device: DeviceRef | None = None,
    actor_user: UserRef | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.KernelExtensionActivity:
    """Build an OCSF Kernel Extension Activity (1002) event."""
    core = _core(
        OcsfClass.KERNEL_EXTENSION_ACTIVITY,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.KernelExtensionActivity(
        **core,
        actor=_actor(actor_user),
        device=_device_or_empty(device),
        driver=build_kernel_driver(driver),
    )


def build_kernel_activity(
    *,
    kernel: KernelRef,
    severity: Severity,
    activity: KernelActivityAction,
    device: DeviceRef | None = None,
    actor_user: UserRef | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.KernelActivity:
    """Build an OCSF Kernel Activity (1003) event."""
    core = _core(
        OcsfClass.KERNEL_ACTIVITY, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.KernelActivity(
        **core,
        actor=_actor(actor_user),
        device=_device_or_empty(device),
        kernel=build_kernel(kernel),
    )


def build_memory_activity(
    *,
    process: ProcessRef,
    severity: Severity,
    activity: MemoryActivityAction,
    device: DeviceRef | None = None,
    actor_user: UserRef | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.MemoryActivity:
    """Build an OCSF Memory Activity (1004) event."""
    core = _core(
        OcsfClass.MEMORY_ACTIVITY, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.MemoryActivity(
        **core,
        actor=_actor(actor_user),
        device=_device_or_empty(device),
        process=build_process(process),
    )


def build_module_activity(
    *,
    module: ModuleRef,
    severity: Severity,
    activity: ModuleActivityAction,
    device: DeviceRef | None = None,
    actor_user: UserRef | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.ModuleActivity:
    """Build an OCSF Module Activity (1005) event."""
    core = _core(
        OcsfClass.MODULE_ACTIVITY, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.ModuleActivity(
        **core,
        actor=_actor(actor_user),
        device=_device_or_empty(device),
        module=build_module(module),
    )


def build_scheduled_job_activity(
    *,
    job: JobRef,
    severity: Severity,
    activity: ScheduledJobActivityAction,
    device: DeviceRef | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.ScheduledJobActivity:
    """Build an OCSF Scheduled Job Activity (1006) event."""
    core = _core(
        OcsfClass.SCHEDULED_JOB_ACTIVITY,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.ScheduledJobActivity(**core, device=_device_or_empty(device), job=build_job(job))


def build_process_activity(
    *,
    process: ProcessRef,
    severity: Severity,
    activity: ProcessActivityAction,
    device: DeviceRef | None = None,
    actor_user: UserRef | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.ProcessActivity:
    """Build an OCSF Process Activity (1007) event."""
    core = _core(
        OcsfClass.PROCESS_ACTIVITY,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.ProcessActivity(
        **core,
        actor=_actor(actor_user),
        device=_device_or_empty(device),
        process=build_process(process),
    )


def build_event_log_activity(
    *,
    severity: Severity,
    activity: EventLogActvityAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.EventLogActvity:
    """Build an OCSF Event Log Activity (1008) event."""
    core = _core(
        OcsfClass.EVENT_LOG_ACTVITY,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.EventLogActvity(**core)


def build_script_activity(
    *,
    script: ScriptRef,
    severity: Severity,
    activity: ScriptActivityAction,
    device: DeviceRef | None = None,
    actor_user: UserRef | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.ScriptActivity:
    """Build an OCSF Script Activity (1009) event."""
    core = _core(
        OcsfClass.SCRIPT_ACTIVITY, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.ScriptActivity(
        **core,
        actor=_actor(actor_user),
        device=_device_or_empty(device),
        script=build_script(script),
    )


# --- Findings [2] ----------------------------------------------------------- #
def _finding_info(
    uid: str | None, title: str, description: str | None, uid_factory: Callable[[], str]
) -> _m.FindingInfo:
    return _m.FindingInfo(
        uid=uid if uid is not None else uid_factory(), title=title, desc=description
    )


def build_vulnerability_finding(
    *,
    title: str,
    vulnerabilities: Sequence[VulnerabilityRef],
    severity: Severity,
    activity: VulnerabilityFindingAction,
    uid: str | None = None,
    description: str | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
    uid_factory: Callable[[], str] = _new_uid,
) -> _m.VulnerabilityFinding:
    """Build an OCSF Vulnerability Finding (2002) event."""
    core = _core(
        OcsfClass.VULNERABILITY_FINDING,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.VulnerabilityFinding(
        **core,
        finding_info=_finding_info(uid, title, description, uid_factory),
        vulnerabilities=[build_vulnerability(v) for v in vulnerabilities],
    )


def build_incident_finding(
    *,
    title: str,
    severity: Severity,
    activity: IncidentFindingAction,
    status: Status = Status.NEW,
    uid: str | None = None,
    description: str | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
    uid_factory: Callable[[], str] = _new_uid,
) -> _m.IncidentFinding:
    """Build an OCSF Incident Finding (2005) event (requires a finding_info list + status)."""
    core = _core(
        OcsfClass.INCIDENT_FINDING,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.IncidentFinding(
        **core,
        finding_info_list=[_finding_info(uid, title, description, uid_factory)],
        status_id=int(defaults.status_id(status)),
    )


def build_data_security_finding(
    *,
    title: str,
    severity: Severity,
    activity: DataSecurityFindingAction,
    uid: str | None = None,
    description: str | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
    uid_factory: Callable[[], str] = _new_uid,
) -> _m.DataSecurityFinding:
    """Build an OCSF Data Security Finding (2006) event."""
    core = _core(
        OcsfClass.DATA_SECURITY_FINDING,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.DataSecurityFinding(
        **core, finding_info=_finding_info(uid, title, description, uid_factory)
    )


def build_application_security_posture_finding(
    *,
    title: str,
    severity: Severity,
    activity: ApplicationSecurityPostureFindingAction,
    uid: str | None = None,
    description: str | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
    uid_factory: Callable[[], str] = _new_uid,
) -> _m.ApplicationSecurityPostureFinding:
    """Build an OCSF Application Security Posture Finding (2007) event."""
    core = _core(
        OcsfClass.APPLICATION_SECURITY_POSTURE_FINDING,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.ApplicationSecurityPostureFinding(
        **core, finding_info=_finding_info(uid, title, description, uid_factory)
    )


# --- Identity & Access Management [3] --------------------------------------- #
def build_authorize_session(
    *,
    user: UserRef,
    severity: Severity,
    activity: AuthorizeSessionAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.AuthorizeSession:
    """Build an OCSF Authorize Session (3003) event."""
    core = _core(
        OcsfClass.AUTHORIZE_SESSION,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.AuthorizeSession(**core, user=build_user(user))


def build_entity_management(
    *,
    entity: ManagedEntityRef,
    severity: Severity,
    activity: EntityManagementAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.EntityManagement:
    """Build an OCSF Entity Management (3004) event."""
    core = _core(
        OcsfClass.ENTITY_MANAGEMENT,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.EntityManagement(**core, entity=build_managed_entity(entity))


def build_user_access(
    *,
    user: UserRef,
    privileges: Sequence[str],
    severity: Severity,
    activity: UserAccessAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.UserAccess:
    """Build an OCSF User Access Management (3005) event."""
    core = _core(
        OcsfClass.USER_ACCESS, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.UserAccess(**core, user=build_user(user), privileges=list(privileges))


def build_group_management(
    *,
    group: GroupRef,
    severity: Severity,
    activity: GroupManagementAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.GroupManagement:
    """Build an OCSF Group Management (3006) event."""
    core = _core(
        OcsfClass.GROUP_MANAGEMENT,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.GroupManagement(**core, group=build_group(group))


# --- Network Activity [4] --------------------------------------------------- #
def build_network_activity(
    *,
    severity: Severity,
    activity: NetworkActivityAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.NetworkActivity:
    """Build an OCSF Network Activity (4001) event."""
    return _m.NetworkActivity(
        **_core(
            OcsfClass.NETWORK_ACTIVITY,
            activity,
            severity,
            message,
            observables,
            time_ms,
            product,
            clock,
        )
    )


def build_http_activity(
    *,
    severity: Severity,
    activity: HttpActivityAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.HttpActivity:
    """Build an OCSF HTTP Activity (4002) event."""
    return _m.HttpActivity(
        **_core(
            OcsfClass.HTTP_ACTIVITY,
            activity,
            severity,
            message,
            observables,
            time_ms,
            product,
            clock,
        )
    )


def build_dns_activity(
    *,
    severity: Severity,
    activity: DnsActivityAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.DnsActivity:
    """Build an OCSF DNS Activity (4003) event."""
    return _m.DnsActivity(
        **_core(
            OcsfClass.DNS_ACTIVITY,
            activity,
            severity,
            message,
            observables,
            time_ms,
            product,
            clock,
        )
    )


def build_dhcp_activity(
    *,
    severity: Severity,
    activity: DhcpActivityAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.DhcpActivity:
    """Build an OCSF DHCP Activity (4004) event."""
    return _m.DhcpActivity(
        **_core(
            OcsfClass.DHCP_ACTIVITY,
            activity,
            severity,
            message,
            observables,
            time_ms,
            product,
            clock,
        )
    )


def build_rdp_activity(
    *,
    severity: Severity,
    activity: RdpActivityAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.RdpActivity:
    """Build an OCSF RDP Activity (4005) event."""
    return _m.RdpActivity(
        **_core(
            OcsfClass.RDP_ACTIVITY,
            activity,
            severity,
            message,
            observables,
            time_ms,
            product,
            clock,
        )
    )


def build_smb_activity(
    *,
    severity: Severity,
    activity: SmbActivityAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.SmbActivity:
    """Build an OCSF SMB Activity (4006) event."""
    return _m.SmbActivity(
        **_core(
            OcsfClass.SMB_ACTIVITY,
            activity,
            severity,
            message,
            observables,
            time_ms,
            product,
            clock,
        )
    )


def build_ssh_activity(
    *,
    severity: Severity,
    activity: SshActivityAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.SshActivity:
    """Build an OCSF SSH Activity (4007) event."""
    return _m.SshActivity(
        **_core(
            OcsfClass.SSH_ACTIVITY,
            activity,
            severity,
            message,
            observables,
            time_ms,
            product,
            clock,
        )
    )


def build_ftp_activity(
    *,
    severity: Severity,
    activity: FtpActivityAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.FtpActivity:
    """Build an OCSF FTP Activity (4008) event."""
    return _m.FtpActivity(
        **_core(
            OcsfClass.FTP_ACTIVITY,
            activity,
            severity,
            message,
            observables,
            time_ms,
            product,
            clock,
        )
    )


def build_email_activity(
    *,
    email: EmailRef,
    direction_id: int,
    severity: Severity,
    activity: EmailActivityAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.EmailActivity:
    """Build an OCSF Email Activity (4009) event (requires email + direction_id)."""
    core = _core(
        OcsfClass.EMAIL_ACTIVITY, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.EmailActivity(**core, email=build_email(email), direction_id=direction_id)


def build_ntp_activity(
    *,
    version: str,
    severity: Severity,
    activity: NtpActivityAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.NtpActivity:
    """Build an OCSF NTP Activity (4013) event (requires version)."""
    core = _core(
        OcsfClass.NTP_ACTIVITY, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.NtpActivity(**core, version=version)


def build_tunnel_activity(
    *,
    severity: Severity,
    activity: TunnelActivityAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.TunnelActivity:
    """Build an OCSF Tunnel Activity (4014) event."""
    return _m.TunnelActivity(
        **_core(
            OcsfClass.TUNNEL_ACTIVITY,
            activity,
            severity,
            message,
            observables,
            time_ms,
            product,
            clock,
        )
    )


# --- Discovery [5] ---------------------------------------------------------- #
def build_inventory_info(
    *,
    device: DeviceRef,
    severity: Severity,
    activity: InventoryInfoAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.InventoryInfo:
    """Build an OCSF Device Inventory Info (5001) event."""
    core = _core(
        OcsfClass.INVENTORY_INFO, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.InventoryInfo(**core, device=build_device(device))


def build_user_inventory(
    *,
    user: UserRef,
    severity: Severity,
    activity: UserInventoryAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.UserInventory:
    """Build an OCSF User Inventory Info (5003) event."""
    core = _core(
        OcsfClass.USER_INVENTORY, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.UserInventory(**core, user=build_user(user))


def build_device_config_state_change(
    *,
    device: DeviceRef,
    severity: Severity,
    activity: DeviceConfigStateChangeAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.DeviceConfigStateChange:
    """Build an OCSF Device Config State Change (5019) event."""
    core = _core(
        OcsfClass.DEVICE_CONFIG_STATE_CHANGE,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.DeviceConfigStateChange(**core, device=build_device(device))


def build_software_info(
    *,
    device: DeviceRef,
    severity: Severity,
    activity: SoftwareInfoAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.SoftwareInfo:
    """Build an OCSF Software Inventory Info (5020) event."""
    core = _core(
        OcsfClass.SOFTWARE_INFO, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.SoftwareInfo(**core, device=build_device(device))


def build_osint_inventory_info(
    *,
    osint: Sequence[OsintRef],
    severity: Severity,
    activity: OsintInventoryInfoAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.OsintInventoryInfo:
    """Build an OCSF OSINT Inventory Info (5021) event."""
    core = _core(
        OcsfClass.OSINT_INVENTORY_INFO,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.OsintInventoryInfo(**core, osint=[build_osint(o) for o in osint])


def build_cloud_resources_inventory_info(
    *,
    severity: Severity,
    activity: CloudResourcesInventoryInfoAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.CloudResourcesInventoryInfo:
    """Build an OCSF Cloud Resources Inventory Info (5023) event."""
    return _m.CloudResourcesInventoryInfo(
        **_core(
            OcsfClass.CLOUD_RESOURCES_INVENTORY_INFO,
            activity,
            severity,
            message,
            observables,
            time_ms,
            product,
            clock,
        )
    )


def build_evidence_info(
    *,
    query_evidence: QueryEvidenceRef,
    query_result_id: int,
    severity: Severity,
    activity: EvidenceInfoAction,
    device: DeviceRef | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.EvidenceInfo:
    """Build an OCSF Live Evidence Info (5040) event."""
    core = _core(
        OcsfClass.EVIDENCE_INFO, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.EvidenceInfo(
        **core,
        device=_device_or_empty(device),
        query_evidence=build_query_evidence(query_evidence),
        query_result_id=query_result_id,
    )


# --- Application Activity [6] ----------------------------------------------- #
def build_application_lifecycle(
    *,
    app_name: str,
    severity: Severity,
    activity: ApplicationLifecycleAction,
    app_version: str | None = None,
    app_vendor: str | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.ApplicationLifecycle:
    """Build an OCSF Application Lifecycle (6002) event (``app`` is an OCSF product)."""
    core = _core(
        OcsfClass.APPLICATION_LIFECYCLE,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    app = _m.Product(name=app_name, version=app_version, vendor_name=app_vendor)
    return _m.ApplicationLifecycle(**core, app=app)


def build_datastore_activity(
    *,
    severity: Severity,
    activity: DatastoreActivityAction,
    src_endpoint: EndpointRef | None = None,
    actor_user: UserRef | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.DatastoreActivity:
    """Build an OCSF Datastore Activity (6005) event."""
    core = _core(
        OcsfClass.DATASTORE_ACTIVITY,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.DatastoreActivity(
        **core, actor=_actor(actor_user), src_endpoint=_endpoint_or_empty(src_endpoint)
    )


def build_scan_activity(
    *,
    scan: ScanRef,
    severity: Severity,
    activity: ScanActivityAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.ScanActivity:
    """Build an OCSF Scan Activity (6007) event."""
    core = _core(
        OcsfClass.SCAN_ACTIVITY, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.ScanActivity(**core, scan=build_scan(scan))


def build_application_error(
    *,
    severity: Severity,
    activity: ApplicationErrorAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.ApplicationError:
    """Build an OCSF Application Error (6008) event."""
    return _m.ApplicationError(
        **_core(
            OcsfClass.APPLICATION_ERROR,
            activity,
            severity,
            message,
            observables,
            time_ms,
            product,
            clock,
        )
    )


# --- Remediation [7] -------------------------------------------------------- #
def build_remediation_activity(
    *,
    command_uid: str,
    severity: Severity,
    activity: RemediationActivityAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.RemediationActivity:
    """Build an OCSF Remediation Activity (7001) event (requires command_uid)."""
    core = _core(
        OcsfClass.REMEDIATION_ACTIVITY,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.RemediationActivity(**core, command_uid=command_uid)


def build_file_remediation_activity(
    *,
    command_uid: str,
    file: FileRef,
    severity: Severity,
    activity: FileRemediationActivityAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.FileRemediationActivity:
    """Build an OCSF File Remediation Activity (7002) event."""
    core = _core(
        OcsfClass.FILE_REMEDIATION_ACTIVITY,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.FileRemediationActivity(**core, command_uid=command_uid, file=build_file(file))


def build_process_remediation_activity(
    *,
    command_uid: str,
    process: ProcessRef,
    severity: Severity,
    activity: ProcessRemediationActivityAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.ProcessRemediationActivity:
    """Build an OCSF Process Remediation Activity (7003) event."""
    core = _core(
        OcsfClass.PROCESS_REMEDIATION_ACTIVITY,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.ProcessRemediationActivity(
        **core, command_uid=command_uid, process=build_process(process)
    )


def build_network_remediation_activity(
    *,
    command_uid: str,
    connection_info: ConnectionInfoRef,
    severity: Severity,
    activity: NetworkRemediationActivityAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.NetworkRemediationActivity:
    """Build an OCSF Network Remediation Activity (7004) event."""
    core = _core(
        OcsfClass.NETWORK_REMEDIATION_ACTIVITY,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.NetworkRemediationActivity(
        **core, command_uid=command_uid, connection_info=build_connection_info(connection_info)
    )


# --- Unmanned Systems [8] --------------------------------------------------- #
def build_drone_flights_activity(
    *,
    uas: UasRef,
    operator: UserRef,
    severity: Severity,
    activity: DroneFlightsActivityAction,
    dst_endpoint: EndpointRef | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.DroneFlightsActivity:
    """Build an OCSF Drone Flights Activity (8001) event."""
    core = _core(
        OcsfClass.DRONE_FLIGHTS_ACTIVITY,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.DroneFlightsActivity(
        **core,
        unmanned_aerial_system=build_uas(uas),
        unmanned_system_operator=build_user(operator),
        dst_endpoint=_endpoint_or_empty(dst_endpoint),
    )


def build_airborne_broadcast_activity(
    *,
    uas: UasRef,
    operator: UserRef,
    severity: Severity,
    activity: AirborneBroadcastActivityAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.AirborneBroadcastActivity:
    """Build an OCSF Airborne Broadcast Activity (8002) event."""
    core = _core(
        OcsfClass.AIRBORNE_BROADCAST_ACTIVITY,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.AirborneBroadcastActivity(
        **core,
        unmanned_aerial_system=build_uas(uas),
        unmanned_system_operator=build_user(operator),
    )
