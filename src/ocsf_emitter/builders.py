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
    DatabaseRef,
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
    ResourceDetailsRef,
    ScanRef,
    ScriptRef,
    UasRef,
    UserRef,
    VulnerabilityRef,
    WebResourceRef,
)
from .errors import OcsfEmitterError


def _at_least_one(constraint: str, **fields: object) -> None:
    """Raise if none of ``fields`` is set (OCSF ``at_least_one`` constraint)."""
    if not any(v not in (None, [], "") for v in fields.values()):
        raise OcsfEmitterError(
            f"OCSF requires at least one of {constraint}: pass one of {sorted(fields)}."
        )


def _just_one(constraint: str, **fields: object) -> None:
    """Raise unless exactly one of ``fields`` is set (OCSF ``just_one`` constraint)."""
    n = sum(1 for v in fields.values() if v not in (None, [], ""))
    if n != 1:
        raise OcsfEmitterError(
            f"OCSF requires exactly one of {constraint}: pass one of {sorted(fields)} (got {n})."
        )


# Our observable kinds -> OCSF observable type_id (schema 1.5.0, full set). The
# int is passed straight through; Pydantic coerces it into the observable model's
# type_id enum. NOTE: these ids shifted between OCSF versions (e.g. Process Name
# was 20 in 1.1.0, is 9 in 1.5.0; 20 is now Endpoint) -- keep in sync with the
# schema (tests/test_observables.py guards this).
_OBSERVABLE_TYPE_TO_ID: dict[ObservableType, int] = {
    ObservableType.UNKNOWN: 0,
    ObservableType.HOSTNAME: 1,
    ObservableType.IP_ADDRESS: 2,
    ObservableType.MAC_ADDRESS: 3,
    ObservableType.USER_NAME: 4,
    ObservableType.EMAIL_ADDRESS: 5,
    ObservableType.URL: 6,
    ObservableType.FILE_NAME: 7,
    ObservableType.FILE_HASH: 8,
    ObservableType.PROCESS_NAME: 9,
    ObservableType.RESOURCE_UID: 10,
    ObservableType.PORT: 11,
    ObservableType.SUBNET: 12,
    ObservableType.COMMAND_LINE: 13,
    ObservableType.COUNTRY: 14,
    ObservableType.PROCESS_ID: 15,
    ObservableType.HTTP_USER_AGENT: 16,
    ObservableType.CWE_UID: 17,
    ObservableType.CVE_UID: 18,
    ObservableType.USER_CREDENTIAL_ID: 19,
    ObservableType.ENDPOINT: 20,
    ObservableType.USER: 21,
    ObservableType.EMAIL: 22,
    ObservableType.URL_OBJECT: 23,
    ObservableType.FILE: 24,
    ObservableType.PROCESS: 25,
    ObservableType.GEO_LOCATION: 26,
    ObservableType.CONTAINER: 27,
    ObservableType.REGISTRY_KEY: 28,
    ObservableType.REGISTRY_VALUE: 29,
    ObservableType.FINGERPRINT: 30,
    ObservableType.USER_UID: 31,
    ObservableType.GROUP_NAME: 32,
    ObservableType.GROUP_UID: 33,
    ObservableType.ACCOUNT_NAME: 34,
    ObservableType.ACCOUNT_UID: 35,
    ObservableType.SCRIPT_CONTENT: 36,
    ObservableType.SERIAL_NUMBER: 37,
    ObservableType.RESOURCE_DETAILS_NAME: 38,
    ObservableType.PROCESS_ENTITY_UID: 39,
    ObservableType.EMAIL_SUBJECT: 40,
    ObservableType.EMAIL_UID: 41,
    ObservableType.MESSAGE_UID: 42,
    ObservableType.REGISTRY_VALUE_NAME: 43,
    ObservableType.ADVISORY_UID: 44,
    ObservableType.FILE_PATH: 45,
    ObservableType.REGISTRY_KEY_PATH: 46,
    ObservableType.OTHER: 99,
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
    """Map a domain UserRef to an OCSF user object (requires name or uid)."""
    _at_least_one("user.name / user.uid", name=user.name, uid=user.uid)
    return _m.User(
        name=user.name,
        uid=user.uid,
        email_addr=user.email,
        domain=user.domain,
        full_name=user.full_name,
    )


def build_device(device: DeviceRef) -> _m.Device:
    """Map a domain DeviceRef to an OCSF device object (requires hostname or uid)."""
    _at_least_one("device.hostname / device.uid", hostname=device.hostname, uid=device.uid)
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
    """Map a domain WebResourceRef to an OCSF web_resource object (requires name or uid)."""
    _at_least_one("web_resource.name / .uid", name=resource.name, uid=resource.uid)
    return _m.WebResource(
        name=resource.name,
        type=resource.type,
        uid=resource.uid,
        url_string=resource.url_string,
    )


def build_endpoint(endpoint: EndpointRef) -> _m.NetworkEndpoint:
    """Map a domain EndpointRef to an OCSF network_endpoint (requires ip/hostname/uid)."""
    _at_least_one(
        "network_endpoint.ip / .hostname / .uid",
        ip=endpoint.ip,
        hostname=endpoint.hostname,
        uid=endpoint.uid,
    )
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
    """Map a domain ProcessRef to an OCSF process object (requires pid or uid)."""
    _at_least_one("process.pid / process.uid", pid=process.pid, uid=process.uid)
    return _m.Process(
        name=process.name, pid=process.pid, cmd_line=process.cmd_line, uid=process.uid
    )


def build_email(email: EmailRef) -> _m.Email:
    """Map a domain EmailRef to an OCSF email object (requires from or to; ``from`` is aliased)."""
    _at_least_one("email.from / email.to", from_addr=email.from_addr, to=email.to)
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
    """Map a domain VulnerabilityRef to an OCSF vulnerability (just one of cve/cwe/advisory)."""
    _just_one(
        "vulnerability.cve / .cwe / .advisory",
        cve_uid=vuln.cve_uid,
        cwe_uid=vuln.cwe_uid,
        advisory_uid=vuln.advisory_uid,
    )
    cve = _m.Cve(uid=vuln.cve_uid) if vuln.cve_uid is not None else None
    cwe = _m.Cwe(uid=vuln.cwe_uid) if vuln.cwe_uid is not None else None
    advisory = _m.Advisory(uid=vuln.advisory_uid) if vuln.advisory_uid is not None else None
    return _m.Vulnerability(
        title=vuln.title,
        severity=vuln.severity,
        desc=vuln.desc,
        cve=cve,
        cwe=cwe,
        advisory=advisory,
    )


def build_connection_info(conn: ConnectionInfoRef) -> _m.NetworkConnectionInfo:
    """Map a domain ConnectionInfoRef to an OCSF network_connection_info object."""
    return _m.NetworkConnectionInfo(
        direction_id=conn.direction_id, protocol_name=conn.protocol_name, uid=conn.uid
    )


def build_group(group: GroupRef) -> _m.Group:
    """Map a domain GroupRef to an OCSF group object (requires name or uid)."""
    _at_least_one("group.name / group.uid", name=group.name, uid=group.uid)
    return _m.Group(name=group.name, uid=group.uid, type=group.type)


def build_database(database: DatabaseRef) -> _m.Database:
    """Map a domain DatabaseRef to an OCSF database object (requires name or uid)."""
    _at_least_one("database.name / database.uid", name=database.name, uid=database.uid)
    return _m.Database(name=database.name, uid=database.uid, type_id=database.type_id)


def build_resource_details(resource: ResourceDetailsRef) -> _m.ResourceDetails:
    """Map a domain ResourceDetailsRef to an OCSF resource_details (requires name or uid)."""
    _at_least_one("resource_details.name / .uid", name=resource.name, uid=resource.uid)
    return _m.ResourceDetails(name=resource.name, uid=resource.uid, type=resource.type)


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
    """Map a domain ScanRef to an OCSF scan object (requires type_id, and name or uid)."""
    _at_least_one("scan.name / scan.uid", name=scan.name, uid=scan.uid)
    return _m.Scan(type_id=scan.type_id, name=scan.name, uid=scan.uid)


def build_osint(osint: OsintRef) -> _m.Osint:
    """Map a domain OsintRef to an OCSF osint object (requires type_id + value)."""
    return _m.Osint(type_id=osint.type_id, value=osint.value, desc=osint.desc)


def build_managed_entity(entity: ManagedEntityRef) -> _m.ManagedEntity:
    """Map a domain ManagedEntityRef to an OCSF managed_entity object (requires name or uid)."""
    _at_least_one("managed_entity.name / .uid", name=entity.name, uid=entity.uid)
    return _m.ManagedEntity(
        name=entity.name, uid=entity.uid, type=entity.type, type_id=entity.type_id
    )


def build_query_evidence(query: QueryEvidenceRef) -> _m.QueryEvidence:
    """Map a domain QueryEvidenceRef to an OCSF query_evidence (just one queried object)."""
    _just_one("query_evidence.user / .process", user=query.user, process=query.process)
    return _m.QueryEvidence(
        query_type_id=query.query_type_id,
        query_type=query.query_type,
        user=build_user(query.user) if query.user is not None else None,
        process=build_process(query.process) if query.process is not None else None,
    )


def build_kernel_driver(driver: KernelDriverRef) -> _m.KernelDriver:
    """Map a domain KernelDriverRef to an OCSF kernel_driver object (requires file)."""
    return _m.KernelDriver(file=build_file(driver.file))


def build_uas(uas: UasRef) -> _m.UnmannedAerialSystem:
    """Map a domain UasRef to an OCSF unmanned_aerial_system (requires name/serial_number/uid)."""
    _at_least_one(
        "unmanned_aerial_system.name / .serial_number / .uid",
        name=uas.name,
        serial_number=uas.serial_number,
        uid=uas.uid,
    )
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
    src_endpoint: EndpointRef,
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
    return _m.ApiActivity(
        **core,
        api=build_api(api),
        actor=_actor(actor_user, product),
        src_endpoint=build_endpoint(src_endpoint),
    )


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
    src_endpoint: EndpointRef,
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
    return _m.FileHosting(
        **core,
        file=build_file(file),
        actor=_actor(actor_user, product),
        src_endpoint=build_endpoint(src_endpoint),
    )


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
# (each class has a distinct vocabulary, so there's no safe default). Objects with
# their own OCSF constraints (device, endpoint) are required inputs; ``actor`` is
# satisfied via the caller's ``actor_user`` or, failing that, the emitting
# product's name (OCSF ``actor.at_least_one`` accepts ``app_name``).
# --------------------------------------------------------------------------- #
def _actor(user: UserRef | None, product: _m.Product | None) -> _m.Actor:
    if user is not None:
        return _m.Actor(user=build_user(user))
    prod = product if product is not None else defaults.default_product()
    return _m.Actor(app_name=prod.name if prod is not None else "ocsf-emitter")


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
    device: DeviceRef,
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
        **core,
        actor=_actor(actor_user, product),
        device=build_device(device),
        file=build_file(file),
    )


def build_kernel_extension_activity(
    *,
    driver: KernelDriverRef,
    severity: Severity,
    activity: KernelExtensionActivityAction,
    device: DeviceRef,
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
        actor=_actor(actor_user, product),
        device=build_device(device),
        driver=build_kernel_driver(driver),
    )


def build_kernel_activity(
    *,
    kernel: KernelRef,
    severity: Severity,
    activity: KernelActivityAction,
    device: DeviceRef,
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
        actor=_actor(actor_user, product),
        device=build_device(device),
        kernel=build_kernel(kernel),
    )


def build_memory_activity(
    *,
    process: ProcessRef,
    severity: Severity,
    activity: MemoryActivityAction,
    device: DeviceRef,
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
        actor=_actor(actor_user, product),
        device=build_device(device),
        process=build_process(process),
    )


def build_module_activity(
    *,
    module: ModuleRef,
    severity: Severity,
    activity: ModuleActivityAction,
    device: DeviceRef,
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
        actor=_actor(actor_user, product),
        device=build_device(device),
        module=build_module(module),
    )


def build_scheduled_job_activity(
    *,
    job: JobRef,
    severity: Severity,
    activity: ScheduledJobActivityAction,
    device: DeviceRef,
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
    return _m.ScheduledJobActivity(**core, device=build_device(device), job=build_job(job))


def build_process_activity(
    *,
    process: ProcessRef,
    severity: Severity,
    activity: ProcessActivityAction,
    device: DeviceRef,
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
        actor=_actor(actor_user, product),
        device=build_device(device),
        process=build_process(process),
    )


def build_event_log_activity(
    *,
    log_name: str,
    severity: Severity,
    activity: EventLogActvityAction,
    log_provider: str | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.EventLogActvity:
    """Build an OCSF Event Log Activity (1008) event (requires a log identifier)."""
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
    return _m.EventLogActvity(**core, log_name=log_name, log_provider=log_provider)


def build_script_activity(
    *,
    script: ScriptRef,
    severity: Severity,
    activity: ScriptActivityAction,
    device: DeviceRef,
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
        actor=_actor(actor_user, product),
        device=build_device(device),
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
    assignee: UserRef | None = None,
    assignee_group: GroupRef | None = None,
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
    """Build an OCSF Incident Finding (2005) event (requires an assignee or assignee_group)."""
    _at_least_one("assignee / assignee_group", assignee=assignee, assignee_group=assignee_group)
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
        assignee=build_user(assignee) if assignee is not None else None,
        assignee_group=build_group(assignee_group) if assignee_group is not None else None,
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
    compliance: ComplianceRef | None = None,
    vulnerabilities: Sequence[VulnerabilityRef] | None = None,
    uid: str | None = None,
    description: str | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
    uid_factory: Callable[[], str] = _new_uid,
) -> _m.ApplicationSecurityPostureFinding:
    """Build an OCSF App Security Posture Finding (2007); needs compliance or vulnerabilities."""
    _at_least_one(
        "compliance / vulnerabilities", compliance=compliance, vulnerabilities=vulnerabilities
    )
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
        **core,
        finding_info=_finding_info(uid, title, description, uid_factory),
        compliance=build_compliance(compliance) if compliance is not None else None,
        vulnerabilities=(
            [build_vulnerability(v) for v in vulnerabilities] if vulnerabilities else None
        ),
    )


# --- Identity & Access Management [3] --------------------------------------- #
def build_authorize_session(
    *,
    user: UserRef,
    severity: Severity,
    activity: AuthorizeSessionAction,
    privileges: Sequence[str] | None = None,
    group: GroupRef | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.AuthorizeSession:
    """Build an OCSF Authorize Session (3003) event (requires exactly one of privileges/group)."""
    _just_one("privileges / group", privileges=privileges, group=group)
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
    return _m.AuthorizeSession(
        **core,
        user=build_user(user),
        privileges=list(privileges) if privileges else None,
        group=build_group(group) if group is not None else None,
    )


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
    src_endpoint: EndpointRef,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.NetworkActivity:
    """Build an OCSF Network Activity (4001) event (requires src or dst endpoint)."""
    core = _core(
        OcsfClass.NETWORK_ACTIVITY,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.NetworkActivity(**core, src_endpoint=build_endpoint(src_endpoint))


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
    core = _core(
        OcsfClass.HTTP_ACTIVITY, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.HttpActivity(**core, http_request=_m.HttpRequest())


def build_dns_activity(
    *,
    severity: Severity,
    activity: DnsActivityAction,
    src_endpoint: EndpointRef,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.DnsActivity:
    """Build an OCSF DNS Activity (4003) event (requires src or dst endpoint)."""
    core = _core(
        OcsfClass.DNS_ACTIVITY, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.DnsActivity(**core, src_endpoint=build_endpoint(src_endpoint))


def build_dhcp_activity(
    *,
    severity: Severity,
    activity: DhcpActivityAction,
    src_endpoint: EndpointRef,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.DhcpActivity:
    """Build an OCSF DHCP Activity (4004) event (requires src or dst endpoint)."""
    core = _core(
        OcsfClass.DHCP_ACTIVITY, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.DhcpActivity(**core, src_endpoint=build_endpoint(src_endpoint))


def build_rdp_activity(
    *,
    severity: Severity,
    activity: RdpActivityAction,
    src_endpoint: EndpointRef,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.RdpActivity:
    """Build an OCSF RDP Activity (4005) event (requires src or dst endpoint)."""
    core = _core(
        OcsfClass.RDP_ACTIVITY, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.RdpActivity(**core, src_endpoint=build_endpoint(src_endpoint))


def build_smb_activity(
    *,
    severity: Severity,
    activity: SmbActivityAction,
    src_endpoint: EndpointRef,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.SmbActivity:
    """Build an OCSF SMB Activity (4006) event (requires src or dst endpoint)."""
    core = _core(
        OcsfClass.SMB_ACTIVITY, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.SmbActivity(**core, src_endpoint=build_endpoint(src_endpoint))


def build_ssh_activity(
    *,
    severity: Severity,
    activity: SshActivityAction,
    src_endpoint: EndpointRef,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.SshActivity:
    """Build an OCSF SSH Activity (4007) event (requires src or dst endpoint)."""
    core = _core(
        OcsfClass.SSH_ACTIVITY, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.SshActivity(**core, src_endpoint=build_endpoint(src_endpoint))


def build_ftp_activity(
    *,
    severity: Severity,
    activity: FtpActivityAction,
    src_endpoint: EndpointRef,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.FtpActivity:
    """Build an OCSF FTP Activity (4008) event (requires src or dst endpoint)."""
    core = _core(
        OcsfClass.FTP_ACTIVITY, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.FtpActivity(**core, src_endpoint=build_endpoint(src_endpoint))


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
    src_endpoint: EndpointRef,
    severity: Severity,
    activity: NtpActivityAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.NtpActivity:
    """Build an OCSF NTP Activity (4013) event (requires version + src or dst endpoint)."""
    core = _core(
        OcsfClass.NTP_ACTIVITY, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.NtpActivity(**core, version=version, src_endpoint=build_endpoint(src_endpoint))


def build_tunnel_activity(
    *,
    src_endpoint: EndpointRef,
    severity: Severity,
    activity: TunnelActivityAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.TunnelActivity:
    """Build an OCSF Tunnel Activity (4014) event (requires a src_endpoint/session/…)."""
    core = _core(
        OcsfClass.TUNNEL_ACTIVITY, activity, severity, message, observables, time_ms, product, clock
    )
    return _m.TunnelActivity(**core, src_endpoint=build_endpoint(src_endpoint))


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
    resources: Sequence[ResourceDetailsRef],
    severity: Severity,
    activity: CloudResourcesInventoryInfoAction,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.CloudResourcesInventoryInfo:
    """Build an OCSF Cloud Resources Inventory Info (5023) event (requires resources/…)."""
    _at_least_one("cloud_resources.resources", resources=list(resources))
    core = _core(
        OcsfClass.CLOUD_RESOURCES_INVENTORY_INFO,
        activity,
        severity,
        message,
        observables,
        time_ms,
        product,
        clock,
    )
    return _m.CloudResourcesInventoryInfo(
        **core, resources=[build_resource_details(r) for r in resources]
    )


def build_evidence_info(
    *,
    query_evidence: QueryEvidenceRef,
    query_result_id: int,
    severity: Severity,
    activity: EvidenceInfoAction,
    device: DeviceRef,
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
        device=build_device(device),
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
    database: DatabaseRef,
    src_endpoint: EndpointRef,
    severity: Severity,
    activity: DatastoreActivityAction,
    actor_user: UserRef | None = None,
    message: str | None = None,
    observables: Sequence[Observable] | None = None,
    time_ms: int | None = None,
    product: _m.Product | None = None,
    clock: Callable[[], int] = _now_ms,
) -> _m.DatastoreActivity:
    """Build an OCSF Datastore Activity (6005) event (requires a database/databucket/table)."""
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
        **core,
        actor=_actor(actor_user, product),
        src_endpoint=build_endpoint(src_endpoint),
        database=build_database(database),
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
    dst_endpoint: EndpointRef,
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
        dst_endpoint=build_endpoint(dst_endpoint),
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
