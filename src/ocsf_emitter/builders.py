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
from .defaults import Activity, Confidence, RiskLevel, Severity, Status
from .domain import DetectionSignal, MitreAttack, Observable, ObservableType
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

    OCSF ``observable.name`` is the attribute name/path and is required in
    1.1.0. When the caller does not supply one we fall back to the observable
    type's label (e.g. ``"ip_address"``).
    """
    return _m.Observable(
        name=observable.name if observable.name is not None else observable.type.value,
        value=observable.value,
        type_id=_m.TypeId6(_OBSERVABLE_TYPE_TO_ID[observable.type]),
    )


def build_attack(attack: MitreAttack) -> _m.Attack:
    """Map a MitreAttack to an OCSF attack object (technique [+ tactic])."""
    technique = _m.Technique(uid=attack.technique_uid, name=attack.technique_name)
    tactics = None
    if attack.tactic_uid is not None:
        tactics = [_m.Tactic(uid=attack.tactic_uid, name=attack.tactic_name)]
    return _m.Attack(technique=technique, tactics=tactics)


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
