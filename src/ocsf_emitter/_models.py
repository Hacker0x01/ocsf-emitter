"""Generated OCSF models for schema version 1.1.0.

DO NOT EDIT BY HAND. Regenerate with:
    uv run --extra codegen python scripts/gen_models.py 1.1.0

Source: OCSF 1.1.0 metaschema (ocsf-lib), class detection_finding (2004),
converted to JSON Schema (base class, profiles excluded).
"""

from __future__ import annotations

from enum import IntEnum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class ClassUid(IntEnum):
    integer_2004 = 2004


class ActivityId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class RiskLevelId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4


class ImpactId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_99 = 99


class CategoryUid(IntEnum):
    integer_2 = 2


class TypeUid(IntEnum):
    integer_200400 = 200400
    integer_200401 = 200401
    integer_200402 = 200402
    integer_200403 = 200403
    integer_200499 = 200499


class StatusId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_99 = 99


class SeverityId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_99 = 99


class ConfidenceId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class Enrichment(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    data: Any
    name: str
    type: str | None = None
    value: str
    provider: str | None = None


class Group(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    type: str | None = None
    domain: str | None = None
    desc: str | None = None
    uid: str | None = None
    privileges: list[str] | None = None


class TypeId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class Location(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    desc: str | None = None
    city: str | None = None
    country: str | None = None
    coordinates: list[float] | None = None
    continent: str | None = None
    is_on_premises: bool | None = None
    isp: str | None = None
    postal_code: str | None = None
    provider: str | None = None
    region: str | None = None


class TypeId1(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_7 = 7
    integer_8 = 8
    integer_9 = 9
    integer_10 = 10
    integer_99 = 99


class Account(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    type: str | None = None
    uid: str | None = None
    type_id: TypeId1 | None = None


class Organization(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    uid: str | None = None
    ou_name: str | None = None
    ou_uid: str | None = None


class TypeId2(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_7 = 7
    integer_8 = 8
    integer_9 = 9
    integer_10 = 10
    integer_11 = 11
    integer_99 = 99


class KeyboardInfo(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    function_keys: int | None = None
    ime: str | None = None
    keyboard_layout: str | None = None
    keyboard_subtype: int | None = None
    keyboard_type: str | None = None


class Display(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    color_depth: int | None = None
    physical_height: int | None = None
    physical_orientation: int | None = None
    physical_width: int | None = None
    scale_factor: int | None = None


class TypeId4(IntEnum):
    integer_0 = 0
    integer_99 = 99
    integer_100 = 100
    integer_101 = 101
    integer_200 = 200
    integer_201 = 201
    integer_300 = 300
    integer_301 = 301
    integer_302 = 302
    integer_400 = 400
    integer_401 = 401
    integer_402 = 402


class Os(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    type: str | None = None
    version: str | None = None
    build: str | None = None
    country: str | None = None
    type_id: TypeId4
    lang: str | None = None
    cpe_name: str | None = None
    cpu_bits: int | None = None
    edition: str | None = None
    sp_name: str | None = None
    sp_ver: int | None = None


class Idp(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    uid: str | None = None


class Policy(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    version: str | None = None
    group: Group | None = None
    desc: str | None = None
    uid: str | None = None


class Session(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    count: int | None = None
    terminal: str | None = None
    uid: str | None = None
    uuid: str | None = None
    issuer: str | None = None
    created_time: int | None = None
    credential_uid: str | None = None
    expiration_reason: str | None = None
    expiration_time: int | None = None
    is_mfa: bool | None = None
    is_remote: bool | None = None
    is_vpn: bool | None = None
    uid_alt: str | None = None


class IntegrityId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_99 = 99


class Object(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )


class TypeId5(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_7 = 7
    integer_99 = 99


class ConfidentialityId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_99 = 99


class AlgorithmId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_7 = 7
    integer_99 = 99


class Fingerprint(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    value: str
    algorithm: str | None = None
    algorithm_id: AlgorithmId


class Feature(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    version: str | None = None
    uid: str | None = None


class AlgorithmId1(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_99 = 99


class Certificate(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    version: str | None = None
    uid: str | None = None
    subject: str | None = None
    issuer: str
    fingerprints: list[Fingerprint]
    created_time: int | None = None
    expiration_time: int | None = None
    serial_number: str


class Image(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    tag: str | None = None
    path: str | None = None
    uid: str
    labels: list[str] | None = None


class Service(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    version: str | None = None
    uid: str | None = None
    labels: list[str] | None = None


class BoundaryId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_7 = 7
    integer_8 = 8
    integer_9 = 9
    integer_10 = 10
    integer_11 = 11
    integer_99 = 99


class DirectionId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class ProtocolVerId(IntEnum):
    integer_0 = 0
    integer_4 = 4
    integer_6 = 6
    integer_99 = 99


class NetworkConnectionInfo(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    session: Session | None = None
    uid: str | None = None
    boundary: str | None = None
    protocol_name: str | None = None
    direction: str | None = None
    boundary_id: BoundaryId | None = None
    direction_id: DirectionId
    protocol_num: int | None = None
    protocol_ver: str | None = None
    protocol_ver_id: ProtocolVerId | None = None
    tcp_flags: int | None = None


class OpcodeId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6


class DnsQuery(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type: str | None = None
    class_: str | None = Field(None, alias='class')
    opcode: str | None = None
    hostname: str
    opcode_id: OpcodeId | None = None
    packet_uid: int | None = None


class PhaseId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_7 = 7
    integer_99 = 99


class KillChainPhase(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    phase: str | None = None
    phase_id: PhaseId


class Tactic(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    uid: str | None = None
    src_url: str | None = None


class SubTechnique(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    uid: str | None = None
    src_url: str | None = None


class Technique(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    uid: str | None = None
    src_url: str | None = None


class TypeId6(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_7 = 7
    integer_8 = 8
    integer_9 = 9
    integer_10 = 10
    integer_20 = 20
    integer_21 = 21
    integer_22 = 22
    integer_23 = 23
    integer_24 = 24
    integer_25 = 25
    integer_26 = 26
    integer_27 = 27
    integer_28 = 28
    integer_29 = 29
    integer_30 = 30
    integer_99 = 99


class ScoreId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_7 = 7
    integer_8 = 8
    integer_9 = 9
    integer_10 = 10
    integer_99 = 99


class Reputation(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    base_score: float
    provider: str | None = None
    score: str | None = None
    score_id: ScoreId


class TypeId7(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_99 = 99


class Analytic(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    type: str | None = None
    version: str | None = None
    desc: str | None = None
    uid: str | None = None
    category: str | None = None
    type_id: TypeId7
    related_analytics: list[Analytic] | None = None


class Package(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    version: str
    release: str | None = None
    epoch: int | None = None
    license: str | None = None
    architecture: str | None = None
    purl: str | None = None


class Cwe(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    uid: str
    caption: str | None = None
    src_url: str | None = None


class Epss(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    version: str | None = None
    created_time: int | None = None
    percentile: float | None = None
    score: str


class Metric(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    value: str


class TypeId8(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_7 = 7
    integer_8 = 8
    integer_9 = 9
    integer_10 = 10
    integer_11 = 11
    integer_99 = 99


class TypeId9(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_99 = 99


class NetworkInterface(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    type: str | None = None
    ip: str | None = None
    uid: str | None = None
    mac: str | None = None
    hostname: str | None = None
    namespace: str | None = None
    type_id: TypeId9
    subnet_prefix: int | None = None


class Extension(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    version: str
    uid: str


class DeviceHwInfo(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    bios_date: str | None = None
    bios_manufacturer: str | None = None
    bios_ver: str | None = None
    chassis: str | None = None
    cpu_bits: int | None = None
    cpu_cores: int | None = None
    cpu_count: int | None = None
    cpu_speed: int | None = None
    cpu_type: str | None = None
    desktop_display: Display | None = None
    keyboard_info: KeyboardInfo | None = None
    ram_size: int | None = None
    serial_number: str | None = None


class Authorization(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    decision: str | None = None
    policy: Policy | None = None


class Product(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    version: str | None = None
    path: str | None = None
    uid: str | None = None
    feature: Feature | None = None
    lang: str | None = None
    cpe_name: str | None = None
    url_string: str | None = None
    vendor_name: str


class DigitalSignature(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    digest: Fingerprint | None = None
    certificate: Certificate | None = None
    algorithm: str | None = None
    algorithm_id: AlgorithmId1
    created_time: int | None = None
    developer_uid: str | None = None


class Container(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    runtime: str | None = None
    size: int | None = None
    tag: str | None = None
    uid: str | None = None
    image: Image | None = None
    hash: Fingerprint | None = None
    network_driver: str | None = None
    orchestrator: str | None = None
    pod_uuid: str | None = None


class Request(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    data: Any | None = None
    flags: list[str] | None = None
    uid: str
    containers: list[Container] | None = None


class Attack(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    version: str | None = None
    tactics: list[Tactic] | None = None
    technique: Technique | None = None
    sub_technique: SubTechnique | None = None
    tactic: Tactic | None = None


class Observable(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    type: str | None = None
    value: str | None = None
    type_id: TypeId6
    reputation: Reputation | None = None


class KbArticle(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    size: int | None = None
    os: Os | None = None
    title: str | None = None
    product: Product | None = None
    uid: str
    severity: str | None = None
    bulletin: str | None = None
    classification: str | None = None
    created_time: int | None = None
    is_superseded: bool | None = None
    src_url: str | None = None


class Cvss(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    version: str
    depth: str | None = None
    severity: str | None = None
    metrics: list[Metric] | None = None
    base_score: float
    overall_score: float | None = None
    vector_string: str | None = None


class Device(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    autoscale_uid: str | None = None
    is_trusted: bool | None = None
    org: Organization | None = None
    vpc_uid: str | None = None
    created_time: int | None = None
    risk_level_id: RiskLevelId | None = None
    is_compliant: bool | None = None
    is_personal: bool | None = None
    subnet: str | None = None
    last_seen_time: int | None = None
    image: Image | None = None
    os: Os | None = None
    vlan_uid: str | None = None
    location: Location | None = None
    uid: str | None = None
    ip: str | None = None
    risk_score: int | None = None
    modified_time: int | None = None
    desc: str | None = None
    region: str | None = None
    hw_info: DeviceHwInfo | None = None
    zone: str | None = None
    domain: str | None = None
    instance_uid: str | None = None
    subnet_uid: str | None = None
    imei: str | None = None
    uid_alt: str | None = None
    network_interfaces: list[NetworkInterface] | None = None
    interface_uid: str | None = None
    groups: list[Group] | None = None
    first_seen_time: int | None = None
    name: str | None = None
    is_managed: bool | None = None
    risk_level: str | None = None
    mac: str | None = None
    type: str | None = None
    hypervisor: str | None = None
    type_id: TypeId8
    interface_name: str | None = None
    hostname: str | None = None


class NetworkProxy(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    port: int | None = None
    type: str | None = None
    os: Os | None = None
    domain: str | None = None
    ip: str | None = None
    location: Location | None = None
    uid: str | None = None
    mac: str | None = None
    hostname: str | None = None
    type_id: TypeId2 | None = None
    hw_info: DeviceHwInfo | None = None
    instance_uid: str | None = None
    interface_name: str | None = None
    interface_uid: str | None = None
    intermediate_ips: list[str] | None = None
    proxy_endpoint: NetworkProxy | None = None
    subnet_uid: str | None = None
    svc_name: str | None = None
    vlan_uid: str | None = None
    vpc_uid: str | None = None
    zone: str | None = None


class Response(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    error: str | None = None
    code: int | None = None
    data: Any | None = None
    flags: list[str] | None = None
    message: str | None = None
    containers: list[Container] | None = None
    error_message: str | None = None


class RelatedEvent(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type: str | None = None
    uid: str
    type_uid: int | None = None
    observables: list[Observable] | None = None
    attacks: list[Attack] | None = None
    kill_chain: list[KillChainPhase] | None = None
    product_uid: str | None = None


class Remediation(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    desc: str
    references: list[str] | None = None
    kb_articles: list[str] | None = None
    kb_article_list: list[KbArticle] | None = None


class Cve(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type: str | None = None
    title: str | None = None
    product: Product | None = None
    desc: str | None = None
    uid: str
    references: list[str] | None = None
    created_time: int | None = None
    cvss: list[Cvss] | None = None
    cwe: Cwe | None = None
    cwe_uid: str | None = None
    cwe_url: str | None = None
    epss: Epss | None = None
    modified_time: int | None = None


class AffectedPackage(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    version: str
    path: str | None = None
    release: str | None = None
    epoch: int | None = None
    license: str | None = None
    architecture: str | None = None
    fixed_in_version: str | None = None
    package_manager: str | None = None
    purl: str | None = None
    remediation: Remediation | None = None


class Logger(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    version: str | None = None
    device: Device | None = None
    product: Product | None = None
    uid: str | None = None
    log_level: str | None = None
    log_name: str | None = None
    log_provider: str | None = None
    log_version: str | None = None
    logged_time: int | None = None
    transmit_time: int | None = None


class NetworkEndpoint(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    port: int | None = None
    type: str | None = None
    os: Os | None = None
    domain: str | None = None
    ip: str | None = None
    location: Location | None = None
    uid: str | None = None
    mac: str | None = None
    hostname: str | None = None
    type_id: TypeId2 | None = None
    hw_info: DeviceHwInfo | None = None
    instance_uid: str | None = None
    interface_name: str | None = None
    interface_uid: str | None = None
    intermediate_ips: list[str] | None = None
    proxy_endpoint: NetworkProxy | None = None
    subnet_uid: str | None = None
    svc_name: str | None = None
    vlan_uid: str | None = None
    vpc_uid: str | None = None
    zone: str | None = None


class Api(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    version: str | None = None
    request: Request | None = None
    service: Service | None = None
    group: Group | None = None
    response: Response | None = None
    operation: str


class FindingInfo(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    title: str
    desc: str | None = None
    uid: str
    types: list[str] | None = None
    attacks: list[Attack] | None = None
    analytic: Analytic | None = None
    created_time: int | None = None
    data_sources: list[str] | None = None
    first_seen_time: int | None = None
    kill_chain: list[KillChainPhase] | None = None
    last_seen_time: int | None = None
    modified_time: int | None = None
    product_uid: str | None = None
    related_analytics: list[Analytic] | None = None
    related_events: list[RelatedEvent] | None = None
    src_url: str | None = None


class Metadata(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    version: str
    extension: Extension | None = None
    product: Product
    uid: str | None = None
    extensions: list[Extension] | None = None
    labels: list[str] | None = None
    log_level: str | None = None
    sequence: int | None = None
    profiles: list[str] | None = None
    correlation_uid: str | None = None
    event_code: str | None = None
    log_name: str | None = None
    log_provider: str | None = None
    log_version: str | None = None
    logged_time: int | None = None
    loggers: list[Logger] | None = None
    modified_time: int | None = None
    original_time: str | None = None
    processed_time: int | None = None
    tenant_uid: str | None = None


class DetectionFinding(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    status_code: str | None = None
    timezone_offset: int | None = None
    status_detail: str | None = None
    impact_score: int | None = None
    observables: list[Observable] | None = None
    class_uid: ClassUid
    activity_id: ActivityId
    raw_data: str | None = None
    risk_level_id: RiskLevelId | None = None
    severity: str | None = None
    message: str | None = None
    unmapped: Object | None = None
    comment: str | None = None
    activity_name: str | None = None
    class_name: str | None = None
    impact: str | None = None
    metadata: Metadata
    vulnerabilities: list[Vulnerability] | None = None
    remediation: Remediation | None = None
    duration: int | None = None
    impact_id: ImpactId | None = None
    status: str | None = None
    time: int
    confidence_score: int | None = None
    risk_score: int | None = None
    start_time: int | None = None
    category_uid: CategoryUid
    end_time: int | None = None
    type_uid: TypeUid
    status_id: StatusId | None = None
    finding_info: FindingInfo
    category_name: str | None = None
    count: int | None = None
    type_name: str | None = None
    severity_id: SeverityId
    risk_level: str | None = None
    evidences: list[Evidences] | None = None
    confidence_id: ConfidenceId | None = None
    confidence: str | None = None
    resources: list[ResourceDetails] | None = None
    enrichments: list[Enrichment] | None = None


class ResourceDetails(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    data: Any | None = None
    name: str | None = None
    owner: User | None = None
    type: str | None = None
    version: str | None = None
    group: Group | None = None
    uid: str | None = None
    labels: list[str] | None = None
    namespace: str | None = None
    criticality: str | None = None


class User(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    type: str | None = None
    domain: str | None = None
    uid: str | None = None
    org: Organization | None = None
    groups: list[Group] | None = None
    type_id: TypeId | None = None
    full_name: str | None = None
    account: Account | None = None
    credential_uid: str | None = None
    email_addr: str | None = None
    ldap_person: LdapPerson | None = None
    uid_alt: str | None = None


class LdapPerson(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    location: Location | None = None
    labels: list[str] | None = None
    manager: User | None = None
    cost_center: str | None = None
    created_time: int | None = None
    deleted_time: int | None = None
    email_addrs: list[str] | None = None
    employee_uid: str | None = None
    given_name: str | None = None
    hire_time: int | None = None
    job_title: str | None = None
    last_login_time: int | None = None
    ldap_cn: str | None = None
    ldap_dn: str | None = None
    leave_time: int | None = None
    modified_time: int | None = None
    office_location: str | None = None
    surname: str | None = None


class Evidences(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    data: Any | None = None
    process: Process | None = None
    file: File | None = None
    query: DnsQuery | None = None
    connection_info: NetworkConnectionInfo | None = None
    api: Api | None = None
    actor: Actor | None = None
    dst_endpoint: NetworkEndpoint | None = None
    src_endpoint: NetworkEndpoint | None = None


class Actor(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    process: Process | None = None
    session: Session | None = None
    user: User | None = None
    authorizations: list[Authorization] | None = None
    idp: Idp | None = None
    invoked_by: str | None = None


class Process(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    pid: int | None = None
    session: Session | None = None
    file: File | None = None
    user: User | None = None
    tid: int | None = None
    uid: str | None = None
    loaded_modules: list[str] | None = None
    cmd_line: str | None = None
    created_time: int | None = None
    integrity: str | None = None
    integrity_id: IntegrityId | None = None
    lineage: list[str] | None = None
    parent_process: Process | None = None
    sandbox: str | None = None
    terminated_time: int | None = None
    xattributes: Object | None = None


class File(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    attributes: int | None = None
    name: str
    owner: User | None = None
    size: int | None = None
    type: str | None = None
    version: str | None = None
    path: str | None = None
    signature: DigitalSignature | None = None
    product: Product | None = None
    modifier: User | None = None
    desc: str | None = None
    uid: str | None = None
    type_id: TypeId5
    accessor: User | None = None
    company_name: str | None = None
    creator: User | None = None
    mime_type: str | None = None
    parent_folder: str | None = None
    accessed_time: int | None = None
    confidentiality: str | None = None
    confidentiality_id: ConfidentialityId | None = None
    created_time: int | None = None
    hashes: list[Fingerprint] | None = None
    is_system: bool | None = None
    modified_time: int | None = None
    security_descriptor: str | None = None
    xattributes: Object | None = None


class Vulnerability(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    title: str | None = None
    desc: str | None = None
    references: list[str] | None = None
    severity: str | None = None
    affected_code: list[AffectedCode] | None = None
    affected_packages: list[AffectedPackage] | None = None
    cve: Cve | None = None
    cwe: Cwe | None = None
    first_seen_time: int | None = None
    fix_available: bool | None = None
    is_exploit_available: bool | None = None
    is_fix_available: bool | None = None
    kb_articles: list[str] | None = None
    kb_article_list: list[KbArticle] | None = None
    last_seen_time: int | None = None
    packages: list[Package] | None = None
    related_vulnerabilities: list[str] | None = None
    remediation: Remediation | None = None
    vendor_name: str | None = None


class AffectedCode(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    owner: User | None = None
    file: File
    end_line: int | None = None
    remediation: Remediation | None = None
    start_line: int | None = None


Analytic.model_rebuild()
NetworkProxy.model_rebuild()
DetectionFinding.model_rebuild()
ResourceDetails.model_rebuild()
User.model_rebuild()
Evidences.model_rebuild()
Actor.model_rebuild()
Process.model_rebuild()
Vulnerability.model_rebuild()
