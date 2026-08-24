"""Generated OCSF models for schema version 1.5.0.

DO NOT EDIT BY HAND. Regenerate with:
    uv run --extra codegen python scripts/gen_models.py 1.5.0

Source: OCSF 1.5.0 metaschema (ocsf-lib), classes:
    - detection_finding
    - compliance_finding
    - authentication
    - account_change
    - patch_state
    - api_activity
    - web_resources_activity
    - file_hosting
converted to JSON Schema (base classes, profiles excluded).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field
from enum import IntEnum
from typing import Any


class OcsfSupportedClasses(BaseModel):
    pass


class TypeUid(IntEnum):
    integer_200400 = 200400
    integer_200401 = 200401
    integer_200402 = 200402
    integer_200403 = 200403
    integer_200499 = 200499


class ImpactId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_99 = 99


class ActivityId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class CategoryUid(IntEnum):
    integer_2 = 2


class ConfidenceId(IntEnum):
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
    integer_99 = 99


class ClassUid(IntEnum):
    integer_2004 = 2004


class StatusId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
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


class TypeUid1(IntEnum):
    integer_200300 = 200300
    integer_200301 = 200301
    integer_200302 = 200302
    integer_200303 = 200303
    integer_200399 = 200399


class ClassUid1(IntEnum):
    integer_2003 = 2003


class TypeUid2(IntEnum):
    integer_300200 = 300200
    integer_300201 = 300201
    integer_300202 = 300202
    integer_300203 = 300203
    integer_300204 = 300204
    integer_300205 = 300205
    integer_300206 = 300206
    integer_300299 = 300299


class AuthProtocolId(IntEnum):
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
    integer_12 = 12
    integer_99 = 99


class ActivityId2(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_99 = 99


class CategoryUid2(IntEnum):
    integer_3 = 3


class LogonTypeId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_7 = 7
    integer_8 = 8
    integer_9 = 9
    integer_10 = 10
    integer_11 = 11
    integer_12 = 12
    integer_13 = 13
    integer_99 = 99


class ClassUid2(IntEnum):
    integer_3002 = 3002


class StatusId2(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_99 = 99


class TypeUid3(IntEnum):
    integer_300100 = 300100
    integer_300101 = 300101
    integer_300102 = 300102
    integer_300103 = 300103
    integer_300104 = 300104
    integer_300105 = 300105
    integer_300106 = 300106
    integer_300107 = 300107
    integer_300108 = 300108
    integer_300109 = 300109
    integer_300110 = 300110
    integer_300111 = 300111
    integer_300112 = 300112
    integer_300199 = 300199


class ActivityId3(IntEnum):
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
    integer_12 = 12
    integer_99 = 99


class ClassUid3(IntEnum):
    integer_3001 = 3001


class TypeUid4(IntEnum):
    integer_500400 = 500400
    integer_500401 = 500401
    integer_500402 = 500402
    integer_500499 = 500499


class ActivityId4(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_99 = 99


class CategoryUid4(IntEnum):
    integer_5 = 5


class ClassUid4(IntEnum):
    integer_5004 = 5004


class TypeUid5(IntEnum):
    integer_600300 = 600300
    integer_600301 = 600301
    integer_600302 = 600302
    integer_600303 = 600303
    integer_600304 = 600304
    integer_600399 = 600399


class ActivityId5(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_99 = 99


class CategoryUid5(IntEnum):
    integer_6 = 6


class ClassUid5(IntEnum):
    integer_6003 = 6003


class TypeUid6(IntEnum):
    integer_600100 = 600100
    integer_600101 = 600101
    integer_600102 = 600102
    integer_600103 = 600103
    integer_600104 = 600104
    integer_600105 = 600105
    integer_600106 = 600106
    integer_600107 = 600107
    integer_600108 = 600108
    integer_600199 = 600199


class ActivityId6(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_7 = 7
    integer_8 = 8
    integer_99 = 99


class ClassUid6(IntEnum):
    integer_6001 = 6001


class TypeUid7(IntEnum):
    integer_600600 = 600600
    integer_600601 = 600601
    integer_600602 = 600602
    integer_600603 = 600603
    integer_600604 = 600604
    integer_600605 = 600605
    integer_600606 = 600606
    integer_600607 = 600607
    integer_600608 = 600608
    integer_600609 = 600609
    integer_600610 = 600610
    integer_600611 = 600611
    integer_600612 = 600612
    integer_600613 = 600613
    integer_600614 = 600614
    integer_600615 = 600615
    integer_600616 = 600616
    integer_600617 = 600617
    integer_600699 = 600699


class ShareTypeId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class ActivityId7(IntEnum):
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
    integer_12 = 12
    integer_13 = 13
    integer_14 = 14
    integer_15 = 15
    integer_16 = 16
    integer_17 = 17
    integer_99 = 99


class ClassUid7(IntEnum):
    integer_6006 = 6006


class TypeId(IntEnum):
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
    integer_12 = 12
    integer_13 = 13
    integer_14 = 14
    integer_15 = 15
    integer_16 = 16
    integer_17 = 17
    integer_18 = 18
    integer_99 = 99


class InstallStateId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class TypeId1(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_99 = 99


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
    integer_99 = 99


class AnalysisTarget(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    type: str | None = None


class TypeId3(IntEnum):
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
    algorithm: str | None = None
    type_id: TypeId3
    related_analytics: list[Analytic] | None = None


class FactorTypeId(IntEnum):
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


class TypeId4(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_99 = 99


class AutonomousSystem(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    number: int | None = None


class StatusId8(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class Check(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    status: str | None = None
    version: str | None = None
    desc: str | None = None
    uid: str | None = None
    severity: str | None = None
    severity_id: SeverityId | None = None
    standards: list[str] | None = None
    status_id: StatusId8 | None = None


class CisControl(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    version: str | None = None
    desc: str | None = None


class Cwe(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    uid: str
    caption: str | None = None
    src_url: str | None = None


class D3fTactic(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    uid: str | None = None
    src_url: str | None = None


class D3fTechnique(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    uid: str | None = None
    src_url: str | None = None


class D3fend(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    version: str | None = None
    d3f_tactic: D3fTactic | None = None
    d3f_technique: D3fTechnique | None = None


class TypeId5(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_99 = 99


class TypeId6(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class TypeId7(IntEnum):
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
    integer_12 = 12
    integer_13 = 13
    integer_14 = 14
    integer_15 = 15
    integer_99 = 99


class CpuArchitectureId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class AlgorithmId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_99 = 99


class StateId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_99 = 99


class Display(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    color_depth: int | None = None
    physical_height: int | None = None
    physical_orientation: int | None = None
    physical_width: int | None = None
    scale_factor: int | None = None


class OpcodeId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_99 = 99


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


class Edge(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    data: Any | None = None
    name: str | None = None
    relation: str | None = None
    uid: str | None = None
    source: str
    target: str
    is_directed: bool | None = None


class AlgorithmId1(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_99 = 99


class EncryptionDetails(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type: str | None = None
    key_length: int | None = None
    algorithm: str | None = None
    algorithm_id: AlgorithmId1 | None = None
    key_uid: str | None = None


class EnvironmentVariable(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    value: str


class Epss(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    version: str | None = None
    created_time: int | None = None
    percentile: float | None = None
    score: str


class VerdictId(IntEnum):
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


class Extension(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    version: str
    uid: str


class Feature(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    version: str | None = None
    uid: str | None = None


class TypeId8(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_7 = 7
    integer_99 = 99


class DriveTypeId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_99 = 99


class ConfidentialityId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_99 = 99


class AlgorithmId2(IntEnum):
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
    algorithm_id: AlgorithmId2


class QueryLanguageId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_7 = 7
    integer_99 = 99


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


class HttpHeader(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    value: str


class HttpResponse(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    code: int
    message: str | None = None
    status: str | None = None
    length: int | None = None
    content_type: str | None = None
    body_length: int | None = None
    http_headers: list[HttpHeader] | None = None
    latency: int | None = None


class StateId1(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_99 = 99


class TypeId9(IntEnum):
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
    integer_99 = 99


class Ja4Fingerprint(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type: str | None = None
    value: str
    type_id: TypeId9
    section_a: str | None = None
    section_b: str | None = None
    section_c: str | None = None
    section_d: str | None = None


class RunStateId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_99 = 99


class KeyValueObject(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    value: str | None = None
    values: list[str] | None = None


class KeyboardInfo(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    function_keys: int | None = None
    ime: str | None = None
    keyboard_layout: str | None = None
    keyboard_subtype: int | None = None
    keyboard_type: str | None = None


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


class Location(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    desc: str | None = None
    long: float | None = None
    city: str | None = None
    country: str | None = None
    coordinates: list[float] | None = None
    continent: str | None = None
    aerial_height: str | None = None
    geodetic_altitude: str | None = None
    geodetic_vertical_accuracy: str | None = None
    geohash: str | None = None
    horizontal_accuracy: str | None = None
    is_on_premises: bool | None = None
    isp: str | None = None
    lat: float | None = None
    postal_code: str | None = None
    pressure_altitude: str | None = None
    provider: str | None = None
    region: str | None = None


class LongString(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    value: str
    is_truncated: bool | None = None
    untruncated_size: int | None = None


class ClassificationId(IntEnum):
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
    integer_13 = 13
    integer_14 = 14
    integer_15 = 15
    integer_16 = 16
    integer_17 = 17
    integer_18 = 18
    integer_19 = 19
    integer_20 = 20
    integer_21 = 21
    integer_22 = 22
    integer_99 = 99


class TypeId10(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_7 = 7
    integer_99 = 99


class MalwareScanInfo(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    size: int | None = None
    type: str | None = None
    uid: str | None = None
    start_time: int | None = None
    type_id: TypeId10
    end_time: int | None = None
    num_volumes: int | None = None
    num_infected: int | None = None
    unique_malware_count: int | None = None
    num_files: int | None = None


class Metric(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    value: str


class Mitigation(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    uid: str | None = None
    countermeasures: list[D3fend] | None = None
    src_url: str | None = None


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


class TypeId11(IntEnum):
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
    integer_12 = 12
    integer_13 = 13
    integer_14 = 14
    integer_15 = 15
    integer_99 = 99


class TypeId12(IntEnum):
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
    hostname: str | None = None
    mac: str | None = None
    namespace: str | None = None
    type_id: TypeId12
    subnet_prefix: int | None = None


class TypeId13(IntEnum):
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
    integer_12 = 12
    integer_13 = 13
    integer_14 = 14
    integer_15 = 15
    integer_99 = 99


class Node(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    data: Any | None = None
    name: str | None = None
    type: str | None = None
    desc: str | None = None
    uid: str


class Object(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )


class TypeId14(IntEnum):
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
    integer_12 = 12
    integer_13 = 13
    integer_14 = 14
    integer_15 = 15
    integer_16 = 16
    integer_17 = 17
    integer_18 = 18
    integer_19 = 19
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
    integer_31 = 31
    integer_32 = 32
    integer_33 = 33
    integer_34 = 34
    integer_35 = 35
    integer_36 = 36
    integer_37 = 37
    integer_38 = 38
    integer_39 = 39
    integer_40 = 40
    integer_41 = 41
    integer_42 = 42
    integer_43 = 43
    integer_44 = 44
    integer_45 = 45
    integer_46 = 46
    integer_99 = 99


class Organization(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    uid: str | None = None
    ou_name: str | None = None
    ou_uid: str | None = None


class TypeId15(IntEnum):
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
    lang: str | None = None
    type_id: TypeId15
    cpe_name: str | None = None
    cpu_bits: int | None = None
    edition: str | None = None
    kernel_release: str | None = None
    sp_name: str | None = None
    sp_ver: int | None = None


class TypeId16(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_99 = 99


class Package(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    type: str | None = None
    version: str
    uid: str | None = None
    hash: Fingerprint | None = None
    release: str | None = None
    epoch: int | None = None
    type_id: TypeId16 | None = None
    license: str | None = None
    architecture: str | None = None
    cpe_name: str | None = None
    license_url: str | None = None
    package_manager: str | None = None
    package_manager_url: str | None = None
    purl: str | None = None
    src_url: str | None = None
    vendor_name: str | None = None


class Policy(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    data: Any | None = None
    name: str | None = None
    version: str | None = None
    group: Group | None = None
    desc: str | None = None
    uid: str | None = None
    is_applied: bool | None = None


class IntegrityId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_99 = 99


class ProcessEntity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    pid: int | None = None
    path: str | None = None
    uid: str | None = None
    cmd_line: str | None = None
    cpid: str | None = None
    created_time: int | None = None


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
    vendor_name: str | None = None


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


class Rule(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    type: str | None = None
    version: str | None = None
    desc: str | None = None
    uid: str | None = None
    category: str | None = None


class San(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    type: str


class Scim(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    version: str | None = None
    state: str | None = None
    uid: str | None = None
    protocol_name: str | None = None
    auth_protocol: str | None = None
    auth_protocol_id: AuthProtocolId | None = None
    created_time: int | None = None
    error_message: str | None = None
    is_group_provisioning_enabled: bool | None = None
    is_user_provisioning_enabled: bool | None = None
    last_run_time: int | None = None
    modified_time: int | None = None
    rate_limit: int | None = None
    scim_group_schema: Any | None = None
    scim_user_schema: Any | None = None
    state_id: StateId1 | None = None
    uid_alt: str | None = None
    url_string: str | None = None
    vendor_name: str | None = None


class TypeId17(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_7 = 7
    integer_99 = 99


class Service(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    version: str | None = None
    uid: str | None = None
    labels: list[str] | None = None
    tags: list[KeyValueObject] | None = None


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


class SubTechnique(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    uid: str | None = None
    src_url: str | None = None


class Tactic(BaseModel):
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


class TypeId18(IntEnum):
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
    integer_99 = 99


class Timespan(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type: str | None = None
    start_time: int | None = None
    duration: int | None = None
    type_id: TypeId18 | None = None
    end_time: int | None = None
    duration_days: int | None = None
    duration_hours: int | None = None
    duration_mins: int | None = None
    duration_months: int | None = None
    duration_secs: int | None = None
    duration_weeks: int | None = None
    duration_years: int | None = None


class TypeId19(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_5 = 5
    integer_10 = 10
    integer_13 = 13
    integer_14 = 14
    integer_15 = 15
    integer_16 = 16
    integer_18 = 18
    integer_19 = 19
    integer_20 = 20
    integer_21 = 21
    integer_41 = 41
    integer_42 = 42
    integer_43 = 43
    integer_44 = 44
    integer_45 = 45
    integer_47 = 47
    integer_48 = 48
    integer_49 = 49
    integer_50 = 50
    integer_51 = 51
    integer_99 = 99


class TlsExtension(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    data: Any | None = None
    type: str | None = None
    type_id: TypeId19


class Trait(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    type: str | None = None
    values: list[str] | None = None
    uid: str | None = None
    category: str | None = None


class TransformationInfo(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    time: int | None = None
    product: Product | None = None
    uid: str | None = None
    lang: str | None = None
    url_string: str | None = None


class CategoryId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_7 = 7
    integer_9 = 9
    integer_11 = 11
    integer_14 = 14
    integer_15 = 15
    integer_16 = 16
    integer_17 = 17
    integer_18 = 18
    integer_20 = 20
    integer_21 = 21
    integer_22 = 22
    integer_23 = 23
    integer_24 = 24
    integer_25 = 25
    integer_26 = 26
    integer_27 = 27
    integer_29 = 29
    integer_30 = 30
    integer_31 = 31
    integer_32 = 32
    integer_33 = 33
    integer_34 = 34
    integer_35 = 35
    integer_36 = 36
    integer_37 = 37
    integer_38 = 38
    integer_40 = 40
    integer_43 = 43
    integer_44 = 44
    integer_45 = 45
    integer_46 = 46
    integer_47 = 47
    integer_49 = 49
    integer_50 = 50
    integer_51 = 51
    integer_52 = 52
    integer_53 = 53
    integer_54 = 54
    integer_55 = 55
    integer_56 = 56
    integer_57 = 57
    integer_58 = 58
    integer_59 = 59
    integer_60 = 60
    integer_61 = 61
    integer_63 = 63
    integer_64 = 64
    integer_65 = 65
    integer_66 = 66
    integer_67 = 67
    integer_68 = 68
    integer_71 = 71
    integer_83 = 83
    integer_84 = 84
    integer_85 = 85
    integer_86 = 86
    integer_87 = 87
    integer_88 = 88
    integer_89 = 89
    integer_90 = 90
    integer_92 = 92
    integer_93 = 93
    integer_95 = 95
    integer_96 = 96
    integer_97 = 97
    integer_98 = 98
    integer_99 = 99
    integer_101 = 101
    integer_102 = 102
    integer_103 = 103
    integer_106 = 106
    integer_107 = 107
    integer_108 = 108
    integer_109 = 109
    integer_110 = 110
    integer_111 = 111
    integer_112 = 112
    integer_113 = 113
    integer_114 = 114
    integer_118 = 118
    integer_121 = 121


class Url(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    port: int | None = None
    scheme: str | None = None
    path: str | None = None
    domain: str | None = None
    hostname: str | None = None
    query_string: str | None = None
    categories: list[str] | None = None
    category_ids: list[CategoryId] | None = None
    resource_type: str | None = None
    subdomain: str | None = None
    url_string: str | None = None


class TypeId20(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class VendorAttributes(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    severity: str | None = None
    severity_id: SeverityId | None = None


class FixCoverageId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class WebResource(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    data: Any | None = None
    name: str | None = None
    type: str | None = None
    desc: str | None = None
    uid: str | None = None
    labels: list[str] | None = None
    tags: list[KeyValueObject] | None = None
    created_time: int | None = None
    modified_time: int | None = None
    uid_alt: str | None = None
    url_string: str | None = None


class WinRegKey(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    path: str
    is_system: bool | None = None
    modified_time: int | None = None
    security_descriptor: str | None = None


class TypeId21(IntEnum):
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


class WinRegValue(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    data: Any | None = None
    name: str
    type: str | None = None
    path: str
    type_id: TypeId21 | None = None
    is_default: bool | None = None
    is_system: bool | None = None
    modified_time: int | None = None


class ServiceCategoryId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_99 = 99


class ServiceErrorControlId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_99 = 99


class ServiceStartTypeId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_99 = 99


class ServiceTypeId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_99 = 99


class WinWinService(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    version: str | None = None
    uid: str | None = None
    labels: list[str] | None = None
    tags: list[KeyValueObject] | None = None
    cmd_line: str | None = None
    load_order_group: str | None = None
    service_category: str | None = None
    service_category_id: ServiceCategoryId | None = None
    service_dependencies: list[str] | None = None
    service_error_control: str | None = None
    service_error_control_id: ServiceErrorControlId | None = None
    service_start_name: str | None = None
    service_start_type: str | None = None
    service_start_type_id: ServiceStartTypeId | None = None
    service_type: str | None = None
    service_type_id: ServiceTypeId | None = None


class Account(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    type: str | None = None
    uid: str | None = None
    labels: list[str] | None = None
    tags: list[KeyValueObject] | None = None
    type_id: TypeId | None = None


class Agent(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    type: str | None = None
    version: str | None = None
    uid: str | None = None
    type_id: TypeId2 | None = None
    policies: list[Policy] | None = None
    uid_alt: str | None = None
    vendor_name: str | None = None


class Assessment(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    desc: str | None = None
    uid: str | None = None
    category: str | None = None
    meets_criteria: bool
    policy: Policy | None = None


class Attack(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    version: str | None = None
    tactics: list[Tactic] | None = None
    technique: Technique | None = None
    mitigation: Mitigation | None = None
    sub_technique: SubTechnique | None = None
    tactic: Tactic | None = None


class AuthenticationToken(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type: str | None = None
    type_id: TypeId4 | None = None
    created_time: int | None = None
    encryption_details: EncryptionDetails | None = None
    expiration_time: int | None = None
    kerberos_flags: str | None = None
    is_renewable: bool | None = None


class Authorization(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    decision: str | None = None
    policy: Policy | None = None


class Certificate(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    version: str | None = None
    uid: str | None = None
    is_self_signed: bool | None = None
    subject: str | None = None
    issuer: str
    fingerprints: list[Fingerprint] | None = None
    created_time: int | None = None
    expiration_time: int | None = None
    sans: list[San] | None = None
    serial_number: str


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
    src_url: str | None = None
    vector_string: str | None = None
    vendor_name: str | None = None


class Database(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    size: int | None = None
    type: str | None = None
    desc: str | None = None
    uid: str | None = None
    groups: list[Group] | None = None
    type_id: TypeId5
    created_time: int | None = None
    modified_time: int | None = None


class DeviceHwInfo(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    uuid: str | None = None
    bios_date: str | None = None
    bios_manufacturer: str | None = None
    bios_ver: str | None = None
    chassis: str | None = None
    cpu_architecture: str | None = None
    cpu_architecture_id: CpuArchitectureId | None = None
    cpu_bits: int | None = None
    cpu_cores: int | None = None
    cpu_count: int | None = None
    cpu_speed: int | None = None
    cpu_type: str | None = None
    desktop_display: Display | None = None
    keyboard_info: KeyboardInfo | None = None
    ram_size: int | None = None
    serial_number: str | None = None
    vendor_name: str | None = None


class DigitalSignature(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    state: str | None = None
    digest: Fingerprint | None = None
    certificate: Certificate | None = None
    algorithm: str | None = None
    algorithm_id: AlgorithmId
    created_time: int | None = None
    developer_uid: str | None = None
    state_id: StateId | None = None


class Enrichment(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    data: Any
    name: str
    type: str | None = None
    value: str
    desc: str | None = None
    created_time: int | None = None
    provider: str | None = None
    reputation: Reputation | None = None
    short_desc: str | None = None
    src_url: str | None = None


class Graph(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    type: str | None = None
    nodes: list[Node]
    desc: str | None = None
    uid: str | None = None
    edges: list[Edge] | None = None
    is_directed: bool | None = None
    query_language: str | None = None
    query_language_id: QueryLanguageId | None = None


class HttpRequest(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    args: str | None = None
    version: str | None = None
    length: int | None = None
    uid: str | None = None
    url: Url | None = None
    body_length: int | None = None
    user_agent: str | None = None
    http_headers: list[HttpHeader] | None = None
    http_method: str | None = None
    referrer: str | None = None
    x_forwarded_for: list[str] | None = None


class Image(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    tag: str | None = None
    path: str | None = None
    uid: str
    labels: list[str] | None = None
    tags: list[KeyValueObject] | None = None


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
    avg_timespan: Timespan | None = None
    bulletin: str | None = None
    classification: str | None = None
    created_time: int | None = None
    install_state: str | None = None
    install_state_id: InstallStateId | None = None
    is_superseded: bool | None = None
    src_url: str | None = None


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
    community_uid: str | None = None
    direction_id: DirectionId
    flag_history: str | None = None
    protocol_num: int | None = None
    protocol_ver: str | None = None
    protocol_ver_id: ProtocolVerId | None = None
    tcp_flags: int | None = None


class Observable(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    type: str | None = None
    value: str | None = None
    type_id: TypeId14
    reputation: Reputation | None = None


class Observation(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    count: int | None = None
    value: str
    timespan: Timespan | None = None


class RelatedEvent(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    count: int | None = None
    type: str | None = None
    title: str | None = None
    product: Product | None = None
    desc: str | None = None
    uid: str
    severity: str | None = None
    tags: list[KeyValueObject] | None = None
    type_uid: int | None = None
    type_name: str | None = None
    observables: list[Observable] | None = None
    attacks: list[Attack] | None = None
    created_time: int | None = None
    first_seen_time: int | None = None
    kill_chain: list[KillChainPhase] | None = None
    last_seen_time: int | None = None
    modified_time: int | None = None
    product_uid: str | None = None
    severity_id: SeverityId | None = None
    traits: list[Trait] | None = None


class Remediation(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    desc: str
    references: list[str] | None = None
    cis_controls: list[CisControl] | None = None
    kb_article_list: list[KbArticle] | None = None
    kb_articles: list[str] | None = None


class Sso(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    uid: str | None = None
    protocol_name: str | None = None
    certificate: Certificate | None = None
    idle_timeout: int | None = None
    auth_protocol: str | None = None
    auth_protocol_id: AuthProtocolId | None = None
    created_time: int | None = None
    duration_mins: int | None = None
    login_endpoint: str | None = None
    logout_endpoint: str | None = None
    metadata_endpoint: str | None = None
    modified_time: int | None = None
    scopes: list[str] | None = None
    vendor_name: str | None = None


class Tls(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    version: str
    alert: int | None = None
    key_length: int | None = None
    cipher: str | None = None
    certificate: Certificate | None = None
    sni: str | None = None
    certificate_chain: list[str] | None = None
    client_ciphers: list[str] | None = None
    extension_list: list[TlsExtension] | None = None
    handshake_dur: int | None = None
    ja3_hash: Fingerprint | None = None
    ja3s_hash: Fingerprint | None = None
    sans: list[San] | None = None
    server_ciphers: list[str] | None = None
    tls_extension_list: list[TlsExtension] | None = None


class AffectedPackage(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    type: str | None = None
    version: str
    path: str | None = None
    uid: str | None = None
    hash: Fingerprint | None = None
    release: str | None = None
    epoch: int | None = None
    type_id: TypeId1 | None = None
    license: str | None = None
    remediation: Remediation | None = None
    architecture: str | None = None
    cpe_name: str | None = None
    fixed_in_version: str | None = None
    license_url: str | None = None
    package_manager: str | None = None
    package_manager_url: str | None = None
    purl: str | None = None
    src_url: str | None = None
    vendor_name: str | None = None


class Anomaly(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    observation_parameter: str
    observations: list[Observation]
    observation_type: str | None = None
    observed_pattern: str | None = None


class Baseline(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    observation_parameter: str
    observations: list[Observation]
    observation_type: str | None = None
    observed_pattern: str | None = None


class Compliance(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    control: str | None = None
    status: str | None = None
    desc: str | None = None
    category: str | None = None
    assessments: list[Assessment] | None = None
    checks: list[Check] | None = None
    compliance_references: list[KbArticle] | None = None
    compliance_standards: list[KbArticle] | None = None
    control_parameters: list[KeyValueObject] | None = None
    requirements: list[str] | None = None
    standards: list[str] | None = None
    status_code: str | None = None
    status_detail: str | None = None
    status_details: list[str] | None = None
    status_id: StatusId8 | None = None


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
    labels: list[str] | None = None
    tags: list[KeyValueObject] | None = None
    network_driver: str | None = None
    orchestrator: str | None = None
    pod_uuid: str | None = None


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
    related_cwes: list[Cwe] | None = None


class FindingInfo(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    title: str | None = None
    product: Product | None = None
    desc: str | None = None
    uid: str
    types: list[str] | None = None
    tags: list[KeyValueObject] | None = None
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
    related_events_count: int | None = None
    src_url: str | None = None
    uid_alt: str | None = None
    traits: list[Trait] | None = None


class Request(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    data: Any | None = None
    flags: list[str] | None = None
    uid: str
    containers: list[Container] | None = None


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


class Advisory(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    size: int | None = None
    os: Os | None = None
    title: str | None = None
    product: Product | None = None
    desc: str | None = None
    uid: str
    references: list[str] | None = None
    avg_timespan: Timespan | None = None
    bulletin: str | None = None
    classification: str | None = None
    created_time: int | None = None
    install_state: str | None = None
    install_state_id: InstallStateId | None = None
    is_superseded: bool | None = None
    modified_time: int | None = None
    related_cves: list[Cve] | None = None
    related_cwes: list[Cwe] | None = None
    src_url: str | None = None


class AnomalyAnalysis(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    analysis_targets: list[AnalysisTarget]
    anomalies: list[Anomaly]
    baselines: list[Baseline] | None = None


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


class DetectionFinding(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    malware: list[Malware] | None = None
    type_uid: TypeUid
    evidences: list[Evidences] | None = None
    confidence_score: int | None = None
    type_name: str | None = None
    impact: str | None = None
    device: Device | None = None
    message: str | None = None
    severity: str | None = None
    impact_id: ImpactId | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    malware_scan_info: MalwareScanInfo | None = None
    metadata: Metadata
    activity_id: ActivityId
    status_code: str | None = None
    is_alert: bool | None = None
    finding_info: FindingInfo
    category_uid: CategoryUid
    timezone_offset: int | None = None
    comment: str | None = None
    impact_score: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    confidence: str | None = None
    confidence_id: ConfidenceId | None = None
    anomaly_analyses: list[AnomalyAnalysis] | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    risk_level_id: RiskLevelId | None = None
    vulnerabilities: list[Vulnerability] | None = None
    remediation: Remediation | None = None
    unmapped: Object | None = None
    class_uid: ClassUid
    risk_score: int | None = None
    resources: list[ResourceDetails] | None = None
    category_name: str | None = None
    risk_details: str | None = None
    status_id: StatusId | None = None
    risk_level: str | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None
    vendor_attributes: VendorAttributes | None = None


class ComplianceFinding(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid1
    evidences: list[Evidences] | None = None
    confidence_score: int | None = None
    type_name: str | None = None
    device: Device | None = None
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId
    status_code: str | None = None
    finding_info: FindingInfo
    category_uid: CategoryUid
    timezone_offset: int | None = None
    comment: str | None = None
    compliance: Compliance
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    confidence: str | None = None
    confidence_id: ConfidenceId | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    resource: ResourceDetails | None = None
    remediation: Remediation | None = None
    unmapped: Object | None = None
    class_uid: ClassUid1
    resources: list[ResourceDetails] | None = None
    category_name: str | None = None
    status_id: StatusId | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None
    vendor_attributes: VendorAttributes | None = None


class Authentication(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid2
    service: Service | None = None
    auth_factors: list[AuthFactor] | None = None
    is_remote: bool | None = None
    auth_protocol_id: AuthProtocolId | None = None
    type_name: str | None = None
    http_response: HttpResponse | None = None
    message: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    severity: str | None = None
    certificate: Certificate | None = None
    observables: list[Observable] | None = None
    auth_protocol: str | None = None
    class_name: str | None = None
    http_request: HttpRequest | None = None
    metadata: Metadata
    activity_id: ActivityId2
    status_code: str | None = None
    category_uid: CategoryUid2
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    user: User
    raw_data: str | None = None
    actor: Actor | None = None
    session: Session | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    is_new_logon: bool | None = None
    logon_type_id: LogonTypeId | None = None
    unmapped: Object | None = None
    class_uid: ClassUid2
    category_name: str | None = None
    is_cleartext: bool | None = None
    status_id: StatusId2 | None = None
    is_mfa: bool | None = None
    authentication_token: AuthenticationToken | None = None
    logon_type: str | None = None
    severity_id: SeverityId
    logon_process: Process | None = None
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class AccountChange(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid3
    type_name: str | None = None
    http_response: HttpResponse | None = None
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    http_request: HttpRequest | None = None
    metadata: Metadata
    policies: list[Policy] | None = None
    activity_id: ActivityId3
    status_code: str | None = None
    category_uid: CategoryUid2
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    user: User
    raw_data: str | None = None
    actor: Actor | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    user_result: User | None = None
    unmapped: Object | None = None
    class_uid: ClassUid3
    category_name: str | None = None
    status_id: StatusId2 | None = None
    policy: Policy | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class PatchState(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid4
    type_name: str | None = None
    device: Device
    message: str | None = None
    severity: str | None = None
    kb_article_list: list[KbArticle] | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId4
    status_code: str | None = None
    category_uid: CategoryUid4
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    class_uid: ClassUid4
    category_name: str | None = None
    status_id: StatusId2 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class ApiActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint
    type_uid: TypeUid5
    type_name: str | None = None
    http_response: HttpResponse | None = None
    message: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    severity: str | None = None
    api: Api
    observables: list[Observable] | None = None
    class_name: str | None = None
    http_request: HttpRequest | None = None
    metadata: Metadata
    activity_id: ActivityId5
    status_code: str | None = None
    category_uid: CategoryUid5
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    actor: Actor
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    class_uid: ClassUid5
    resources: list[ResourceDetails] | None = None
    category_name: str | None = None
    status_id: StatusId2 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class WebResourcesActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid6
    type_name: str | None = None
    http_response: HttpResponse | None = None
    message: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    http_request: HttpRequest | None = None
    metadata: Metadata
    activity_id: ActivityId6
    status_code: str | None = None
    category_uid: CategoryUid5
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    web_resources_result: list[WebResource] | None = None
    tls: Tls | None = None
    class_uid: ClassUid6
    category_name: str | None = None
    web_resources: list[WebResource]
    status_id: StatusId2 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class FileHosting(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint
    type_uid: TypeUid7
    share_type_id: ShareTypeId | None = None
    file_result: File | None = None
    type_name: str | None = None
    message: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    severity: str | None = None
    expiration_time: int | None = None
    observables: list[Observable] | None = None
    file: File
    share: str | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId7
    status_code: str | None = None
    category_uid: CategoryUid5
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    actor: Actor
    status_detail: str | None = None
    count: int | None = None
    access_mask: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    share_type: str | None = None
    class_uid: ClassUid7
    category_name: str | None = None
    connection_info: NetworkConnectionInfo | None = None
    status_id: StatusId2 | None = None
    access_list: list[str] | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None
    access_result: Any | None = None


class Actor(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    process: Process | None = None
    session: Session | None = None
    user: User | None = None
    app_name: str | None = None
    app_uid: str | None = None
    authorizations: list[Authorization] | None = None
    idp: Idp | None = None
    invoked_by: str | None = None


class AffectedCode(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    owner: User | None = None
    file: File
    end_line: int | None = None
    end_column: int | None = None
    remediation: Remediation | None = None
    rule: Rule | None = None
    start_column: int | None = None
    start_line: int | None = None


class AuthFactor(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    device: Device | None = None
    email_addr: str | None = None
    factor_type: str | None = None
    factor_type_id: FactorTypeId
    is_hotp: bool | None = None
    is_totp: bool | None = None
    phone_number: str | None = None
    provider: str | None = None
    security_questions: list[str] | None = None


class Databucket(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    desc: str | None = None
    is_backed_up: bool | None = None
    hostname: str | None = None
    size: int | None = None
    labels: list[str] | None = None
    file: File | None = None
    agent_list: list[Agent] | None = None
    uid: str | None = None
    criticality: str | None = None
    owner: User | None = None
    data: Any | None = None
    group: Group | None = None
    tags: list[KeyValueObject] | None = None
    type_id: TypeId6
    ip: str | None = None
    created_time: int | None = None
    is_public: bool | None = None
    is_encrypted: bool | None = None
    groups: list[Group] | None = None
    modified_time: int | None = None
    version: str | None = None
    namespace: str | None = None
    name: str | None = None
    uid_alt: str | None = None
    resource_relationship: Graph | None = None
    type: str | None = None
    encryption_details: EncryptionDetails | None = None


class Device(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    desc: str | None = None
    instance_uid: str | None = None
    is_backed_up: bool | None = None
    hostname: str | None = None
    vlan_uid: str | None = None
    hypervisor: str | None = None
    hw_info: DeviceHwInfo | None = None
    agent_list: list[Agent] | None = None
    uid: str | None = None
    model: str | None = None
    owner: User | None = None
    region: str | None = None
    image: Image | None = None
    os: Os | None = None
    network_interfaces: list[NetworkInterface] | None = None
    first_seen_time: int | None = None
    iccid: str | None = None
    type_id: TypeId7
    ip: str | None = None
    meid: str | None = None
    boot_uid: str | None = None
    vendor_name: str | None = None
    eid: str | None = None
    subnet: str | None = None
    mac: str | None = None
    created_time: int | None = None
    imei: str | None = None
    groups: list[Group] | None = None
    imei_list: list[str] | None = None
    domain: str | None = None
    zone: str | None = None
    is_trusted: bool | None = None
    is_compliant: bool | None = None
    modified_time: int | None = None
    risk_level_id: RiskLevelId | None = None
    org: Organization | None = None
    is_personal: bool | None = None
    is_supervised: bool | None = None
    interface_uid: str | None = None
    last_seen_time: int | None = None
    risk_score: int | None = None
    is_mobile_account_active: bool | None = None
    name: str | None = None
    interface_name: str | None = None
    uid_alt: str | None = None
    is_shared: bool | None = None
    is_managed: bool | None = None
    autoscale_uid: str | None = None
    os_machine_uuid: str | None = None
    type: str | None = None
    subnet_uid: str | None = None
    risk_level: str | None = None
    udid: str | None = None
    vpc_uid: str | None = None
    boot_time: int | None = None
    location: Location | None = None


class Email(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    size: int | None = None
    uid: str | None = None
    files: list[File] | None = None
    from_: str | None = Field(None, alias='from')
    cc: list[str] | None = None
    to: list[str] | None = None
    subject: str | None = None
    cc_mailboxes: list[str] | None = None
    delivered_to: str | None = None
    delivered_to_list: list[str] | None = None
    from_mailbox: str | None = None
    http_headers: list[HttpHeader] | None = None
    is_read: bool | None = None
    message_uid: str | None = None
    raw_header: str | None = None
    reply_to: str | None = None
    reply_to_mailboxes: list[str] | None = None
    smtp_from: str | None = None
    smtp_to: list[str] | None = None
    to_mailboxes: list[str] | None = None
    urls: list[Url] | None = None
    x_originating_ip: list[str] | None = None


class Evidences(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    data: Any | None = None
    http_response: HttpResponse | None = None
    http_request: HttpRequest | None = None
    name: str | None = None
    process: Process | None = None
    file: File | None = None
    user: User | None = None
    script: Script | None = None
    device: Device | None = None
    uid: str | None = None
    query: DnsQuery | None = None
    connection_info: NetworkConnectionInfo | None = None
    url: Url | None = None
    email: Email | None = None
    tls: Tls | None = None
    api: Api | None = None
    resources: list[ResourceDetails] | None = None
    actor: Actor | None = None
    container: Container | None = None
    database: Database | None = None
    databucket: Databucket | None = None
    dst_endpoint: NetworkEndpoint | None = None
    ja4_fingerprint_list: list[Ja4Fingerprint] | None = None
    job: Job | None = None
    src_endpoint: NetworkEndpoint | None = None
    verdict: str | None = None
    verdict_id: VerdictId | None = None
    reg_key: WinRegKey | None = None
    reg_value: WinRegValue | None = None
    win_service: WinWinService | None = None


class File(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    desc: str | None = None
    confidentiality: str | None = None
    uri: str | None = None
    modifier: User | None = None
    size: int | None = None
    attributes: int | None = None
    uid: str | None = None
    owner: User | None = None
    tags: list[KeyValueObject] | None = None
    type_id: TypeId8
    accessed_time: int | None = None
    company_name: str | None = None
    product: Product | None = None
    volume: str | None = None
    parent_folder: str | None = None
    created_time: int | None = None
    path: str | None = None
    is_encrypted: bool | None = None
    hashes: list[Fingerprint] | None = None
    is_deleted: bool | None = None
    modified_time: int | None = None
    mime_type: str | None = None
    version: str | None = None
    ext: str | None = None
    xattributes: Object | None = None
    signature: DigitalSignature | None = None
    name: str
    url: Url | None = None
    drive_type: str | None = None
    security_descriptor: str | None = None
    creator: User | None = None
    accessor: User | None = None
    internal_name: str | None = None
    type: str | None = None
    drive_type_id: DriveTypeId | None = None
    confidentiality_id: ConfidentialityId | None = None
    encryption_details: EncryptionDetails | None = None
    is_system: bool | None = None


class Idp(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    state: str | None = None
    domain: str | None = None
    uid: str | None = None
    protocol_name: str | None = None
    issuer: str | None = None
    fingerprint: Fingerprint | None = None
    auth_factors: list[AuthFactor] | None = None
    has_mfa: bool | None = None
    scim: Scim | None = None
    sso: Sso | None = None
    state_id: StateId1 | None = None
    tenant_uid: str | None = None
    url_string: str | None = None


class Job(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    file: File
    user: User | None = None
    desc: str | None = None
    cmd_line: str | None = None
    created_time: int | None = None
    last_run_time: int | None = None
    next_run_time: int | None = None
    run_state: str | None = None
    run_state_id: RunStateId | None = None


class LdapPerson(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    location: Location | None = None
    labels: list[str] | None = None
    manager: User | None = None
    tags: list[KeyValueObject] | None = None
    cost_center: str | None = None
    created_time: int | None = None
    deleted_time: int | None = None
    display_name: str | None = None
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
    phone_number: str | None = None
    surname: str | None = None


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
    event_uid: str | None = None
    log_name: str | None = None
    log_provider: str | None = None
    log_version: str | None = None
    logged_time: int | None = None
    transmit_time: int | None = None


class Malware(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    path: str | None = None
    uid: str | None = None
    files: list[File] | None = None
    severity: str | None = None
    classification_ids: list[ClassificationId]
    classifications: list[str] | None = None
    cves: list[Cve] | None = None
    num_infected: int | None = None
    provider: str | None = None
    severity_id: SeverityId | None = None


class Metadata(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    version: str
    debug: list[str] | None = None
    extension: Extension | None = None
    product: Product
    uid: str | None = None
    extensions: list[Extension] | None = None
    labels: list[str] | None = None
    log_level: str | None = None
    sequence: int | None = None
    tags: list[KeyValueObject] | None = None
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
    transformation_info_list: list[TransformationInfo] | None = None


class NetworkEndpoint(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    owner: User | None = None
    port: int | None = None
    type: str | None = None
    os: Os | None = None
    domain: str | None = None
    ip: str | None = None
    location: Location | None = None
    uid: str | None = None
    hostname: str | None = None
    mac: str | None = None
    type_id: TypeId11 | None = None
    agent_list: list[Agent] | None = None
    autonomous_system: AutonomousSystem | None = None
    hw_info: DeviceHwInfo | None = None
    instance_uid: str | None = None
    interface_name: str | None = None
    interface_uid: str | None = None
    intermediate_ips: list[str] | None = None
    isp: str | None = None
    isp_org: str | None = None
    proxy_endpoint: NetworkProxy | None = None
    subnet_uid: str | None = None
    svc_name: str | None = None
    vlan_uid: str | None = None
    vpc_uid: str | None = None
    zone: str | None = None


class NetworkProxy(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    owner: User | None = None
    port: int | None = None
    type: str | None = None
    os: Os | None = None
    domain: str | None = None
    ip: str | None = None
    location: Location | None = None
    uid: str | None = None
    hostname: str | None = None
    mac: str | None = None
    type_id: TypeId13 | None = None
    agent_list: list[Agent] | None = None
    autonomous_system: AutonomousSystem | None = None
    hw_info: DeviceHwInfo | None = None
    instance_uid: str | None = None
    interface_name: str | None = None
    interface_uid: str | None = None
    intermediate_ips: list[str] | None = None
    isp: str | None = None
    isp_org: str | None = None
    proxy_endpoint: NetworkProxy | None = None
    subnet_uid: str | None = None
    svc_name: str | None = None
    vlan_uid: str | None = None
    vpc_uid: str | None = None
    zone: str | None = None


class Process(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    pid: int | None = None
    session: Session | None = None
    file: File | None = None
    user: User | None = None
    path: str | None = None
    tid: int | None = None
    uid: str | None = None
    loaded_modules: list[str] | None = None
    ancestry: list[ProcessEntity] | None = None
    cmd_line: str | None = None
    cpid: str | None = None
    created_time: int | None = None
    environment_variables: list[EnvironmentVariable] | None = None
    integrity: str | None = None
    integrity_id: IntegrityId | None = None
    lineage: list[str] | None = None
    parent_process: Process | None = None
    sandbox: str | None = None
    terminated_time: int | None = None
    working_directory: str | None = None
    xattributes: Object | None = None


class ResourceDetails(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    data: Any | None = None
    name: str | None = None
    owner: User | None = None
    type: str | None = None
    version: str | None = None
    ip: str | None = None
    group: Group | None = None
    uid: str | None = None
    hostname: str | None = None
    labels: list[str] | None = None
    namespace: str | None = None
    tags: list[KeyValueObject] | None = None
    agent_list: list[Agent] | None = None
    created_time: int | None = None
    criticality: str | None = None
    is_backed_up: bool | None = None
    modified_time: int | None = None
    resource_relationship: Graph | None = None
    uid_alt: str | None = None


class Script(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    type: str | None = None
    file: File | None = None
    uid: str | None = None
    type_id: TypeId17
    hashes: list[Fingerprint] | None = None
    parent_uid: str | None = None
    script_content: LongString


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
    full_name: str | None = None
    type_id: TypeId20 | None = None
    account: Account | None = None
    credential_uid: str | None = None
    display_name: str | None = None
    email_addr: str | None = None
    forward_addr: str | None = None
    has_mfa: bool | None = None
    ldap_person: LdapPerson | None = None
    phone_number: str | None = None
    risk_level: str | None = None
    risk_level_id: RiskLevelId | None = None
    risk_score: int | None = None
    uid_alt: str | None = None


class Vulnerability(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    title: str | None = None
    desc: str | None = None
    category: str | None = None
    references: list[str] | None = None
    severity: str | None = None
    remediation: Remediation | None = None
    advisory: Advisory | None = None
    affected_code: list[AffectedCode] | None = None
    affected_packages: list[AffectedPackage] | None = None
    cve: Cve | None = None
    cwe: Cwe | None = None
    dependency_chain: str | None = None
    exploit_last_seen_time: int | None = None
    exploit_ref_url: str | None = None
    exploit_requirement: str | None = None
    exploit_type: str | None = None
    first_seen_time: int | None = None
    fix_available: bool | None = None
    fix_coverage: str | None = None
    fix_coverage_id: FixCoverageId | None = None
    is_exploit_available: bool | None = None
    is_fix_available: bool | None = None
    kb_article_list: list[KbArticle] | None = None
    kb_articles: list[str] | None = None
    last_seen_time: int | None = None
    packages: list[Package] | None = None
    related_vulnerabilities: list[str] | None = None
    vendor_name: str | None = None


Analytic.model_rebuild()
DetectionFinding.model_rebuild()
ComplianceFinding.model_rebuild()
Authentication.model_rebuild()
AccountChange.model_rebuild()
PatchState.model_rebuild()
ApiActivity.model_rebuild()
WebResourcesActivity.model_rebuild()
FileHosting.model_rebuild()
Actor.model_rebuild()
AffectedCode.model_rebuild()
AuthFactor.model_rebuild()
Databucket.model_rebuild()
Device.model_rebuild()
Email.model_rebuild()
Evidences.model_rebuild()
File.model_rebuild()
Job.model_rebuild()
LdapPerson.model_rebuild()
NetworkEndpoint.model_rebuild()
NetworkProxy.model_rebuild()
Process.model_rebuild()
ResourceDetails.model_rebuild()
