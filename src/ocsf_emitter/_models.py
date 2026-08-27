"""Generated OCSF models for schema version 1.5.0.

DO NOT EDIT BY HAND. Regenerate with:
    uv run --extra codegen python scripts/gen_models.py 1.5.0

Source: OCSF 1.5.0 metaschema (ocsf-lib), classes:
    - file_activity
    - kernel_extension_activity
    - kernel_activity
    - memory_activity
    - module_activity
    - scheduled_job_activity
    - process_activity
    - event_log_actvity
    - script_activity
    - vulnerability_finding
    - compliance_finding
    - detection_finding
    - incident_finding
    - data_security_finding
    - application_security_posture_finding
    - account_change
    - authentication
    - authorize_session
    - entity_management
    - user_access
    - group_management
    - network_activity
    - http_activity
    - dns_activity
    - dhcp_activity
    - rdp_activity
    - smb_activity
    - ssh_activity
    - ftp_activity
    - email_activity
    - ntp_activity
    - tunnel_activity
    - inventory_info
    - user_inventory
    - patch_state
    - device_config_state_change
    - software_info
    - osint_inventory_info
    - cloud_resources_inventory_info
    - evidence_info
    - web_resources_activity
    - application_lifecycle
    - api_activity
    - datastore_activity
    - file_hosting
    - scan_activity
    - application_error
    - remediation_activity
    - file_remediation_activity
    - process_remediation_activity
    - network_remediation_activity
    - drone_flights_activity
    - airborne_broadcast_activity
converted to JSON Schema (base classes, profiles excluded).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field
from enum import IntEnum
from typing import Any


class OcsfSupportedClasses(BaseModel):
    pass


class TypeUid(IntEnum):
    integer_100100 = 100100
    integer_100101 = 100101
    integer_100102 = 100102
    integer_100103 = 100103
    integer_100104 = 100104
    integer_100105 = 100105
    integer_100106 = 100106
    integer_100107 = 100107
    integer_100108 = 100108
    integer_100109 = 100109
    integer_100110 = 100110
    integer_100111 = 100111
    integer_100112 = 100112
    integer_100113 = 100113
    integer_100114 = 100114
    integer_100199 = 100199


class ActivityId(IntEnum):
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
    integer_99 = 99


class CategoryUid(IntEnum):
    integer_1 = 1


class ClassUid(IntEnum):
    integer_1001 = 1001


class StatusId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
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
    integer_100200 = 100200
    integer_100201 = 100201
    integer_100202 = 100202
    integer_100299 = 100299


class ActivityId1(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_99 = 99


class ClassUid1(IntEnum):
    integer_1002 = 1002


class TypeUid2(IntEnum):
    integer_100300 = 100300
    integer_100301 = 100301
    integer_100302 = 100302
    integer_100303 = 100303
    integer_100304 = 100304
    integer_100399 = 100399


class ActivityId2(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_99 = 99


class ClassUid2(IntEnum):
    integer_1003 = 1003


class TypeUid3(IntEnum):
    integer_100400 = 100400
    integer_100401 = 100401
    integer_100402 = 100402
    integer_100403 = 100403
    integer_100404 = 100404
    integer_100405 = 100405
    integer_100406 = 100406
    integer_100407 = 100407
    integer_100408 = 100408
    integer_100409 = 100409
    integer_100499 = 100499


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
    integer_99 = 99


class ClassUid3(IntEnum):
    integer_1004 = 1004


class TypeUid4(IntEnum):
    integer_100500 = 100500
    integer_100501 = 100501
    integer_100502 = 100502
    integer_100599 = 100599


class ActivityId4(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_99 = 99


class ClassUid4(IntEnum):
    integer_1005 = 1005


class TypeUid5(IntEnum):
    integer_100600 = 100600
    integer_100601 = 100601
    integer_100602 = 100602
    integer_100603 = 100603
    integer_100604 = 100604
    integer_100605 = 100605
    integer_100606 = 100606
    integer_100699 = 100699


class ActivityId5(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_99 = 99


class ClassUid5(IntEnum):
    integer_1006 = 1006


class TypeUid6(IntEnum):
    integer_100700 = 100700
    integer_100701 = 100701
    integer_100702 = 100702
    integer_100703 = 100703
    integer_100704 = 100704
    integer_100705 = 100705
    integer_100799 = 100799


class ActivityId6(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_99 = 99


class InjectionTypeId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class ClassUid6(IntEnum):
    integer_1007 = 1007


class TypeUid7(IntEnum):
    integer_100800 = 100800
    integer_100801 = 100801
    integer_100802 = 100802
    integer_100803 = 100803
    integer_100804 = 100804
    integer_100805 = 100805
    integer_100806 = 100806
    integer_100807 = 100807
    integer_100808 = 100808
    integer_100809 = 100809
    integer_100810 = 100810
    integer_100899 = 100899


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
    integer_99 = 99


class ClassUid7(IntEnum):
    integer_1008 = 1008


class LogTypeId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_99 = 99


class TypeUid8(IntEnum):
    integer_100900 = 100900
    integer_100901 = 100901
    integer_100999 = 100999


class ActivityId8(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_99 = 99


class ClassUid8(IntEnum):
    integer_1009 = 1009


class TypeUid9(IntEnum):
    integer_200200 = 200200
    integer_200201 = 200201
    integer_200202 = 200202
    integer_200203 = 200203
    integer_200299 = 200299


class ActivityId9(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class CategoryUid9(IntEnum):
    integer_2 = 2


class ConfidenceId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class ClassUid9(IntEnum):
    integer_2002 = 2002


class StatusId9(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_99 = 99


class TypeUid10(IntEnum):
    integer_200300 = 200300
    integer_200301 = 200301
    integer_200302 = 200302
    integer_200303 = 200303
    integer_200399 = 200399


class ClassUid10(IntEnum):
    integer_2003 = 2003


class TypeUid11(IntEnum):
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


class RiskLevelId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_99 = 99


class ClassUid11(IntEnum):
    integer_2004 = 2004


class TypeUid12(IntEnum):
    integer_200500 = 200500
    integer_200501 = 200501
    integer_200502 = 200502
    integer_200503 = 200503
    integer_200599 = 200599


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


class ClassUid12(IntEnum):
    integer_2005 = 2005


class PriorityId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_99 = 99


class TypeUid13(IntEnum):
    integer_200600 = 200600
    integer_200601 = 200601
    integer_200602 = 200602
    integer_200603 = 200603
    integer_200604 = 200604
    integer_200699 = 200699


class ActivityId13(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_99 = 99


class ClassUid13(IntEnum):
    integer_2006 = 2006


class TypeUid14(IntEnum):
    integer_200700 = 200700
    integer_200701 = 200701
    integer_200702 = 200702
    integer_200703 = 200703
    integer_200799 = 200799


class ActivityId14(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class ClassUid14(IntEnum):
    integer_2007 = 2007


class TypeUid15(IntEnum):
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


class ActivityId15(IntEnum):
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


class CategoryUid15(IntEnum):
    integer_3 = 3


class ClassUid15(IntEnum):
    integer_3001 = 3001


class StatusId15(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_99 = 99


class TypeUid16(IntEnum):
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


class ActivityId16(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_99 = 99


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


class ClassUid16(IntEnum):
    integer_3002 = 3002


class TypeUid17(IntEnum):
    integer_300300 = 300300
    integer_300301 = 300301
    integer_300302 = 300302
    integer_300399 = 300399


class ActivityId17(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_99 = 99


class ClassUid17(IntEnum):
    integer_3003 = 3003


class TypeUid18(IntEnum):
    integer_300400 = 300400
    integer_300401 = 300401
    integer_300402 = 300402
    integer_300403 = 300403
    integer_300404 = 300404
    integer_300405 = 300405
    integer_300406 = 300406
    integer_300407 = 300407
    integer_300408 = 300408
    integer_300409 = 300409
    integer_300410 = 300410
    integer_300411 = 300411
    integer_300412 = 300412
    integer_300413 = 300413
    integer_300499 = 300499


class ActivityId18(IntEnum):
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
    integer_99 = 99


class ClassUid18(IntEnum):
    integer_3004 = 3004


class TypeUid19(IntEnum):
    integer_300500 = 300500
    integer_300501 = 300501
    integer_300502 = 300502
    integer_300599 = 300599


class ActivityId19(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_99 = 99


class ClassUid19(IntEnum):
    integer_3005 = 3005


class TypeUid20(IntEnum):
    integer_300600 = 300600
    integer_300601 = 300601
    integer_300602 = 300602
    integer_300603 = 300603
    integer_300604 = 300604
    integer_300605 = 300605
    integer_300606 = 300606
    integer_300699 = 300699


class ActivityId20(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_99 = 99


class ClassUid20(IntEnum):
    integer_3006 = 3006


class TypeUid21(IntEnum):
    integer_400100 = 400100
    integer_400101 = 400101
    integer_400102 = 400102
    integer_400103 = 400103
    integer_400104 = 400104
    integer_400105 = 400105
    integer_400106 = 400106
    integer_400107 = 400107
    integer_400199 = 400199


class ActivityId21(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_7 = 7
    integer_99 = 99


class CategoryUid21(IntEnum):
    integer_4 = 4


class ClassUid21(IntEnum):
    integer_4001 = 4001


class TypeUid22(IntEnum):
    integer_400200 = 400200
    integer_400201 = 400201
    integer_400202 = 400202
    integer_400203 = 400203
    integer_400204 = 400204
    integer_400205 = 400205
    integer_400206 = 400206
    integer_400207 = 400207
    integer_400208 = 400208
    integer_400299 = 400299


class ActivityId22(IntEnum):
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


class ClassUid22(IntEnum):
    integer_4002 = 4002


class TypeUid23(IntEnum):
    integer_400300 = 400300
    integer_400301 = 400301
    integer_400302 = 400302
    integer_400306 = 400306
    integer_400399 = 400399


class ActivityId23(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_6 = 6
    integer_99 = 99


class RcodeId(IntEnum):
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
    integer_99 = 99


class ClassUid23(IntEnum):
    integer_4003 = 4003


class TypeUid24(IntEnum):
    integer_400400 = 400400
    integer_400401 = 400401
    integer_400402 = 400402
    integer_400403 = 400403
    integer_400404 = 400404
    integer_400405 = 400405
    integer_400406 = 400406
    integer_400407 = 400407
    integer_400408 = 400408
    integer_400409 = 400409
    integer_400499 = 400499


class ActivityId24(IntEnum):
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


class ClassUid24(IntEnum):
    integer_4004 = 4004


class TypeUid25(IntEnum):
    integer_400500 = 400500
    integer_400501 = 400501
    integer_400502 = 400502
    integer_400503 = 400503
    integer_400504 = 400504
    integer_400505 = 400505
    integer_400506 = 400506
    integer_400599 = 400599


class ActivityId25(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_99 = 99


class ClassUid25(IntEnum):
    integer_4005 = 4005


class TypeUid26(IntEnum):
    integer_400600 = 400600
    integer_400601 = 400601
    integer_400602 = 400602
    integer_400603 = 400603
    integer_400604 = 400604
    integer_400605 = 400605
    integer_400606 = 400606
    integer_400699 = 400699


class ShareTypeId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class ClassUid26(IntEnum):
    integer_4006 = 4006


class TypeUid27(IntEnum):
    integer_400700 = 400700
    integer_400701 = 400701
    integer_400702 = 400702
    integer_400703 = 400703
    integer_400704 = 400704
    integer_400705 = 400705
    integer_400706 = 400706
    integer_400707 = 400707
    integer_400799 = 400799


class AuthTypeId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_99 = 99


class ActivityId27(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_7 = 7
    integer_99 = 99


class ClassUid27(IntEnum):
    integer_4007 = 4007


class TypeUid28(IntEnum):
    integer_400800 = 400800
    integer_400801 = 400801
    integer_400802 = 400802
    integer_400803 = 400803
    integer_400804 = 400804
    integer_400805 = 400805
    integer_400806 = 400806
    integer_400899 = 400899


class ActivityId28(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_99 = 99


class ClassUid28(IntEnum):
    integer_4008 = 4008


class TypeUid29(IntEnum):
    integer_400900 = 400900
    integer_400901 = 400901
    integer_400902 = 400902
    integer_400903 = 400903
    integer_400904 = 400904
    integer_400999 = 400999


class DirectionId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class ActivityId29(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_99 = 99


class ClassUid29(IntEnum):
    integer_4009 = 4009


class TypeUid30(IntEnum):
    integer_401300 = 401300
    integer_401301 = 401301
    integer_401302 = 401302
    integer_401303 = 401303
    integer_401304 = 401304
    integer_401305 = 401305
    integer_401306 = 401306
    integer_401307 = 401307
    integer_401399 = 401399


class ActivityId30(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_7 = 7
    integer_99 = 99


class StratumId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_16 = 16
    integer_17 = 17
    integer_99 = 99


class ClassUid30(IntEnum):
    integer_4013 = 4013


class TypeUid31(IntEnum):
    integer_401400 = 401400
    integer_401401 = 401401
    integer_401402 = 401402
    integer_401403 = 401403
    integer_401499 = 401499


class ActivityId31(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class TunnelTypeId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_99 = 99


class ClassUid31(IntEnum):
    integer_4014 = 4014


class TypeUid32(IntEnum):
    integer_500100 = 500100
    integer_500101 = 500101
    integer_500102 = 500102
    integer_500199 = 500199


class ActivityId32(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_99 = 99


class CategoryUid32(IntEnum):
    integer_5 = 5


class ClassUid32(IntEnum):
    integer_5001 = 5001


class TypeUid33(IntEnum):
    integer_500300 = 500300
    integer_500301 = 500301
    integer_500302 = 500302
    integer_500399 = 500399


class ClassUid33(IntEnum):
    integer_5003 = 5003


class TypeUid34(IntEnum):
    integer_500400 = 500400
    integer_500401 = 500401
    integer_500402 = 500402
    integer_500499 = 500499


class ClassUid34(IntEnum):
    integer_5004 = 5004


class TypeUid35(IntEnum):
    integer_501900 = 501900
    integer_501901 = 501901
    integer_501902 = 501902
    integer_501999 = 501999


class SecurityLevelId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class ClassUid35(IntEnum):
    integer_5019 = 5019


class PrevSecurityLevelId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class StateId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_99 = 99


class TypeUid36(IntEnum):
    integer_502000 = 502000
    integer_502001 = 502001
    integer_502002 = 502002
    integer_502099 = 502099


class ClassUid36(IntEnum):
    integer_5020 = 5020


class TypeUid37(IntEnum):
    integer_502100 = 502100
    integer_502101 = 502101
    integer_502102 = 502102
    integer_502199 = 502199


class ClassUid37(IntEnum):
    integer_5021 = 5021


class TypeUid38(IntEnum):
    integer_502300 = 502300
    integer_502301 = 502301
    integer_502302 = 502302
    integer_502399 = 502399


class ClassUid38(IntEnum):
    integer_5023 = 5023


class TypeUid39(IntEnum):
    integer_504000 = 504000
    integer_504001 = 504001
    integer_504099 = 504099


class QueryResultId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_99 = 99


class ActivityId39(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_99 = 99


class ClassUid39(IntEnum):
    integer_5040 = 5040


class TypeUid40(IntEnum):
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


class ActivityId40(IntEnum):
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


class CategoryUid40(IntEnum):
    integer_6 = 6


class ClassUid40(IntEnum):
    integer_6001 = 6001


class TypeUid41(IntEnum):
    integer_600200 = 600200
    integer_600201 = 600201
    integer_600202 = 600202
    integer_600203 = 600203
    integer_600204 = 600204
    integer_600205 = 600205
    integer_600206 = 600206
    integer_600207 = 600207
    integer_600208 = 600208
    integer_600299 = 600299


class ClassUid41(IntEnum):
    integer_6002 = 6002


class TypeUid42(IntEnum):
    integer_600300 = 600300
    integer_600301 = 600301
    integer_600302 = 600302
    integer_600303 = 600303
    integer_600304 = 600304
    integer_600399 = 600399


class ActivityId42(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_99 = 99


class ClassUid42(IntEnum):
    integer_6003 = 6003


class TypeUid43(IntEnum):
    integer_600500 = 600500
    integer_600501 = 600501
    integer_600502 = 600502
    integer_600503 = 600503
    integer_600504 = 600504
    integer_600505 = 600505
    integer_600506 = 600506
    integer_600507 = 600507
    integer_600508 = 600508
    integer_600509 = 600509
    integer_600510 = 600510
    integer_600599 = 600599


class ActivityId43(IntEnum):
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


class TypeId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class ClassUid43(IntEnum):
    integer_6005 = 6005


class TypeUid44(IntEnum):
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


class ActivityId44(IntEnum):
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


class ClassUid44(IntEnum):
    integer_6006 = 6006


class TypeUid45(IntEnum):
    integer_600700 = 600700
    integer_600701 = 600701
    integer_600702 = 600702
    integer_600703 = 600703
    integer_600704 = 600704
    integer_600705 = 600705
    integer_600706 = 600706
    integer_600707 = 600707
    integer_600708 = 600708
    integer_600709 = 600709
    integer_600710 = 600710
    integer_600799 = 600799


class ActivityId45(IntEnum):
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


class ClassUid45(IntEnum):
    integer_6007 = 6007


class TypeUid46(IntEnum):
    integer_600800 = 600800
    integer_600801 = 600801
    integer_600802 = 600802
    integer_600899 = 600899


class ActivityId46(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_99 = 99


class ClassUid46(IntEnum):
    integer_6008 = 6008


class TypeUid47(IntEnum):
    integer_700100 = 700100
    integer_700101 = 700101
    integer_700102 = 700102
    integer_700103 = 700103
    integer_700104 = 700104
    integer_700105 = 700105
    integer_700199 = 700199


class ActivityId47(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_99 = 99


class CategoryUid47(IntEnum):
    integer_7 = 7


class ClassUid47(IntEnum):
    integer_7001 = 7001


class StatusId47(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_99 = 99


class TypeUid48(IntEnum):
    integer_700200 = 700200
    integer_700201 = 700201
    integer_700202 = 700202
    integer_700203 = 700203
    integer_700204 = 700204
    integer_700205 = 700205
    integer_700299 = 700299


class ClassUid48(IntEnum):
    integer_7002 = 7002


class TypeUid49(IntEnum):
    integer_700300 = 700300
    integer_700301 = 700301
    integer_700302 = 700302
    integer_700303 = 700303
    integer_700304 = 700304
    integer_700305 = 700305
    integer_700399 = 700399


class ClassUid49(IntEnum):
    integer_7003 = 7003


class TypeUid50(IntEnum):
    integer_700400 = 700400
    integer_700401 = 700401
    integer_700402 = 700402
    integer_700403 = 700403
    integer_700404 = 700404
    integer_700405 = 700405
    integer_700499 = 700499


class ClassUid50(IntEnum):
    integer_7004 = 7004


class TypeUid51(IntEnum):
    integer_800100 = 800100
    integer_800101 = 800101
    integer_800102 = 800102
    integer_800199 = 800199


class ActivityId51(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_99 = 99


class CategoryUid51(IntEnum):
    integer_8 = 8


class ClassUid51(IntEnum):
    integer_8001 = 8001


class TypeUid52(IntEnum):
    integer_800200 = 800200
    integer_800201 = 800201
    integer_800202 = 800202
    integer_800299 = 800299


class ClassUid52(IntEnum):
    integer_8002 = 8002


class StatusId52(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_99 = 99


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


class TypeId2(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_99 = 99


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
    integer_99 = 99


class AnalysisTarget(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    type: str | None = None


class TypeId4(IntEnum):
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
    type_id: TypeId4
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


class TypeId5(IntEnum):
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


class Campaign(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str


class StatusId53(IntEnum):
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
    status_id: StatusId53 | None = None


class CisControl(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    version: str | None = None
    desc: str | None = None


class ClassifierDetails(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    type: str
    uid: str | None = None


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


class CategoryId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
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


class DataLifecycleStateId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class DetectionSystemId(IntEnum):
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


class TypeId6(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_99 = 99


class TypeId7(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


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


class StateId1(IntEnum):
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


class FlagId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_99 = 99


class DnsAnswer(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    flags: list[str] | None = None
    type: str | None = None
    ttl: int | None = None
    class_: str | None = Field(None, alias='class')
    flag_ids: list[FlagId] | None = None
    packet_uid: int | None = None
    rdata: str


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


class TypeId9(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_99 = 99


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


class EmailAuth(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    spf: str | None = None
    dkim: str | None = None
    dkim_domain: str | None = None
    dkim_signature: str | None = None
    dmarc: str | None = None
    dmarc_override: str | None = None
    dmarc_policy: str | None = None


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


class DriveTypeId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
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


class Hassh(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    algorithm: str | None = None
    fingerprint: Fingerprint


class HttpCookie(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    value: str
    path: str | None = None
    domain: str | None = None
    secure: bool | None = None
    http_only: bool | None = None
    expiration_time: int | None = None
    is_http_only: bool | None = None
    is_secure: bool | None = None
    samesite: str | None = None


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


class StateId2(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
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
    integer_99 = 99


class Ja4Fingerprint(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type: str | None = None
    value: str
    type_id: TypeId11
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


class TypeId12(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_99 = 99


class Kernel(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    type: str | None = None
    path: str | None = None
    type_id: TypeId12
    is_system: bool | None = None
    system_call: str | None = None


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


class TypeId13(IntEnum):
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
    type_id: TypeId13
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


class LoadTypeId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_99 = 99


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


class ProtocolVerId(IntEnum):
    integer_0 = 0
    integer_4 = 4
    integer_6 = 6
    integer_99 = 99


class TypeId15(IntEnum):
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


class TypeId16(IntEnum):
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
    type_id: TypeId16
    subnet_prefix: int | None = None


class TypeId17(IntEnum):
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


class NetworkTraffic(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    bytes_in: int | None = None
    bytes_out: int | None = None
    chunks: int | None = None
    bytes: int | None = None
    bytes_missed: int | None = None
    chunks_in: int | None = None
    chunks_out: int | None = None
    packets: int | None = None
    packets_in: int | None = None
    packets_out: int | None = None


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


class OccurrenceDetails(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    end_line: int | None = None
    cell_name: str | None = None
    column_name: str | None = None
    column_number: int | None = None
    json_path: str | None = None
    page_number: int | None = None
    record_index_in_array: int | None = None
    row_number: int | None = None
    start_line: int | None = None


class Organization(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    uid: str | None = None
    ou_name: str | None = None
    ou_uid: str | None = None


class TypeId19(IntEnum):
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
    type_id: TypeId19
    cpe_name: str | None = None
    cpu_bits: int | None = None
    edition: str | None = None
    kernel_release: str | None = None
    sp_name: str | None = None
    sp_ver: int | None = None


class DetectionPatternTypeId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_99 = 99


class TypeId20(IntEnum):
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
    integer_99 = 99


class TypeId21(IntEnum):
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
    type_id: TypeId21 | None = None
    license: str | None = None
    architecture: str | None = None
    cpe_name: str | None = None
    license_url: str | None = None
    package_manager: str | None = None
    package_manager_url: str | None = None
    purl: str | None = None
    src_url: str | None = None
    vendor_name: str | None = None


class PeripheralDevice(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    class_: str = Field(..., alias='class')
    uid: str | None = None
    model: str | None = None
    serial_number: str | None = None
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


class QueryTypeId(IntEnum):
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


class TcpStateId(IntEnum):
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


class QueryInfo(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    data: Any | None = None
    name: str | None = None
    bytes: int | None = None
    uid: str | None = None
    query_string: str
    query_time: int | None = None


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


class RpcInterface(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    version: str
    uuid: str
    ack_reason: int | None = None
    ack_result: int | None = None


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


class TypeId22(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class TypeId23(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_5 = 5
    integer_6 = 6
    integer_7 = 7
    integer_99 = 99


class Scan(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    type: str | None = None
    uid: str | None = None
    type_id: TypeId23


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
    state_id: StateId2 | None = None
    uid_alt: str | None = None
    url_string: str | None = None
    vendor_name: str | None = None


class StateId4(IntEnum):
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
    integer_99 = 99


class SecurityState(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    state: str | None = None
    state_id: StateId4 | None = None


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


class TypeId25(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class RelationshipId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_99 = 99


class SoftwareComponent(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    type: str | None = None
    version: str
    author: str | None = None
    hash: Fingerprint | None = None
    relationship: str | None = None
    type_id: TypeId25 | None = None
    license: str | None = None
    purl: str | None = None
    related_component: str | None = None
    relationship_id: RelationshipId | None = None


class TypeId26(IntEnum):
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


class RunModeId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class RunStateId1(IntEnum):
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


class StartTypeId(IntEnum):
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


class SubTechnique(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    uid: str | None = None
    src_url: str | None = None


class Table(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    size: int | None = None
    desc: str | None = None
    uid: str | None = None
    groups: list[Group] | None = None
    created_time: int | None = None
    modified_time: int | None = None


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


class TypeId27(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_4 = 4
    integer_99 = 99


class ThreatActor(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str
    type: str | None = None
    type_id: TypeId27 | None = None


class TypeId28(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_99 = 99


class StatusId56(IntEnum):
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


class Ticket(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    status: str | None = None
    type: str | None = None
    title: str | None = None
    uid: str | None = None
    type_id: TypeId28 | None = None
    src_url: str | None = None
    status_details: list[str] | None = None
    status_id: StatusId56 | None = None


class TypeId29(IntEnum):
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
    type_id: TypeId29 | None = None
    end_time: int | None = None
    duration_days: int | None = None
    duration_hours: int | None = None
    duration_mins: int | None = None
    duration_months: int | None = None
    duration_secs: int | None = None
    duration_weeks: int | None = None
    duration_years: int | None = None


class TypeId30(IntEnum):
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
    type_id: TypeId30


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


class TypeId31(IntEnum):
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
    integer_99 = 99


class TypeId32(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_3 = 3
    integer_99 = 99


class UnmannedSystemOperatingArea(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    count: int | None = None
    type: str | None = None
    desc: str | None = None
    long: float | None = None
    start_time: int | None = None
    city: str | None = None
    country: str | None = None
    coordinates: list[float] | None = None
    continent: str | None = None
    type_id: TypeId32 | None = None
    end_time: int | None = None
    aerial_height: str | None = None
    altitude_ceiling: str | None = None
    altitude_floor: str | None = None
    geodetic_altitude: str | None = None
    geodetic_vertical_accuracy: str | None = None
    geohash: str | None = None
    horizontal_accuracy: str | None = None
    is_on_premises: bool | None = None
    isp: str | None = None
    lat: float | None = None
    locations: list[Location] | None = None
    postal_code: str | None = None
    pressure_altitude: str | None = None
    provider: str | None = None
    radius: str | None = None
    region: str | None = None


class CategoryId1(IntEnum):
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
    category_ids: list[CategoryId1] | None = None
    resource_type: str | None = None
    subdomain: str | None = None
    url_string: str | None = None


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


class DnssecStatusId(IntEnum):
    integer_0 = 0
    integer_1 = 1
    integer_2 = 2
    integer_99 = 99


class WinRegKey(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    path: str
    is_system: bool | None = None
    modified_time: int | None = None
    security_descriptor: str | None = None


class TypeId34(IntEnum):
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
    type_id: TypeId34 | None = None
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
    type_id: TypeId1 | None = None


class Agent(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    type: str | None = None
    version: str | None = None
    uid: str | None = None
    type_id: TypeId3 | None = None
    policies: list[Policy] | None = None
    uid_alt: str | None = None
    vendor_name: str | None = None


class Aircraft(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    speed: str | None = None
    location: Location | None = None
    uid: str | None = None
    model: str | None = None
    serial_number: str | None = None
    speed_accuracy: str | None = None
    track_direction: str | None = None
    uid_alt: str | None = None
    vertical_speed: str | None = None


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
    type_id: TypeId5 | None = None
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


class Cloud(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    org: Organization | None = None
    account: Account | None = None
    cloud_partition: str | None = None
    project_uid: str | None = None
    provider: str
    region: str | None = None
    zone: str | None = None


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
    type_id: TypeId6
    created_time: int | None = None
    modified_time: int | None = None


class DceRpc(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    command: str | None = None
    flags: list[str]
    command_response: str | None = None
    opnum: int | None = None
    rpc_interface: RpcInterface


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
    state_id: StateId1 | None = None


class DiscoveryDetails(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    count: int | None = None
    type: str | None = None
    value: str | None = None
    occurrence_details: OccurrenceDetails | None = None
    occurrences: list[OccurrenceDetails] | None = None


class DomainContact(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    type: str | None = None
    location: Location | None = None
    uid: str | None = None
    type_id: TypeId9
    email_addr: str | None = None
    phone_number: str | None = None


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
    type_id: TypeId18
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


class Sbom(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type: str | None = None
    version: str | None = None
    product: Product | None = None
    uid: str | None = None
    type_id: TypeId22 | None = None
    created_time: int | None = None
    package: Package
    software_components: list[SoftwareComponent]


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


class UnmannedAerialSystem(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    name: str | None = None
    type: str | None = None
    speed: str | None = None
    location: Location | None = None
    uid: str | None = None
    uuid: str | None = None
    type_id: TypeId31 | None = None
    hw_info: DeviceHwInfo | None = None
    model: str | None = None
    serial_number: str | None = None
    speed_accuracy: str | None = None
    track_direction: str | None = None
    uid_alt: str | None = None
    vertical_speed: str | None = None


class Whois(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    status: str | None = None
    domain: str | None = None
    registrar: str | None = None
    subdomains: list[str] | None = None
    subnet: str | None = None
    autonomous_system: AutonomousSystem | None = None
    created_time: int | None = None
    dnssec_status: str | None = None
    dnssec_status_id: DnssecStatusId | None = None
    domain_contacts: list[DomainContact] | None = None
    email_addr: str | None = None
    isp: str | None = None
    isp_org: str | None = None
    last_seen_time: int | None = None
    name_servers: list[str] | None = None
    phone_number: str | None = None


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
    type_id: TypeId2 | None = None
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
    status_id: StatusId53 | None = None


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


class DataSecurity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    size: int | None = None
    status: str | None = None
    total: int | None = None
    uid: str | None = None
    category: str | None = None
    pattern_match: str | None = None
    category_id: CategoryId | None = None
    classifier_details: ClassifierDetails | None = None
    confidentiality: str | None = None
    confidentiality_id: ConfidentialityId | None = None
    data_lifecycle_state: str | None = None
    data_lifecycle_state_id: DataLifecycleStateId | None = None
    detection_pattern: str | None = None
    detection_system: str | None = None
    detection_system_id: DetectionSystemId | None = None
    discovery_details: list[DiscoveryDetails] | None = None
    policy: Policy | None = None
    src_url: str | None = None
    status_details: list[str] | None = None
    status_id: StatusId53 | None = None


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


class FileActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid
    component: str | None = None
    file_result: File | None = None
    type_name: str | None = None
    device: Device
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    file: File
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId
    status_code: str | None = None
    category_uid: CategoryUid
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    file_diff: str | None = None
    activity_name: str | None = None
    create_mask: str | None = None
    raw_data_size: int | None = None
    connection_uid: str | None = None
    raw_data: str | None = None
    actor: Actor
    status_detail: str | None = None
    count: int | None = None
    access_mask: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    class_uid: ClassUid
    category_name: str | None = None
    status_id: StatusId | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class KernelExtensionActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid1
    type_name: str | None = None
    device: Device
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId1
    driver: KernelDriver
    status_code: str | None = None
    category_uid: CategoryUid
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
    class_uid: ClassUid1
    category_name: str | None = None
    status_id: StatusId | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class KernelActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid2
    type_name: str | None = None
    device: Device
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId2
    status_code: str | None = None
    category_uid: CategoryUid
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
    class_uid: ClassUid2
    category_name: str | None = None
    kernel: Kernel
    status_id: StatusId | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class MemoryActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid3
    type_name: str | None = None
    device: Device
    process: Process
    message: str | None = None
    severity: str | None = None
    size: int | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId3
    status_code: str | None = None
    category_uid: CategoryUid
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    actual_permissions: int | None = None
    activity_name: str | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    actor: Actor
    base_address: str | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    class_uid: ClassUid3
    category_name: str | None = None
    status_id: StatusId | None = None
    requested_permissions: int | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class ModuleActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid4
    type_name: str | None = None
    device: Device
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    module: Module
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId4
    status_code: str | None = None
    category_uid: CategoryUid
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
    class_uid: ClassUid4
    category_name: str | None = None
    status_id: StatusId | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class ScheduledJobActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid5
    type_name: str | None = None
    device: Device
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId5
    status_code: str | None = None
    category_uid: CategoryUid
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    actor: Actor | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    class_uid: ClassUid5
    category_name: str | None = None
    status_id: StatusId | None = None
    job: Job
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class ProcessActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid6
    type_name: str | None = None
    device: Device
    process: Process
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    injection_type: str | None = None
    module: Module | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId6
    status_code: str | None = None
    category_uid: CategoryUid
    timezone_offset: int | None = None
    injection_type_id: InjectionTypeId | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    actual_permissions: int | None = None
    activity_name: str | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    actor: Actor
    exit_code: int | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    class_uid: ClassUid6
    category_name: str | None = None
    status_id: StatusId | None = None
    requested_permissions: int | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class EventLogActvity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    log_name: str | None = None
    type_uid: TypeUid7
    type_name: str | None = None
    device: Device | None = None
    message: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    file: File | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId7
    status_code: str | None = None
    category_uid: CategoryUid
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    actor: Actor | None = None
    log_provider: str | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    class_uid: ClassUid7
    category_name: str | None = None
    log_type_id: LogTypeId | None = None
    status_id: StatusId | None = None
    log_type: str | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class ScriptActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid8
    type_name: str | None = None
    device: Device
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    script: Script
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId8
    status_code: str | None = None
    category_uid: CategoryUid
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
    class_uid: ClassUid8
    category_name: str | None = None
    status_id: StatusId | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class VulnerabilityFinding(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid9
    confidence_score: int | None = None
    type_name: str | None = None
    device: Device | None = None
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId9
    status_code: str | None = None
    finding_info: FindingInfo
    category_uid: CategoryUid9
    timezone_offset: int | None = None
    comment: str | None = None
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
    vulnerabilities: list[Vulnerability]
    unmapped: Object | None = None
    class_uid: ClassUid9
    resources: list[ResourceDetails] | None = None
    category_name: str | None = None
    status_id: StatusId9 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None
    vendor_attributes: VendorAttributes | None = None


class ComplianceFinding(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid10
    evidences: list[Evidences] | None = None
    confidence_score: int | None = None
    type_name: str | None = None
    device: Device | None = None
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId9
    status_code: str | None = None
    finding_info: FindingInfo
    category_uid: CategoryUid9
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
    class_uid: ClassUid10
    resources: list[ResourceDetails] | None = None
    category_name: str | None = None
    status_id: StatusId9 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None
    vendor_attributes: VendorAttributes | None = None


class DetectionFinding(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    malware: list[Malware] | None = None
    type_uid: TypeUid11
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
    activity_id: ActivityId9
    status_code: str | None = None
    is_alert: bool | None = None
    finding_info: FindingInfo
    category_uid: CategoryUid9
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
    class_uid: ClassUid11
    risk_score: int | None = None
    resources: list[ResourceDetails] | None = None
    category_name: str | None = None
    risk_details: str | None = None
    status_id: StatusId9 | None = None
    risk_level: str | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None
    vendor_attributes: VendorAttributes | None = None


class IncidentFinding(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid12
    desc: str | None = None
    verdict: str | None = None
    ticket: Ticket | None = None
    confidence_score: int | None = None
    type_name: str | None = None
    impact: str | None = None
    attacks: list[Attack] | None = None
    message: str | None = None
    assignee_group: Group | None = None
    severity: str | None = None
    impact_id: ImpactId | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId9
    status_code: str | None = None
    category_uid: CategoryUid9
    timezone_offset: int | None = None
    comment: str | None = None
    impact_score: int | None = None
    duration: int | None = None
    src_url: str | None = None
    tickets: list[Ticket] | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    confidence: str | None = None
    finding_info_list: list[FindingInfo]
    confidence_id: ConfidenceId | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    verdict_id: VerdictId | None = None
    unmapped: Object | None = None
    class_uid: ClassUid12
    category_name: str | None = None
    priority_id: PriorityId | None = None
    priority: str | None = None
    assignee: User | None = None
    status_id: StatusId9
    is_suspected_breach: bool | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None
    vendor_attributes: VendorAttributes | None = None


class DataSecurityFinding(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    databucket: Databucket | None = None
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid13
    confidence_score: int | None = None
    type_name: str | None = None
    data_security: DataSecurity | None = None
    impact: str | None = None
    device: Device | None = None
    message: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    severity: str | None = None
    impact_id: ImpactId | None = None
    observables: list[Observable] | None = None
    file: File | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId13
    status_code: str | None = None
    is_alert: bool | None = None
    finding_info: FindingInfo
    category_uid: CategoryUid9
    timezone_offset: int | None = None
    comment: str | None = None
    impact_score: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    database: Database | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    actor: Actor | None = None
    confidence: str | None = None
    confidence_id: ConfidenceId | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    risk_level_id: RiskLevelId | None = None
    unmapped: Object | None = None
    class_uid: ClassUid13
    risk_score: int | None = None
    resources: list[ResourceDetails] | None = None
    category_name: str | None = None
    risk_details: str | None = None
    status_id: StatusId9 | None = None
    risk_level: str | None = None
    table: Table | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None
    vendor_attributes: VendorAttributes | None = None


class ApplicationSecurityPostureFinding(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid14
    confidence_score: int | None = None
    type_name: str | None = None
    device: Device | None = None
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId14
    status_code: str | None = None
    finding_info: FindingInfo
    category_uid: CategoryUid9
    timezone_offset: int | None = None
    comment: str | None = None
    compliance: Compliance | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    application: Application | None = None
    activity_name: str | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    confidence: str | None = None
    confidence_id: ConfidenceId | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    vulnerabilities: list[Vulnerability] | None = None
    remediation: Remediation | None = None
    unmapped: Object | None = None
    class_uid: ClassUid14
    resources: list[ResourceDetails] | None = None
    category_name: str | None = None
    status_id: StatusId9 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None
    vendor_attributes: VendorAttributes | None = None


class AccountChange(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid15
    type_name: str | None = None
    http_response: HttpResponse | None = None
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    http_request: HttpRequest | None = None
    metadata: Metadata
    policies: list[Policy] | None = None
    activity_id: ActivityId15
    status_code: str | None = None
    category_uid: CategoryUid15
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
    class_uid: ClassUid15
    category_name: str | None = None
    status_id: StatusId15 | None = None
    policy: Policy | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class Authentication(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid16
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
    activity_id: ActivityId16
    status_code: str | None = None
    category_uid: CategoryUid15
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
    class_uid: ClassUid16
    category_name: str | None = None
    is_cleartext: bool | None = None
    status_id: StatusId15 | None = None
    is_mfa: bool | None = None
    authentication_token: AuthenticationToken | None = None
    logon_type: str | None = None
    severity_id: SeverityId
    logon_process: Process | None = None
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class AuthorizeSession(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid17
    type_name: str | None = None
    http_response: HttpResponse | None = None
    message: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    http_request: HttpRequest | None = None
    metadata: Metadata
    activity_id: ActivityId17
    status_code: str | None = None
    category_uid: CategoryUid15
    timezone_offset: int | None = None
    group: Group | None = None
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
    unmapped: Object | None = None
    class_uid: ClassUid17
    category_name: str | None = None
    privileges: list[str] | None = None
    status_id: StatusId15 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class EntityManagement(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid18
    type_name: str | None = None
    http_response: HttpResponse | None = None
    message: str | None = None
    severity: str | None = None
    entity: ManagedEntity
    observables: list[Observable] | None = None
    class_name: str | None = None
    http_request: HttpRequest | None = None
    metadata: Metadata
    activity_id: ActivityId18
    status_code: str | None = None
    category_uid: CategoryUid15
    timezone_offset: int | None = None
    entity_result: ManagedEntity | None = None
    comment: str | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    actor: Actor | None = None
    status_detail: str | None = None
    count: int | None = None
    access_mask: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    class_uid: ClassUid18
    category_name: str | None = None
    status_id: StatusId15 | None = None
    access_list: list[str] | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class UserAccess(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid19
    type_name: str | None = None
    http_response: HttpResponse | None = None
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    http_request: HttpRequest | None = None
    metadata: Metadata
    activity_id: ActivityId19
    status_code: str | None = None
    category_uid: CategoryUid15
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
    resource: ResourceDetails | None = None
    unmapped: Object | None = None
    class_uid: ClassUid19
    resources: list[ResourceDetails] | None = None
    category_name: str | None = None
    privileges: list[str]
    status_id: StatusId15 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class GroupManagement(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid20
    type_name: str | None = None
    http_response: HttpResponse | None = None
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    http_request: HttpRequest | None = None
    metadata: Metadata
    activity_id: ActivityId20
    status_code: str | None = None
    category_uid: CategoryUid15
    timezone_offset: int | None = None
    group: Group
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    user: User | None = None
    raw_data: str | None = None
    actor: Actor | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    resource: ResourceDetails | None = None
    unmapped: Object | None = None
    class_uid: ClassUid20
    category_name: str | None = None
    privileges: list[str] | None = None
    status_id: StatusId15 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class NetworkActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid21
    type_name: str | None = None
    message: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    severity: str | None = None
    proxy: NetworkProxy | None = None
    observables: list[Observable] | None = None
    app_name: str | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId21
    status_code: str | None = None
    category_uid: CategoryUid21
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    ja4_fingerprint_list: list[Ja4Fingerprint] | None = None
    raw_data: str | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    tls: Tls | None = None
    traffic: NetworkTraffic | None = None
    class_uid: ClassUid21
    category_name: str | None = None
    connection_info: NetworkConnectionInfo | None = None
    url: Url | None = None
    status_id: StatusId15 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class HttpActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid22
    type_name: str | None = None
    http_response: HttpResponse | None = None
    message: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    severity: str | None = None
    proxy: NetworkProxy | None = None
    observables: list[Observable] | None = None
    app_name: str | None = None
    file: File | None = None
    http_status: int | None = None
    class_name: str | None = None
    http_request: HttpRequest | None = None
    metadata: Metadata
    activity_id: ActivityId22
    status_code: str | None = None
    category_uid: CategoryUid21
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    ja4_fingerprint_list: list[Ja4Fingerprint] | None = None
    raw_data: str | None = None
    http_cookies: list[HttpCookie] | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    tls: Tls | None = None
    traffic: NetworkTraffic | None = None
    class_uid: ClassUid22
    category_name: str | None = None
    connection_info: NetworkConnectionInfo | None = None
    status_id: StatusId15 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class DnsActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid23
    rcode: str | None = None
    type_name: str | None = None
    message: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    severity: str | None = None
    proxy: NetworkProxy | None = None
    observables: list[Observable] | None = None
    app_name: str | None = None
    response_time: int | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId23
    status_code: str | None = None
    category_uid: CategoryUid21
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    ja4_fingerprint_list: list[Ja4Fingerprint] | None = None
    raw_data: str | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    rcode_id: RcodeId | None = None
    unmapped: Object | None = None
    tls: Tls | None = None
    traffic: NetworkTraffic | None = None
    class_uid: ClassUid23
    category_name: str | None = None
    connection_info: NetworkConnectionInfo | None = None
    query: DnsQuery | None = None
    status_id: StatusId15 | None = None
    query_time: int | None = None
    answers: list[DnsAnswer] | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class DhcpActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid24
    type_name: str | None = None
    message: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    severity: str | None = None
    proxy: NetworkProxy | None = None
    observables: list[Observable] | None = None
    app_name: str | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId24
    status_code: str | None = None
    category_uid: CategoryUid21
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    ja4_fingerprint_list: list[Ja4Fingerprint] | None = None
    raw_data: str | None = None
    lease_dur: int | None = None
    relay: NetworkInterface | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    is_renewal: bool | None = None
    tls: Tls | None = None
    traffic: NetworkTraffic | None = None
    class_uid: ClassUid24
    category_name: str | None = None
    transaction_uid: str | None = None
    connection_info: NetworkConnectionInfo | None = None
    status_id: StatusId15 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class RdpActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid25
    remote_display: Display | None = None
    response: Response | None = None
    type_name: str | None = None
    device: Device | None = None
    keyboard_info: KeyboardInfo | None = None
    message: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    severity: str | None = None
    proxy: NetworkProxy | None = None
    observables: list[Observable] | None = None
    app_name: str | None = None
    file: File | None = None
    identifier_cookie: str | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId25
    status_code: str | None = None
    capabilities: list[str] | None = None
    category_uid: CategoryUid21
    protocol_ver: str | None = None
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    ja4_fingerprint_list: list[Ja4Fingerprint] | None = None
    raw_data: str | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    tls: Tls | None = None
    traffic: NetworkTraffic | None = None
    class_uid: ClassUid25
    category_name: str | None = None
    connection_info: NetworkConnectionInfo | None = None
    request: Request | None = None
    certificate_chain: list[str] | None = None
    status_id: StatusId15 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class SmbActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid26
    response: Response | None = None
    share_type_id: ShareTypeId | None = None
    type_name: str | None = None
    dce_rpc: DceRpc | None = None
    message: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    severity: str | None = None
    proxy: NetworkProxy | None = None
    observables: list[Observable] | None = None
    app_name: str | None = None
    file: File | None = None
    share: str | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId25
    status_code: str | None = None
    category_uid: CategoryUid21
    timezone_offset: int | None = None
    tree_uid: str | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    ja4_fingerprint_list: list[Ja4Fingerprint] | None = None
    command: str | None = None
    raw_data: str | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    tls: Tls | None = None
    traffic: NetworkTraffic | None = None
    share_type: str | None = None
    class_uid: ClassUid26
    dialect: str | None = None
    category_name: str | None = None
    client_dialects: list[str] | None = None
    connection_info: NetworkConnectionInfo | None = None
    status_id: StatusId15 | None = None
    open_type: str | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class SshActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid27
    auth_type_id: AuthTypeId | None = None
    type_name: str | None = None
    message: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    severity: str | None = None
    proxy: NetworkProxy | None = None
    observables: list[Observable] | None = None
    app_name: str | None = None
    file: File | None = None
    class_name: str | None = None
    auth_type: str | None = None
    metadata: Metadata
    activity_id: ActivityId27
    status_code: str | None = None
    category_uid: CategoryUid21
    client_hassh: Hassh | None = None
    protocol_ver: str | None = None
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    ja4_fingerprint_list: list[Ja4Fingerprint] | None = None
    raw_data: str | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    server_hassh: Hassh | None = None
    unmapped: Object | None = None
    tls: Tls | None = None
    traffic: NetworkTraffic | None = None
    class_uid: ClassUid27
    category_name: str | None = None
    connection_info: NetworkConnectionInfo | None = None
    status_id: StatusId15 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class FtpActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid28
    codes: list[int] | None = None
    type_name: str | None = None
    message: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    severity: str | None = None
    proxy: NetworkProxy | None = None
    command_responses: list[str] | None = None
    observables: list[Observable] | None = None
    app_name: str | None = None
    file: File | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId28
    status_code: str | None = None
    category_uid: CategoryUid21
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    ja4_fingerprint_list: list[Ja4Fingerprint] | None = None
    command: str | None = None
    raw_data: str | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    tls: Tls | None = None
    traffic: NetworkTraffic | None = None
    class_uid: ClassUid28
    port: int | None = None
    category_name: str | None = None
    name: str | None = None
    connection_info: NetworkConnectionInfo | None = None
    status_id: StatusId15 | None = None
    type: str | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class EmailActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid29
    smtp_hello: str | None = None
    type_name: str | None = None
    direction_id: DirectionId
    message: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId29
    status_code: str | None = None
    direction: str | None = None
    category_uid: CategoryUid21
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    command: str | None = None
    raw_data: str | None = None
    attempt: int | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    message_trace_uid: str | None = None
    unmapped: Object | None = None
    email: Email
    class_uid: ClassUid29
    category_name: str | None = None
    status_id: StatusId15 | None = None
    protocol_name: str | None = None
    banner: str | None = None
    email_auth: EmailAuth | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class NtpActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid30
    type_name: str | None = None
    message: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    severity: str | None = None
    proxy: NetworkProxy | None = None
    observables: list[Observable] | None = None
    app_name: str | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId30
    status_code: str | None = None
    stratum: str | None = None
    category_uid: CategoryUid21
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    ja4_fingerprint_list: list[Ja4Fingerprint] | None = None
    raw_data: str | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    stratum_id: StratumId | None = None
    dispersion: int | None = None
    unmapped: Object | None = None
    version: str
    tls: Tls | None = None
    traffic: NetworkTraffic | None = None
    class_uid: ClassUid30
    delay: int | None = None
    category_name: str | None = None
    precision: int | None = None
    connection_info: NetworkConnectionInfo | None = None
    status_id: StatusId15 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class TunnelActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid31
    type_name: str | None = None
    device: Device | None = None
    message: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    severity: str | None = None
    proxy: NetworkProxy | None = None
    observables: list[Observable] | None = None
    app_name: str | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId31
    status_code: str | None = None
    category_uid: CategoryUid21
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    tunnel_type_id: TunnelTypeId | None = None
    ja4_fingerprint_list: list[Ja4Fingerprint] | None = None
    user: User | None = None
    raw_data: str | None = None
    session: Session | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    tunnel_type: str | None = None
    unmapped: Object | None = None
    tls: Tls | None = None
    traffic: NetworkTraffic | None = None
    class_uid: ClassUid31
    category_name: str | None = None
    tunnel_interface: NetworkInterface | None = None
    connection_info: NetworkConnectionInfo | None = None
    status_id: StatusId15 | None = None
    protocol_name: str | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class InventoryInfo(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid32
    type_name: str | None = None
    device: Device
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId32
    status_code: str | None = None
    category_uid: CategoryUid32
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    actor: Actor | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    class_uid: ClassUid32
    category_name: str | None = None
    status_id: StatusId15 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class UserInventory(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid33
    type_name: str | None = None
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId32
    status_code: str | None = None
    category_uid: CategoryUid32
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
    unmapped: Object | None = None
    class_uid: ClassUid33
    category_name: str | None = None
    status_id: StatusId15 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class PatchState(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid34
    type_name: str | None = None
    device: Device
    message: str | None = None
    severity: str | None = None
    kb_article_list: list[KbArticle] | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId32
    status_code: str | None = None
    category_uid: CategoryUid32
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
    class_uid: ClassUid34
    category_name: str | None = None
    status_id: StatusId15 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class DeviceConfigStateChange(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid35
    security_level: str | None = None
    type_name: str | None = None
    device: Device
    state: str | None = None
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId32
    status_code: str | None = None
    category_uid: CategoryUid32
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    security_level_id: SecurityLevelId | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    actor: Actor | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    security_states: list[SecurityState] | None = None
    prev_security_level: str | None = None
    unmapped: Object | None = None
    class_uid: ClassUid35
    category_name: str | None = None
    prev_security_states: list[SecurityState] | None = None
    prev_security_level_id: PrevSecurityLevelId | None = None
    status_id: StatusId15 | None = None
    state_id: StateId | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class SoftwareInfo(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid36
    type_name: str | None = None
    device: Device
    sbom: Sbom | None = None
    package: Package | None = None
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId32
    status_code: str | None = None
    category_uid: CategoryUid32
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    product: Product | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    actor: Actor | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    class_uid: ClassUid36
    category_name: str | None = None
    status_id: StatusId15 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class OsintInventoryInfo(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid37
    type_name: str | None = None
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId32
    status_code: str | None = None
    category_uid: CategoryUid32
    osint: list[Osint]
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    actor: Actor | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    class_uid: ClassUid37
    category_name: str | None = None
    status_id: StatusId15 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class CloudResourcesInventoryInfo(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    databucket: Databucket | None = None
    type_uid: TypeUid38
    type_name: str | None = None
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    container: Container | None = None
    region: str | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId32
    status_code: str | None = None
    category_uid: CategoryUid32
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    cloud: Cloud | None = None
    time: int
    activity_name: str | None = None
    database: Database | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    class_uid: ClassUid38
    resources: list[ResourceDetails] | None = None
    category_name: str | None = None
    idp: Idp | None = None
    status_id: StatusId15 | None = None
    table: Table | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class EvidenceInfo(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid39
    type_name: str | None = None
    query_info: QueryInfo | None = None
    device: Device
    message: str | None = None
    severity: str | None = None
    query_result_id: QueryResultId
    observables: list[Observable] | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId39
    status_code: str | None = None
    category_uid: CategoryUid32
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
    class_uid: ClassUid39
    category_name: str | None = None
    query_evidence: QueryEvidence
    status_id: StatusId15 | None = None
    query_result: str | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class WebResourcesActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid40
    type_name: str | None = None
    http_response: HttpResponse | None = None
    message: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    http_request: HttpRequest | None = None
    metadata: Metadata
    activity_id: ActivityId40
    status_code: str | None = None
    category_uid: CategoryUid40
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
    class_uid: ClassUid40
    category_name: str | None = None
    web_resources: list[WebResource]
    status_id: StatusId15 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class ApplicationLifecycle(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid41
    type_name: str | None = None
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId40
    status_code: str | None = None
    category_uid: CategoryUid40
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    app: Product
    raw_data: str | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    class_uid: ClassUid41
    category_name: str | None = None
    status_id: StatusId15 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class ApiActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint
    type_uid: TypeUid42
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
    activity_id: ActivityId42
    status_code: str | None = None
    category_uid: CategoryUid40
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
    class_uid: ClassUid42
    resources: list[ResourceDetails] | None = None
    category_name: str | None = None
    status_id: StatusId15 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class DatastoreActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    databucket: Databucket | None = None
    src_endpoint: NetworkEndpoint
    type_uid: TypeUid43
    type_name: str | None = None
    query_info: QueryInfo | None = None
    http_response: HttpResponse | None = None
    message: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    http_request: HttpRequest | None = None
    metadata: Metadata
    activity_id: ActivityId43
    status_code: str | None = None
    category_uid: CategoryUid40
    timezone_offset: int | None = None
    type_id: TypeId | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    database: Database | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    actor: Actor
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    class_uid: ClassUid43
    category_name: str | None = None
    status_id: StatusId15 | None = None
    type: str | None = None
    table: Table | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class FileHosting(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint
    type_uid: TypeUid44
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
    activity_id: ActivityId44
    status_code: str | None = None
    category_uid: CategoryUid40
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
    class_uid: ClassUid44
    category_name: str | None = None
    connection_info: NetworkConnectionInfo | None = None
    status_id: StatusId15 | None = None
    access_list: list[str] | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None
    access_result: Any | None = None


class ScanActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    num_skipped_items: int | None = None
    type_uid: TypeUid45
    total: int | None = None
    type_name: str | None = None
    command_uid: str | None = None
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    num_folders: int | None = None
    num_registry_items: int | None = None
    scan: Scan
    num_files: int | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId45
    status_code: str | None = None
    num_detections: int | None = None
    category_uid: CategoryUid40
    timezone_offset: int | None = None
    num_trusted_items: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    num_processes: int | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    schedule_uid: str | None = None
    unmapped: Object | None = None
    num_network_items: int | None = None
    class_uid: ClassUid45
    category_name: str | None = None
    num_resolutions: int | None = None
    status_id: StatusId15 | None = None
    policy: Policy | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class ApplicationError(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid46
    type_name: str | None = None
    message: str | None = None
    severity: str | None = None
    observables: list[Observable] | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId46
    status_code: str | None = None
    category_uid: CategoryUid40
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
    class_uid: ClassUid46
    category_name: str | None = None
    status_id: StatusId15 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class RemediationActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid47
    type_name: str | None = None
    command_uid: str
    message: str | None = None
    severity: str | None = None
    countermeasures: list[D3fend] | None = None
    observables: list[Observable] | None = None
    scan: Scan | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId47
    status_code: str | None = None
    category_uid: CategoryUid47
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
    remediation: Remediation | None = None
    unmapped: Object | None = None
    class_uid: ClassUid47
    category_name: str | None = None
    status_id: StatusId47 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class FileRemediationActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid48
    type_name: str | None = None
    command_uid: str
    message: str | None = None
    severity: str | None = None
    countermeasures: list[D3fend] | None = None
    observables: list[Observable] | None = None
    file: File
    scan: Scan | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId47
    status_code: str | None = None
    category_uid: CategoryUid47
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
    remediation: Remediation | None = None
    unmapped: Object | None = None
    class_uid: ClassUid48
    category_name: str | None = None
    status_id: StatusId47 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class ProcessRemediationActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid49
    type_name: str | None = None
    command_uid: str
    process: Process
    message: str | None = None
    severity: str | None = None
    countermeasures: list[D3fend] | None = None
    observables: list[Observable] | None = None
    scan: Scan | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId47
    status_code: str | None = None
    category_uid: CategoryUid47
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
    remediation: Remediation | None = None
    unmapped: Object | None = None
    class_uid: ClassUid49
    category_name: str | None = None
    status_id: StatusId47 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class NetworkRemediationActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type_uid: TypeUid50
    type_name: str | None = None
    command_uid: str
    message: str | None = None
    severity: str | None = None
    countermeasures: list[D3fend] | None = None
    observables: list[Observable] | None = None
    scan: Scan | None = None
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId47
    status_code: str | None = None
    category_uid: CategoryUid47
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
    remediation: Remediation | None = None
    unmapped: Object | None = None
    class_uid: ClassUid50
    category_name: str | None = None
    connection_info: NetworkConnectionInfo
    status_id: StatusId47 | None = None
    severity_id: SeverityId
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class DroneFlightsActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid51
    auth_protocol_id: AuthProtocolId | None = None
    type_name: str | None = None
    message: str | None = None
    dst_endpoint: NetworkEndpoint
    severity: str | None = None
    unmanned_system_operating_area: UnmannedSystemOperatingArea | None = None
    observables: list[Observable] | None = None
    auth_protocol: str | None = None
    unmanned_system_operator: User
    class_name: str | None = None
    metadata: Metadata
    activity_id: ActivityId51
    status_code: str | None = None
    category_uid: CategoryUid51
    timezone_offset: int | None = None
    comment: str | None = None
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
    tls: Tls | None = None
    traffic: NetworkTraffic | None = None
    class_uid: ClassUid51
    category_name: str | None = None
    connection_info: NetworkConnectionInfo | None = None
    status_id: StatusId47 | None = None
    protocol_name: str | None = None
    unmanned_aerial_system: UnmannedAerialSystem
    severity_id: SeverityId
    classification: str | None = None
    proxy_endpoint: NetworkProxy | None = None
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


class AirborneBroadcastActivity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    src_endpoint: NetworkEndpoint | None = None
    type_uid: TypeUid52
    type_name: str | None = None
    message: str | None = None
    dst_endpoint: NetworkEndpoint | None = None
    severity: str | None = None
    unmanned_system_operating_area: UnmannedSystemOperatingArea | None = None
    observables: list[Observable] | None = None
    unmanned_system_operator: User
    class_name: str | None = None
    rssi: int | None = None
    metadata: Metadata
    activity_id: ActivityId51
    status_code: str | None = None
    category_uid: CategoryUid51
    timezone_offset: int | None = None
    duration: int | None = None
    status: str | None = None
    time: int
    activity_name: str | None = None
    raw_data_size: int | None = None
    raw_data: str | None = None
    aircraft: Aircraft | None = None
    status_detail: str | None = None
    count: int | None = None
    end_time: int | None = None
    unmapped: Object | None = None
    tls: Tls | None = None
    traffic: NetworkTraffic | None = None
    class_uid: ClassUid52
    category_name: str | None = None
    connection_info: NetworkConnectionInfo | None = None
    status_id: StatusId52 | None = None
    protocol_name: str | None = None
    unmanned_aerial_system: UnmannedAerialSystem
    severity_id: SeverityId
    proxy_endpoint: NetworkProxy | None = None
    enrichments: list[Enrichment] | None = None
    start_time: int | None = None


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


class Application(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    data: Any | None = None
    name: str | None = None
    owner: User | None = None
    type: str | None = None
    version: str | None = None
    group: Group | None = None
    desc: str | None = None
    uid: str | None = None
    hostname: str | None = None
    labels: list[str] | None = None
    url: Url | None = None
    tags: list[KeyValueObject] | None = None
    criticality: str | None = None
    resource_relationship: Graph | None = None
    risk_level: str | None = None
    risk_level_id: RiskLevelId | None = None
    risk_score: int | None = None
    sbom: Sbom | None = None
    uid_alt: str | None = None


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
    type_id: TypeId7
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
    type_id: TypeId8
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
    type_id: TypeId10
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
    state_id: StateId2 | None = None
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


class KernelDriver(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    file: File


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


class ManagedEntity(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    data: Any | None = None
    name: str | None = None
    type: str | None = None
    version: str | None = None
    user: User | None = None
    device: Device | None = None
    group: Group | None = None
    location: Location | None = None
    uid: str | None = None
    email: Email | None = None
    org: Organization | None = None
    type_id: TypeId13 | None = None
    policy: Policy | None = None


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


class Module(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    type: str | None = None
    file: File | None = None
    base_address: str | None = None
    function_name: str | None = None
    load_type: str | None = None
    load_type_id: LoadTypeId
    start_address: str | None = None


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
    type_id: TypeId15 | None = None
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
    type_id: TypeId17 | None = None
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


class Osint(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    detection_pattern_type_id: DetectionPatternTypeId | None = None
    malware: list[Malware] | None = None
    desc: str | None = None
    attacks: list[Attack] | None = None
    severity: str | None = None
    labels: list[str] | None = None
    uploaded_time: int | None = None
    expiration_time: int | None = None
    script: Script | None = None
    file: File | None = None
    value: str
    uid: str | None = None
    detection_pattern_type: str | None = None
    threat_actor: ThreatActor | None = None
    campaign: Campaign | None = None
    references: list[str] | None = None
    comment: str | None = None
    type_id: TypeId20
    src_url: str | None = None
    signatures: list[DigitalSignature] | None = None
    vendor_name: str | None = None
    whois: Whois | None = None
    subnet: str | None = None
    confidence: str | None = None
    created_time: int | None = None
    confidence_id: ConfidenceId | None = None
    related_analytics: list[Analytic] | None = None
    modified_time: int | None = None
    vulnerabilities: list[Vulnerability] | None = None
    email: Email | None = None
    category: str | None = None
    risk_score: int | None = None
    external_uid: str | None = None
    name: str | None = None
    autonomous_system: AutonomousSystem | None = None
    creator: User | None = None
    subdomains: list[str] | None = None
    kill_chain: list[KillChainPhase] | None = None
    type: str | None = None
    answers: list[DnsAnswer] | None = None
    detection_pattern: str | None = None
    intrusion_sets: list[str] | None = None
    email_auth: EmailAuth | None = None
    severity_id: SeverityId | None = None
    tlp: str | None = None
    reputation: Reputation | None = None
    location: Location | None = None


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


class QueryEvidence(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    module: Module | None = None
    process: Process | None = None
    session: Session | None = None
    file: File | None = None
    state: str | None = None
    user: User | None = None
    kernel: Kernel | None = None
    service: Service | None = None
    group: Group | None = None
    users: list[User] | None = None
    connection_info: NetworkConnectionInfo | None = None
    folder: File | None = None
    job: Job | None = None
    network_interfaces: list[NetworkInterface] | None = None
    peripheral_device: PeripheralDevice | None = None
    query_type: str | None = None
    query_type_id: QueryTypeId
    startup_item: StartupItem | None = None
    tcp_state_id: TcpStateId | None = None
    reg_key: WinRegKey | None = None
    reg_value: WinRegValue | None = None


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
    type_id: TypeId23
    hashes: list[Fingerprint] | None = None
    parent_uid: str | None = None
    script_content: LongString


class StartupItem(BaseModel):
    model_config = ConfigDict(
        extra='allow',
    )
    driver: KernelDriver | None = None
    name: str
    process: Process | None = None
    type: str | None = None
    start_type: str | None = None
    type_id: TypeId26 | None = None
    job: Job | None = None
    run_mode_ids: list[RunModeId] | None = None
    run_modes: list[str] | None = None
    run_state: str | None = None
    run_state_id: RunStateId1 | None = None
    start_type_id: StartTypeId
    win_service: WinWinService | None = None


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
    type_id: TypeId32 | None = None
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
FileActivity.model_rebuild()
KernelExtensionActivity.model_rebuild()
KernelActivity.model_rebuild()
MemoryActivity.model_rebuild()
ModuleActivity.model_rebuild()
ScheduledJobActivity.model_rebuild()
ProcessActivity.model_rebuild()
EventLogActvity.model_rebuild()
ScriptActivity.model_rebuild()
VulnerabilityFinding.model_rebuild()
ComplianceFinding.model_rebuild()
DetectionFinding.model_rebuild()
IncidentFinding.model_rebuild()
DataSecurityFinding.model_rebuild()
ApplicationSecurityPostureFinding.model_rebuild()
AccountChange.model_rebuild()
Authentication.model_rebuild()
AuthorizeSession.model_rebuild()
EntityManagement.model_rebuild()
UserAccess.model_rebuild()
GroupManagement.model_rebuild()
NetworkActivity.model_rebuild()
HttpActivity.model_rebuild()
DnsActivity.model_rebuild()
DhcpActivity.model_rebuild()
RdpActivity.model_rebuild()
SmbActivity.model_rebuild()
SshActivity.model_rebuild()
FtpActivity.model_rebuild()
EmailActivity.model_rebuild()
NtpActivity.model_rebuild()
TunnelActivity.model_rebuild()
InventoryInfo.model_rebuild()
UserInventory.model_rebuild()
PatchState.model_rebuild()
DeviceConfigStateChange.model_rebuild()
SoftwareInfo.model_rebuild()
OsintInventoryInfo.model_rebuild()
CloudResourcesInventoryInfo.model_rebuild()
EvidenceInfo.model_rebuild()
WebResourcesActivity.model_rebuild()
ApplicationLifecycle.model_rebuild()
ApiActivity.model_rebuild()
DatastoreActivity.model_rebuild()
FileHosting.model_rebuild()
ScanActivity.model_rebuild()
ApplicationError.model_rebuild()
RemediationActivity.model_rebuild()
FileRemediationActivity.model_rebuild()
ProcessRemediationActivity.model_rebuild()
NetworkRemediationActivity.model_rebuild()
DroneFlightsActivity.model_rebuild()
AirborneBroadcastActivity.model_rebuild()
Actor.model_rebuild()
AffectedCode.model_rebuild()
Application.model_rebuild()
AuthFactor.model_rebuild()
Databucket.model_rebuild()
Device.model_rebuild()
Email.model_rebuild()
Evidences.model_rebuild()
File.model_rebuild()
Job.model_rebuild()
LdapPerson.model_rebuild()
ManagedEntity.model_rebuild()
NetworkEndpoint.model_rebuild()
NetworkProxy.model_rebuild()
Osint.model_rebuild()
Process.model_rebuild()
QueryEvidence.model_rebuild()
ResourceDetails.model_rebuild()
