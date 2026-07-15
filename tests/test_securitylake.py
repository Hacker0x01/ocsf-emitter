"""Unit tests for the Security Lake Parquet writer layer."""

from __future__ import annotations

import io

import pyarrow.parquet as pq
import pytest

from ocsf_emitter import Activity, Severity, build_detection_finding
from ocsf_emitter import securitylake as sl
from ocsf_emitter._models import DetectionFinding


def _finding(uid: str, time_ms: int) -> DetectionFinding:
    return build_detection_finding(
        uid=uid,
        title="t",
        severity=Severity.HIGH,
        message="m",
        activity=Activity.CREATE,
        time_ms=time_ms,
    )


def test_partition_prefix_format() -> None:
    prefix = sl.partition_prefix(
        source_location="my_detector",
        region="us-east-1",
        account_id="123456789012",
        event_day="20250715",
    )
    assert prefix == ("ext/my_detector/region=us-east-1/accountId=123456789012/eventDay=20250715/")


def test_event_day_from_ms_is_utc() -> None:
    # 2025-07-15T04:00:00Z
    assert sl.event_day_from_ms(1_752_552_000_000) == "20250715"


def test_build_parquet_object_key_and_roundtrip() -> None:
    findings = [_finding(f"det-{i}", 1_752_566_400_000 + i * 1000) for i in range(3)]
    obj = sl.build_parquet_object(
        findings,
        source_location="my_detector",
        region="us-east-1",
        account_id="123456789012",
        object_name="batch-001",
    )
    assert obj.key == (
        "ext/my_detector/region=us-east-1/accountId=123456789012/"
        "eventDay=20250715/batch-001.parquet"
    )
    assert obj.record_count == 3

    table = pq.read_table(io.BytesIO(obj.data))
    assert table.num_rows == 3


def test_parquet_uses_zstd_compression() -> None:
    obj = sl.build_parquet_object(
        [_finding("det-1", 1_752_566_400_000)],
        source_location="s",
        region="us-east-1",
        account_id="123456789012",
        object_name="o",
    )
    meta = pq.read_metadata(io.BytesIO(obj.data))
    assert meta.row_group(0).column(0).compression == "ZSTD"


def test_records_sorted_by_time() -> None:
    # Deliberately out of order.
    findings = [
        _finding("det-late", 1_752_566_405_000),
        _finding("det-early", 1_752_566_400_000),
        _finding("det-mid", 1_752_566_402_000),
    ]
    obj = sl.build_parquet_object(
        findings,
        source_location="s",
        region="us-east-1",
        account_id="123456789012",
        object_name="o",
    )
    times = pq.read_table(io.BytesIO(obj.data)).column("time").to_pylist()
    assert times == sorted(times)


def test_object_name_gets_parquet_suffix() -> None:
    obj = sl.build_parquet_object(
        [_finding("det-1", 1_752_566_400_000)],
        source_location="s",
        region="us-east-1",
        account_id="123456789012",
        object_name="already.parquet",
    )
    assert obj.key.endswith("/already.parquet")
    assert not obj.key.endswith(".parquet.parquet")


def test_empty_findings_rejected() -> None:
    with pytest.raises(ValueError, match="zero findings"):
        sl.build_parquet_object(
            [],
            source_location="s",
            region="us-east-1",
            account_id="123456789012",
            object_name="o",
        )
