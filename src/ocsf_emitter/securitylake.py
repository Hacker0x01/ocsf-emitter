"""AWS Security Lake packaging for OCSF Detection Findings.

Security Lake custom sources must deliver **Parquet** objects (not JSON),
partitioned in S3 by region / account / event-day, with records sorted by time.
This module turns validated findings into a Parquet byte payload and computes
the S3 object key. It does NOT talk to S3 -- the caller uploads the bytes at the
returned key, keeping transport out of the package (see README).

Requirements implemented (per the Security Lake custom-source docs):
    * Apache Parquet, zstandard compression.
    * Data page size <= 1 MB (uncompressed); row group size <= 256 MB.
    * Records sorted by ``time`` within each object.
    * Partition prefix: ``ext/{source}/region={r}/accountId={a}/eventDay={YYYYMMDD}/``.

Batch **one OCSF class per Parquet object** (one Security Lake source location
per class). Mixing classes in a single object yields a sparse union of every
class's columns and defeats Security Lake's per-source OCSF mapping.

This module requires the ``securitylake`` extra (pyarrow):
    uv pip install -e ".[securitylake]"
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from .emit import emit
from .validate import SupportedEvent

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except ImportError as exc:  # pragma: no cover - exercised via extra-not-installed path
    raise ImportError(
        "ocsf_emitter.securitylake requires the 'securitylake' extra: "
        'pip install "ocsf-emitter[securitylake]"'
    ) from exc

# Security Lake object-shape limits.
_DATA_PAGE_SIZE_BYTES = 1024 * 1024  # 1 MB, uncompressed
_ROW_GROUP_SIZE_ROWS = 256 * 1024  # bounded well under the 256 MB compressed cap
_COMPRESSION = "zstd"


@dataclass(frozen=True, slots=True)
class ParquetObject:
    """A ready-to-upload Security Lake object: Parquet ``data`` at S3 ``key``."""

    key: str
    data: bytes
    record_count: int


def partition_prefix(*, source_location: str, region: str, account_id: str, event_day: str) -> str:
    """Build the Security Lake S3 partition prefix.

    ``ext/{source_location}/region={region}/accountId={account_id}/eventDay={event_day}/``
    """
    return f"ext/{source_location}/region={region}/accountId={account_id}/eventDay={event_day}/"


def event_day_from_ms(time_ms: int) -> str:
    """Convert an epoch-ms timestamp to a Security Lake ``eventDay`` (UTC YYYYMMDD)."""
    return datetime.fromtimestamp(time_ms / 1000, tz=UTC).strftime("%Y%m%d")


def _validated_payloads(findings: Iterable[SupportedEvent]) -> list[dict[str, object]]:
    # emit() validates each finding and returns a JSON-serializable dict.
    payloads = [emit(f) for f in findings]
    # Security Lake asks for records sorted by time within each object.
    payloads.sort(key=lambda p: p.get("time", 0))
    return payloads


def to_parquet_bytes(findings: Sequence[SupportedEvent]) -> bytes:
    """Validate, sort by time, and serialize findings to a Parquet byte string."""
    if not findings:
        raise ValueError("cannot build a Parquet object from zero findings")
    payloads = _validated_payloads(findings)
    table = pa.Table.from_pylist(payloads)

    import io

    buf = io.BytesIO()
    pq.write_table(
        table,
        buf,
        compression=_COMPRESSION,
        data_page_size=_DATA_PAGE_SIZE_BYTES,
        row_group_size=_ROW_GROUP_SIZE_ROWS,
    )
    return buf.getvalue()


def build_parquet_object(
    findings: Sequence[SupportedEvent],
    *,
    source_location: str,
    region: str,
    account_id: str,
    object_name: str,
    event_day: str | None = None,
) -> ParquetObject:
    """Package findings into a single Security Lake Parquet object.

    Args:
        findings: One or more validated-on-emit detection findings. All should
            share an event day; ``event_day`` defaults to the day of the
            earliest finding's ``time``.
        source_location: The unique prefix Security Lake assigned to this source.
        region: AWS region the data is uploaded to (e.g. ``us-east-1``).
        account_id: AWS account id the records pertain to (or ``external...``).
        object_name: File name for the object (``.parquet`` appended if absent).
        event_day: ``YYYYMMDD`` UTC partition day. Defaults to the earliest
            finding's event day.

    Returns:
        A :class:`ParquetObject` with the S3 ``key`` and Parquet ``data`` bytes.
    """
    if not findings:
        raise ValueError("cannot build a Parquet object from zero findings")

    data = to_parquet_bytes(findings)

    if event_day is None:
        earliest = min(int(f.time) for f in findings)
        event_day = event_day_from_ms(earliest)

    if not object_name.endswith(".parquet"):
        object_name = f"{object_name}.parquet"

    prefix = partition_prefix(
        source_location=source_location,
        region=region,
        account_id=account_id,
        event_day=event_day,
    )
    return ParquetObject(key=prefix + object_name, data=data, record_count=len(findings))
