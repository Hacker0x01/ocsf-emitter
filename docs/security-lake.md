# AWS Security Lake

This package targets **AWS Security Lake custom-source** ingestion end to end.

## Version pin

Security Lake custom sources accept OCSF **1.1.0 / 1.0.0-rc.2**, and the
[AWS OCSF validation tool](https://github.com/aws-samples/amazon-security-lake-ocsf-validation)
maps `detection_finding` only under **1.1.0**. `ocsf-emitter` therefore pins
**1.1.0**. The builder also stamps the sibling label fields Security Lake
expects: `class_name` (`"Detection Finding"`) and `category_name` (`"Findings"`).

!!! warning "Bumping the version"
    A newer OCSF version will fail Security Lake ingestion and the blocking
    `aws-validation` CI job. Keep the pin at a Security-Lake-supported version.

## Validation is proven against AWS's tool

CI runs AWS's OCSF validation tool against an emitted finding as a **blocking**
job, pinned at a known commit. To reproduce locally:

```bash
git clone https://github.com/aws-samples/amazon-security-lake-ocsf-validation.git /tmp/aws-ocsf
pip install -e ".[securitylake]"
pip install -r /tmp/aws-ocsf/requirements.txt pytest
OCSF_AWS_VALIDATION_DIR=/tmp/aws-ocsf pytest tests/test_integ_aws_validation.py -v
```

The tool reports `VALID OCSF.` for a finding produced by this package.

## Parquet packaging

Security Lake wants **Parquet** objects (not JSON), zstd-compressed, partitioned
in S3 by region/account/event-day and sorted by time. The optional
[`securitylake`](api/securitylake.md) module does this without touching S3 — you
upload the returned bytes at the returned key.

Install the extra:

```bash
pip install "ocsf-emitter[securitylake]"
```

```python
from ocsf_emitter import securitylake as sl

obj = sl.build_parquet_object(
    findings,                       # a batch of built findings
    source_location="my_detector",  # the prefix Security Lake assigned you
    region="us-east-1",
    account_id="123456789012",
    object_name="batch-001",
)
# obj.key  -> ext/my_detector/region=us-east-1/accountId=.../eventDay=YYYYMMDD/batch-001.parquet
# obj.data -> Parquet bytes (zstd); upload to your Security Lake S3 bucket at obj.key
```

The writer validates every finding (via `emit`), sorts records by `time`, uses
zstd compression, and bounds data-page (≤1 MB) and row-group sizes per the
Security Lake custom-source requirements. See the
[Security Lake API reference](api/securitylake.md) for details.
