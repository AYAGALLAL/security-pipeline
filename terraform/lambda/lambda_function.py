import os
import json
import csv
import boto3
from typing import Dict, List, Optional

s3 = boto3.client("s3")

# Comma-separated allowlist of check IDs to remediate
ALLOWLIST = set(x.strip() for x in os.getenv("ALLOWLIST_CHECK_IDS", "s3_bucket_public_access").split(",") if x.strip())
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"


def _detect_delimiter(header_line: str) -> str:
    counts = {
        ";": header_line.count(";"),
        ",": header_line.count(","),
        "\t": header_line.count("\t"),
    }
    return max(counts, key=counts.get)


def _bucket_from_row(row: Dict[str, str]) -> Optional[str]:
    # Try common Prowler columns
    candidates = [
        row.get("RESOURCE_ID"),
        row.get("RESOURCE ARN"),
        row.get("RESOURCE_ARN"),
        row.get("RESOURCE"),
    ]
    for c in candidates:
        if not c:
            continue
        c = c.strip()

        # ARN form: arn:aws:s3:::bucket-name
        if c.startswith("arn:aws:s3:::"):
            return c.split("arn:aws:s3:::")[-1].strip()

        # Sometimes it's just the bucket name
        # (basic sanity check)
        if " " not in c and "/" not in c and ":" not in c:
            return c

    return None


def _check_id_from_row(row: Dict[str, str]) -> Optional[str]:
    for k in ("CHECK_ID", "CHECK ID", "CHECK"):
        if k in row and row[k]:
            return row[k].strip()
    return None


def _status_from_row(row: Dict[str, str]) -> str:
    # Your sample uses STATUS
    for k in ("STATUS", "Status", "status"):
        if k in row and row[k]:
            return row[k].strip().upper()
    return ""


def remediate_s3_public_access(bucket: str) -> None:
    pab = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }

    if DRY_RUN:
        print(f"[DRY_RUN] Would set PublicAccessBlock on bucket={bucket}: {pab}")
        return

    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration=pab,
    )
    print(f"[OK] Set PublicAccessBlock on bucket={bucket}")


def parse_csv_bytes(data: bytes) -> List[Dict[str, str]]:
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if not lines:
        return []

    delim = _detect_delimiter(lines[0])
    reader = csv.DictReader(lines, delimiter=delim)
    return list(reader)


def list_csv_keys(bucket: str, prefix: str) -> List[str]:
    keys = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix.rstrip("/") + "/"):
        for obj in page.get("Contents", []):
            k = obj["Key"]
            if k.lower().endswith(".csv"):
                keys.append(k)
    return keys


def lambda_handler(event, context):
    print("Event:", event)

    for record in event.get("Records", []):
        body = json.loads(record["body"])

        if body.get("event") != "prowler_remediate_needed":
            print("Skipping non-remediation event:", body.get("event"))
            continue

        bucket = body.get("s3_bucket")
        prefix = body.get("s3_prefix")

        if not bucket or not prefix:
            raise ValueError("Missing s3_bucket or s3_prefix in message body. Upload CSV to S3 and include pointers.")

        csv_keys = list_csv_keys(bucket, prefix)
        if not csv_keys:
            print(f"No CSVs found in s3://{bucket}/{prefix}/")
            continue

        # Process all CSVs under the prefix
        for key in csv_keys:
            obj = s3.get_object(Bucket=bucket, Key=key)
            rows = parse_csv_bytes(obj["Body"].read())

            for row in rows:
                if _status_from_row(row) != "FAIL":
                    continue

                check_id = _check_id_from_row(row)
                if not check_id or check_id not in ALLOWLIST:
                    # Don’t remediate anything you didn’t explicitly allow
                    continue

                bucket_name = _bucket_from_row(row)
                if not bucket_name:
                    print(f"[WARN] FAIL row but no bucket parsed. check_id={check_id} row_keys={list(row.keys())}")
                    continue

                # Currently only one remediation implemented
                if check_id == "s3_bucket_public_access":
                    remediate_s3_public_access(bucket_name)

    return {"ok": True}
