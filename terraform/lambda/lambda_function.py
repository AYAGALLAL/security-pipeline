import os
import json
import csv
import boto3
from typing import Dict, List, Optional, Any

# AWS client (uses the Lambda execution role permissions)
s3 = boto3.client("s3")

REPORTS_BUCKET = os.getenv("SECURITY_REPORTS_BUCKET")
BASE_PREFIX = (os.getenv("SECURITY_REPORTS_PREFIX", "prowler/")).strip().strip("/")

# Comma-separated allowlist of check IDs to remediate (safety guardrail)
# Example env var: ALLOWLIST_CHECK_IDS="s3_bucket_public_access,ec2_instance_public_ip"
ALLOWLIST = set(
    x.strip()
    for x in os.getenv("ALLOWLIST_CHECK_IDS", "s3_bucket_public_access").split(",")
    if x.strip()
)

# If DRY_RUN=true, the function will only print what it would do
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"


# ----------------------------
# Helpers: event decoding
# ----------------------------
def extract_payload_from_sqs_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Supports both:
      - Direct SQS -> body is JSON of your payload
      - SNS -> SQS -> Lambda, where SQS body is an SNS envelope and the actual payload is in body["Message"]

    Returns your payload as a dict.
    """
    body_raw = record.get("body", "")

    # 1) Parse the outer body
    try:
        outer = json.loads(body_raw) if isinstance(body_raw, str) else (body_raw or {})
    except json.JSONDecodeError:
        # Not JSON at all
        print("[WARN] SQS record body is not valid JSON:", body_raw)
        return {}

    # 2) If SNS -> SQS, the outer object contains "Type":"Notification" and "Message":"{...}"
    if isinstance(outer, dict) and outer.get("Type") == "Notification" and "Message" in outer:
        msg = outer.get("Message")
        try:
            return json.loads(msg) if isinstance(msg, str) else (msg or {})
        except json.JSONDecodeError:
            print("[WARN] SNS Message is not valid JSON:", msg)
            return {}

    # 3) Otherwise treat outer as the actual payload (direct SQS)
    return outer if isinstance(outer, dict) else {}


# ----------------------------
# Helpers: CSV parsing
# ----------------------------
def _detect_delimiter(header_line: str) -> str:
    """
    Prowler CSV delimiter can differ depending on environment.
    We'll detect the most frequent delimiter in the header line.
    """
    counts = {
        ";": header_line.count(";"),
        ",": header_line.count(","),
        "\t": header_line.count("\t"),
    }
    return max(counts, key=counts.get)


def parse_csv_bytes(data: bytes) -> List[Dict[str, str]]:
    """
    Convert CSV bytes into a list of dict rows.
    Each row is a mapping: column_name -> value (as strings).
    """
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if not lines:
        return []

    delim = _detect_delimiter(lines[0])
    reader = csv.DictReader(lines, delimiter=delim)
    return list(reader)


def list_csv_keys(bucket: str, prefix: str) -> List[str]:
    """
    List all .csv objects under s3://bucket/prefix/
    """
    keys: List[str] = []
    paginator = s3.get_paginator("list_objects_v2")

    normalized_prefix = prefix.rstrip("/") + "/"

    for page in paginator.paginate(Bucket=bucket, Prefix=normalized_prefix):
        for obj in page.get("Contents", []):
            k = obj["Key"]
            if k.lower().endswith(".csv"):
                keys.append(k)

    return keys


# ----------------------------
# Helpers: row field extraction
# ----------------------------
def _status_from_row(row: Dict[str, str]) -> str:
    """
    Normalize status field to compare against FAIL.
    """
    for k in ("STATUS", "Status", "status"):
        if row.get(k):
            return row[k].strip().upper()
    return ""


def _check_id_from_row(row: Dict[str, str]) -> Optional[str]:
    """
    Extract the prowler check id from a row.
    """
    for k in ("CHECK_ID", "CHECK ID", "CHECK"):
        if row.get(k):
            return row[k].strip()
    return None


def _bucket_from_row(row: Dict[str, str]) -> Optional[str]:
    # Prowler v5 CSV commonly uses these fields
    candidates = [
        row.get("RESOURCE_UID"),
        row.get("RESOURCE_NAME"),
        row.get("RESOURCE_ID"),
        row.get("RESOURCE ARN"),
        row.get("RESOURCE_ARN"),
        row.get("RESOURCE"),
        row.get("RESOURCE_DETAILS"),
    ]

    for c in candidates:
        if not c:
            continue
        c = str(c).strip()

        # If it's JSON (sometimes RESOURCE_DETAILS is JSON), try to extract a bucket-ish field
        if c.startswith("{") and c.endswith("}"):
            try:
                details = json.loads(c)
                for k in ("bucket", "bucket_name", "Bucket", "BucketName", "name"):
                    v = details.get(k)
                    if v:
                        return str(v).strip()
            except Exception:
                pass

        # ARN form: arn:aws:s3:::bucket-name
        if "arn:aws:s3:::" in c:
            return c.split("arn:aws:s3:::")[-1].split("/")[0].strip()

        # Plain bucket name sanity check
        if " " not in c and "/" not in c and ":" not in c:
            return c

    return None



# ----------------------------
# Remediation actions
# ----------------------------
def remediate_s3_public_access(bucket: str) -> None:
    """
    Block all public access on the target bucket using PublicAccessBlock.
    Requires permission:
      - s3:PutPublicAccessBlock
    """
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


# ----------------------------
# Lambda entrypoint
# ----------------------------
def lambda_handler(event, context):
    """
    Expected flow:
      - SQS triggers Lambda
      - Each SQS record contains either:
          a) your JSON payload (direct SQS)
          b) SNS envelope containing "Message" which is your JSON payload (SNS -> SQS)

    Your payload should contain:
      {
        "event": "prowler_remediate_needed",
        "s3_bucket": "<bucket-name>",
        "s3_prefix": "prowler/<run-id-or-prefix>"
      }
    """
    print("Received event:", json.dumps(event))

    for record in event.get("Records", []):
        # Decode record body safely (handles SNS->SQS and direct SQS)
        payload = extract_payload_from_sqs_record(record)

        if not payload:
            print("[WARN] Empty/invalid payload, skipping record.")
            continue

        # Only act on remediation messages
        if payload.get("event") != "prowler_remediate_needed":
            print("Skipping non-remediation event:", payload.get("event"))
            continue

        # Where Prowler CSV(s) were uploaded
        bucket = payload.get("s3_bucket")
        prefix = payload.get("s3_prefix")

        if not bucket or not prefix:
            raise ValueError(
                "Missing s3_bucket or s3_prefix in message payload. "
                "Upload CSV to S3 and include these pointers in the message."
            )

        # List all CSV files under the given prefix
        csv_keys = list_csv_keys(bucket, prefix)
        if not csv_keys:
            print(f"[INFO] No CSVs found in s3://{bucket}/{prefix}/")
            continue

        # Process every CSV found under that prefix
        for key in csv_keys:
            print(f"[INFO] Processing s3://{bucket}/{key}")

            obj = s3.get_object(Bucket=bucket, Key=key)
            rows = parse_csv_bytes(obj["Body"].read())

            for row in rows:
                # We remediate only failing checks
                if _status_from_row(row) != "FAIL":
                    continue

                check_id = _check_id_from_row(row)

                # Safety: only allow checks explicitly in ALLOWLIST
                if not check_id or check_id not in ALLOWLIST:
                    continue

                # Extract target bucket from row (for S3 checks)
                bucket_name = _bucket_from_row(row)
                if not bucket_name:
                    print(
                        f"[WARN] FAIL row but no bucket parsed. "
                        f"check_id={check_id} row_keys={list(row.keys())}"
                    )
                    continue

                # Execute remediation based on check id
                if check_id == "s3_bucket_public_access":
                    remediate_s3_public_access(bucket_name)

    return {"ok": True}
