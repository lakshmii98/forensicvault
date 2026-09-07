from pathlib import Path
from datetime import datetime
import hashlib
import json


GENESIS_HASH = "GENESIS"


def calculate_sha256(file_path: str):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def calculate_record_hash(record: dict):
    data = (
        record["timestamp"]
        + record["evidence_file"]
        + record["action"]
        + record["sha256"]
        + record["previous_hash"]
    )

    return hashlib.sha256(
        data.encode("utf-8")
    ).hexdigest()


def migrate_records(records):
    """
    Migrate old chain-of-custody records into
    the new hash-chain structure.
    """

    migrated = []

    previous_hash = GENESIS_HASH

    for record in records:

        if "previous_hash" not in record:
            record["previous_hash"] = previous_hash

        if "hash" not in record:
            record["hash"] = calculate_record_hash(record)

        previous_hash = record["hash"]

        migrated.append(record)

    return migrated


def record_chain_of_custody(
    evidence_path: str,
    action: str,
    log_path: str
):
    """
    Record an evidence handling event using
    a tamper-evident hash chain.
    """

    evidence_hash = calculate_sha256(
        evidence_path
    )

    log_file = Path(log_path)

    records = []

    if log_file.exists():

        with open(log_file, "r") as file:
            records = json.load(file)

        records = migrate_records(records)

    if records:
        previous_hash = records[-1]["hash"]
    else:
        previous_hash = GENESIS_HASH

    record = {
        "timestamp": datetime.now().isoformat(),
        "evidence_file": str(evidence_path),
        "action": action,
        "sha256": evidence_hash,
        "previous_hash": previous_hash
    }

    record["hash"] = calculate_record_hash(record)

    records.append(record)

    with open(log_file, "w") as file:
        json.dump(
            records,
            file,
            indent=4
        )

    return record


def verify_chain(log_path: str):
    """
    Verify the complete hash chain.
    """

    log_file = Path(log_path)

    if not log_file.exists():
        return {
            "valid": False,
            "message": "Chain log not found."
        }

    with open(log_file, "r") as file:
        records = json.load(file)

    if not records:
        return {
            "valid": True,
            "records": 0,
            "message": "Chain is empty."
        }

    expected_previous_hash = GENESIS_HASH

    for index, record in enumerate(records):

        if record["previous_hash"] != expected_previous_hash:
            return {
                "valid": False,
                "failed_at": index + 1,
                "message": "Previous hash mismatch."
            }

        expected_hash = calculate_record_hash(record)

        if record["hash"] != expected_hash:
            return {
                "valid": False,
                "failed_at": index + 1,
                "message": "Record hash mismatch."
            }

        expected_previous_hash = record["hash"]

    return {
        "valid": True,
        "records": len(records),
        "message": "Hash chain is valid."
    }


if __name__ == "__main__":

    project_root = Path(__file__).resolve().parents[2]

    evidence_file = (
        project_root
        / "test-data"
        / "synthetic_evidence.bin"
    )

    log_file = (
        project_root
        / "test-data"
        / "chain_of_custody.json"
    )

    print("\n=== ForensicVault Hash-Chain Audit Log ===")

    record = record_chain_of_custody(
        str(evidence_file),
        "Evidence acquired and integrity recorded",
        str(log_file)
    )

    print(
        f"Timestamp: {record['timestamp']}"
    )

    print(
        f"Evidence: {record['evidence_file']}"
    )

    print(
        f"Action: {record['action']}"
    )

    print(
        f"SHA-256: {record['sha256']}"
    )

    print(
        f"Previous Hash: {record['previous_hash']}"
    )

    print(
        f"Record Hash: {record['hash']}"
    )

    verification = verify_chain(
        str(log_file)
    )

    print("\n=== Chain Verification ===")

    print(
        f"Records: {verification.get('records', 0)}"
    )

    print(
        f"Status: {verification['message']}"
    )

    if verification["valid"]:
        print("\n✅ HASH CHAIN VALID")
    else:
        print("\n⚠️ HASH CHAIN INVALID")