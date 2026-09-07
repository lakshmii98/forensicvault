from pathlib import Path
from datetime import datetime
import hashlib
import json


def calculate_sha256(file_path: str):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def record_chain_of_custody(
    evidence_path: str,
    action: str,
    log_path: str
):
    """
    Record an evidence handling event.
    """

    evidence_hash = calculate_sha256(
        evidence_path
    )

    record = {
        "timestamp": datetime.now().isoformat(),
        "evidence_file": str(evidence_path),
        "action": action,
        "sha256": evidence_hash
    }

    log_file = Path(log_path)

    records = []

    if log_file.exists():

        with open(log_file, "r") as file:
            records = json.load(file)

    records.append(record)

    with open(log_file, "w") as file:
        json.dump(
            records,
            file,
            indent=4
        )

    return record


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

    print("\n=== ForensicVault Chain of Custody ===")

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

    print("\nStatus: CHAIN OF CUSTODY RECORDED")