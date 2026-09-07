import hashlib
import json
from pathlib import Path


def calculate_sha256(file_path):
    """Calculate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


def create_hash_record(file_path, previous_hash=""):
    """Create one tamper-evident hash record."""
    file_path = Path(file_path)

    file_hash = calculate_sha256(file_path)

    record_data = (
        file_path.name
        + "|"
        + file_hash
        + "|"
        + previous_hash
    )

    record_hash = hashlib.sha256(
        record_data.encode()
    ).hexdigest()

    return {
        "file": str(file_path),
        "sha256": file_hash,
        "previous_hash": previous_hash,
        "record_hash": record_hash
    }


def build_hash_chain(files, output_path):
    """Build a SHA-256 hash chain for evidence files."""
    previous_hash = ""
    chain = []

    for file_path in files:
        record = create_hash_record(
            file_path,
            previous_hash
        )

        chain.append(record)
        previous_hash = record["record_hash"]

    output_path = Path(output_path)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(chain, file, indent=4)

    return chain


def verify_hash_chain(hash_file):
    """Verify evidence files and their hash chain."""
    hash_file = Path(hash_file)

    if not hash_file.exists():
        return {
            "success": False,
            "status": "HASH RECORD NOT FOUND",
            "issues": [
                "Hash record file does not exist."
            ]
        }

    with open(hash_file, "r", encoding="utf-8") as file:
        chain = json.load(file)

    previous_hash = ""
    issues = []

    for record in chain:
        path = Path(record["file"])

        # Check whether evidence still exists
        if not path.exists():
            issues.append(
                f"Missing evidence file: {path.name}"
            )
            continue

        # Recalculate SHA-256
        current_sha = calculate_sha256(path)

        if current_sha != record["sha256"]:
            issues.append(
                f"TAMPER DETECTED: {path.name}"
            )

        # Verify chain relationship
        record_data = (
            path.name
            + "|"
            + record["sha256"]
            + "|"
            + previous_hash
        )

        expected_record_hash = hashlib.sha256(
            record_data.encode()
        ).hexdigest()

        if expected_record_hash != record["record_hash"]:
            issues.append(
                f"Hash-chain break: {path.name}"
            )

        previous_hash = record["record_hash"]

    return {
        "success": not issues,
        "status": (
            "INTEGRITY VERIFIED"
            if not issues
            else "TAMPER DETECTED"
        ),
        "records": len(chain),
        "issues": issues
    }


def test_hash_chain():
    """Test hash creation and tamper detection."""

    test_folder = Path("test-data/integrity_test")
    test_folder.mkdir(
        parents=True,
        exist_ok=True
    )

    file1 = test_folder / "evidence_01.txt"
    file2 = test_folder / "evidence_02.txt"

    original_content_1 = (
        "Original forensic evidence file 1."
    )

    original_content_2 = (
        "Original forensic evidence file 2."
    )

    # Create test evidence
    file1.write_text(
        original_content_1,
        encoding="utf-8"
    )

    file2.write_text(
        original_content_2,
        encoding="utf-8"
    )

    hash_file = test_folder / "evidence_chain.json"

    print("\n=== SHA-256 Evidence Integrity Test ===")

    print("\nEvidence files:")
    print(f"  {file1.name}")
    print(f"  {file2.name}")

    # Build hash chain
    chain = build_hash_chain(
        [file1, file2],
        hash_file
    )

    print("\n=== Hash Chain Created ===")

    for index, record in enumerate(chain, start=1):
        print(f"\nRecord {index}")
        print(f"File: {Path(record['file']).name}")
        print(f"SHA-256: {record['sha256']}")
        print(f"Record Hash: {record['record_hash']}")

    # Verify original evidence
    result = verify_hash_chain(hash_file)

    print("\n=== Initial Verification ===")
    print(f"Status: {result['status']}")
    print(f"Records checked: {result['records']}")

    if result["success"]:
        print("Integrity check: PASSED")

    # Tamper with second evidence file
    print("\n=== Tampering Simulation ===")

    file2.write_text(
        "MODIFIED EVIDENCE - TAMPER TEST",
        encoding="utf-8"
    )

    tampered_result = verify_hash_chain(
        hash_file
    )

    print(f"Status: {tampered_result['status']}")

    for issue in tampered_result["issues"]:
        print(f"  {issue}")

    # Restore original evidence
    file2.write_text(
        original_content_2,
        encoding="utf-8"
    )

    # Final verification
    final_result = verify_hash_chain(
        hash_file
    )

    print("\n=== Final Verification ===")
    print(f"Status: {final_result['status']}")

    if final_result["success"]:
        print("\nStatus: SHA-256 INTEGRITY VERIFIED")


if __name__ == "__main__":
    test_hash_chain()