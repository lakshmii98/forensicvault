from pathlib import Path
import hashlib


# ============================================================
# ForensicVault - Evidence Integrity Engine
# ============================================================

def calculate_sha256(file_path: str):
    """
    Calculate SHA-256 hash of a file.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    sha256 = hashlib.sha256()

    with open(path, "rb") as file:

        while True:

            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def verify_integrity(
    file_path: str,
    expected_hash: str
):
    """
    Compare the current SHA-256 hash with
    an expected hash.
    """

    current_hash = calculate_sha256(file_path)

    matches = (
        current_hash.lower()
        == expected_hash.lower()
    )

    return {
        "file": file_path,
        "expected_hash": expected_hash,
        "current_hash": current_hash,
        "integrity_verified": matches
    }


# ============================================================
# TEST PROGRAM
# ============================================================

if __name__ == "__main__":

    project_root = Path(__file__).resolve().parents[2]

    test_file = (
        project_root
        / "test-data"
        / "synthetic_evidence.bin"
    )

    print("\n=== ForensicVault Integrity Engine ===")

    file_hash = calculate_sha256(
        str(test_file)
    )

    print(f"File: {test_file}")
    print(f"SHA-256: {file_hash}")

    # Verify against the same hash
    result = verify_integrity(
        str(test_file),
        file_hash
    )

    print("\n=== Integrity Verification ===")

    print(
        f"Expected hash: "
        f"{result['expected_hash']}"
    )

    print(
        f"Current hash: "
        f"{result['current_hash']}"
    )

    if result["integrity_verified"]:

        print(
            "\nStatus: INTEGRITY VERIFIED"
        )

    else:

        print(
            "\nStatus: INTEGRITY COMPROMISED"
        )