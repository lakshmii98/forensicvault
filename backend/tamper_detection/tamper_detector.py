from pathlib import Path
import hashlib
import json


# ============================================================
# ForensicVault - Tamper Detection Engine
# ============================================================

def calculate_hash(file_path: str):
    """Calculate SHA-256 hash of a file."""

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def create_baseline(file_path: str, baseline_path: str):
    """
    Create a trusted baseline hash for evidence.
    """

    file_hash = calculate_hash(file_path)

    baseline = {
        "file": str(file_path),
        "sha256": file_hash
    }

    with open(baseline_path, "w") as file:
        json.dump(baseline, file, indent=4)

    return baseline


def detect_tampering(
    file_path: str,
    baseline_path: str
):
    """
    Compare the current file hash with the
    trusted baseline hash.
    """

    with open(baseline_path, "r") as file:
        baseline = json.load(file)

    current_hash = calculate_hash(file_path)

    tampered = (
        current_hash.lower()
        != baseline["sha256"].lower()
    )

    return {
        "file": str(file_path),
        "original_hash": baseline["sha256"],
        "current_hash": current_hash,
        "tampered": tampered
    }


# ============================================================
# TEST PROGRAM
# ============================================================

if __name__ == "__main__":

    project_root = Path(__file__).resolve().parents[2]

    evidence_file = (
        project_root
        / "test-data"
        / "synthetic_evidence.bin"
    )

    baseline_file = (
        project_root
        / "test-data"
        / "evidence_baseline.json"
    )

    print("\n=== ForensicVault Tamper Detection ===")

    # Create trusted baseline
    baseline = create_baseline(
        str(evidence_file),
        str(baseline_file)
    )

    print("\n=== Trusted Baseline ===")
    print(f"SHA-256: {baseline['sha256']}")

    # Check for tampering
    result = detect_tampering(
        str(evidence_file),
        str(baseline_file)
    )

    print("\n=== Tamper Verification ===")
    print(
        f"Original hash: "
        f"{result['original_hash']}"
    )

    print(
        f"Current hash: "
        f"{result['current_hash']}"
    )

    if result["tampered"]:

        print(
            "\nStatus: ⚠️ TAMPERING DETECTED"
        )

    else:

        print(
            "\nStatus: ✅ NO TAMPERING DETECTED"
        )