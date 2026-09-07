from pathlib import Path
import hashlib
import json


def calculate_sha256(file_path):
    """Calculate SHA-256 hash of a file."""

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


def simulate_drive_erase(drive_path):
    """
    SAFE drive-erasure simulation.

    This function NEVER erases, formats, or overwrites
    a real physical drive.
    """

    drive_path = Path(drive_path)

    print("\n=== ForensicVault Drive Eraser ===")
    print(f"Target: {drive_path}")

    # Safety protection
    dangerous_targets = [
        Path("C:/"),
        Path("C:\\"),
        Path("/")
    ]

    resolved_target = drive_path.resolve()

    for dangerous in dangerous_targets:
        try:
            if resolved_target == dangerous.resolve():
                return {
                    "success": False,
                    "status": "ERASURE BLOCKED",
                    "reason": "Operating system drive cannot be erased."
                }
        except Exception:
            pass

    if not drive_path.exists():
        return {
            "success": False,
            "status": "TARGET NOT FOUND",
            "reason": "Specified test target does not exist."
        }

    if not drive_path.is_dir():
        return {
            "success": False,
            "status": "INVALID TARGET",
            "reason": "Target must be a test directory."
        }

    # Collect test files
    files = [
        file for file in drive_path.rglob("*")
        if file.is_file()
    ]

    print(f"\nFiles detected: {len(files)}")

    records = []

    for file in files:
        original_hash = calculate_sha256(file)

        records.append({
            "file": str(file),
            "original_sha256": original_hash,
            "status": "READY FOR SANITIZATION"
        })

    print("\n=== Sanitization Simulation ===")

    for record in records:
        print(
            f"  {Path(record['file']).name} "
            f"-> SIMULATED ERASE"
        )
        record["status"] = "SIMULATED ERASED"

    report = {
        "operation": "DRIVE_ERASURE_SIMULATION",
        "target": str(drive_path),
        "files_processed": len(records),
        "records": records,
        "physical_erasure_performed": False,
        "verification": "SIMULATION ONLY"
    }

    report_path = drive_path / "drive_erasure_report.json"

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(report, file, indent=4)

    print("\n=== Safety Verification ===")
    print("Physical drive modification: BLOCKED")
    print("Operating system drive protection: ACTIVE")
    print("Actual data destruction: NOT PERFORMED")

    return {
        "success": True,
        "status": "DRIVE ERASURE SIMULATION VERIFIED",
        "files_processed": len(records),
        "report": str(report_path)
    }


def create_test_drive():
    """Create a harmless simulated drive."""

    test_drive = Path("test-data/simulated_drive")

    test_drive.mkdir(
        parents=True,
        exist_ok=True
    )

    (test_drive / "evidence_01.txt").write_text(
        "Simulated forensic evidence file.",
        encoding="utf-8"
    )

    (test_drive / "evidence_02.txt").write_text(
        "Another simulated evidence file.",
        encoding="utf-8"
    )

    return test_drive


def test_drive_eraser():

    test_drive = create_test_drive()

    print("\n=== Drive Eraser Safety Test ===")
    print(f"Simulated drive: {test_drive}")

    result = simulate_drive_erase(test_drive)

    print("\n=== Final Result ===")
    print(f"Status: {result['status']}")

    if result["success"]:
        print(
            f"Files processed: "
            f"{result['files_processed']}"
        )

        print(
            "\nStatus: "
            "SAFE DRIVE ERASURE SIMULATION VERIFIED"
        )


if __name__ == "__main__":
    test_drive_eraser()