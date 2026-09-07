from pathlib import Path


def assess_trim_awareness(evidence_path: str):
    """
    Provide a TRIM-aware assessment for SSD-based evidence.

    Note:
    TRIM state cannot be reliably determined from a normal
    file-level scan. This module reports the recovery limitation
    instead of falsely claiming actual SSD controller state.
    """

    path = Path(evidence_path)

    if not path.exists():
        return {
            "status": "ERROR",
            "message": "Evidence file not found."
        }

    size = path.stat().st_size

    return {
        "storage_awareness": "SSD/TRIM-aware",
        "evidence_size": size,
        "trim_state": "UNKNOWN",
        "recoverability": "UNCERTAIN",
        "warning": (
            "TRIM may permanently remove deleted SSD data. "
            "File-level analysis cannot reliably determine "
            "whether TRIM has already been executed."
        ),
        "recommendation": (
            "Preserve the original storage device and perform "
            "forensic acquisition before analysis."
        )
    }


if __name__ == "__main__":

    project_root = Path(__file__).resolve().parents[2]

    evidence_file = (
        project_root
        / "test-data"
        / "synthetic_evidence.bin"
    )

    print("\n=== ForensicVault SSD/TRIM Awareness ===")

    result = assess_trim_awareness(
        str(evidence_file)
    )

    for key, value in result.items():
        print(f"{key}: {value}")