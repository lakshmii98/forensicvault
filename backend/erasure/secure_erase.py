from pathlib import Path
import os


# ============================================================
# ForensicVault - Secure Data Erasure Engine
# ============================================================


def overwrite_file(file_path: str, passes: int = 3):
    """
    Overwrite a file multiple times to make its original
    contents difficult to recover.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    if not path.is_file():
        raise ValueError(
            f"Not a file: {file_path}"
        )

    file_size = path.stat().st_size

    print("\n=== ForensicVault Secure Erasure ===")
    print(f"Target file: {path}")
    print(f"File size: {file_size} bytes")
    print(f"Overwrite passes: {passes}")

    for current_pass in range(1, passes + 1):

        print(
            f"Overwrite pass {current_pass}/{passes}..."
        )

        with open(path, "r+b") as file:

            remaining = file_size

            while remaining > 0:

                chunk_size = min(
                    1024 * 1024,
                    remaining
                )

                file.write(
                    os.urandom(chunk_size)
                )

                remaining -= chunk_size

            file.flush()
            os.fsync(file.fileno())

    return True


def verify_erasure(file_path: str):
    """
    Verify that the file still exists and check whether
    its contents can be read after overwriting.
    """

    path = Path(file_path)

    if not path.exists():
        return {
            "exists": False,
            "readable": False,
            "status": "ERASED"
        }

    try:

        with open(path, "rb") as file:
            data = file.read()

        return {
            "exists": True,
            "readable": True,
            "size": len(data),
            "status": "OVERWRITTEN"
        }

    except Exception:

        return {
            "exists": True,
            "readable": False,
            "status": "UNREADABLE"
        }


def secure_erase(file_path: str, passes: int = 3):
    """
    Perform secure overwrite and verification.
    """

    overwrite_file(
        file_path,
        passes
    )

    verification = verify_erasure(
        file_path
    )

    return verification


# ============================================================
# TEST PROGRAM
# ============================================================

if __name__ == "__main__":

    # Create a temporary test file
    test_file = (
        Path(__file__).resolve().parents[2]
        / "test-data"
        / "erase_test.txt"
    )

    # Create test data
    with open(test_file, "w") as file:
        file.write(
            "CONFIDENTIAL FORENSIC DATA - "
            "THIS MUST BE ERASED"
        )

    print("\nTest file created:")
    print(test_file)

    # Perform secure erasure
    result = secure_erase(
        str(test_file),
        passes=3
    )

    # Display verification result
    print("\n=== Erasure Verification ===")

    for key, value in result.items():
        print(f"{key}: {value}")

    if result["status"] == "OVERWRITTEN":

        print(
            "\nStatus: SECURE OVERWRITE COMPLETED"
        )

    elif result["status"] == "ERASED":

        print(
            "\nStatus: FILE ERASED"
        )

    else:

        print(
            "\nStatus: VERIFICATION REQUIRES REVIEW"
        )