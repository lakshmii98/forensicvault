 
from pathlib import Path
import os


# ============================================================
# ForensicVault - Secure File Erasure Engine
# ============================================================


def secure_erase_file(
    file_path,
    passes=3
):
    """
    Securely erase a file by overwriting its contents
    before deleting it.

    Prototype implementation intended for controlled
    test files only.

    NEVER use this on system-critical files.
    """

    file_path = Path(file_path)

    # --------------------------------------------------------
    # Check file exists
    # --------------------------------------------------------

    if not file_path.exists():

        return {
            "success": False,
            "status": "NOT FOUND",
            "message":
                f"File does not exist: {file_path}"
        }

    # --------------------------------------------------------
    # Ensure target is a file
    # --------------------------------------------------------

    if not file_path.is_file():

        return {
            "success": False,
            "status": "INVALID TARGET",
            "message":
                "Target is not a regular file."
        }

    try:

        file_size = file_path.stat().st_size

        # ----------------------------------------------------
        # Overwrite file
        # ----------------------------------------------------

        with open(
            file_path,
            "r+b"
        ) as file:

            for pass_number in range(passes):

                file.seek(0)

                if pass_number % 2 == 0:

                    # Overwrite with zeros
                    pattern = b"\x00"

                else:

                    # Overwrite with 0xFF
                    pattern = b"\xFF"

                remaining = file_size
                chunk_size = 4096

                while remaining > 0:

                    write_size = min(
                        chunk_size,
                        remaining
                    )

                    file.write(
                        pattern * write_size
                    )

                    remaining -= write_size

                file.flush()

                os.fsync(
                    file.fileno()
                )

        # ----------------------------------------------------
        # Delete file
        # ----------------------------------------------------

        file_path.unlink()

        # ----------------------------------------------------
        # Verify deletion
        # ----------------------------------------------------

        if file_path.exists():

            return {
                "success": False,
                "status": "VERIFICATION FAILED",
                "message":
                    "File still exists after deletion."
            }

        return {
            "success": True,
            "status": "SECURELY ERASED",
            "file": str(file_path),
            "original_size": file_size,
            "passes": passes,
            "verified": True
        }

    except Exception as error:

        return {
            "success": False,
            "status": "ERROR",
            "message": str(error)
        }


# ============================================================
# SECURE FOLDER ERASURE
# ============================================================

def secure_erase_folder(
    folder_path,
    passes=3
):
    """
    Securely erase every file inside a folder,
    including files in nested directories.

    After erasing the files, empty directories are removed.

    Intended for controlled test data only.
    """

    folder_path = Path(folder_path)

    # --------------------------------------------------------
    # Check folder exists
    # --------------------------------------------------------

    if not folder_path.exists():

        return {
            "success": False,
            "status": "NOT FOUND",
            "message":
                f"Folder does not exist: {folder_path}"
        }

    # --------------------------------------------------------
    # Ensure target is a directory
    # --------------------------------------------------------

    if not folder_path.is_dir():

        return {
            "success": False,
            "status": "INVALID TARGET",
            "message":
                "Target is not a folder."
        }

    results = []

    # --------------------------------------------------------
    # Find all files recursively
    # --------------------------------------------------------

    files = [
        path
        for path in folder_path.rglob("*")
        if path.is_file()
    ]

    # --------------------------------------------------------
    # Securely erase each file
    # --------------------------------------------------------

    for file_path in files:

        result = secure_erase_file(
            file_path,
            passes=passes
        )

        results.append(result)

    # --------------------------------------------------------
    # Remove empty nested directories
    # --------------------------------------------------------

    directories = sorted(
        [
            path
            for path in folder_path.rglob("*")
            if path.is_dir()
        ],
        key=lambda path: len(path.parts),
        reverse=True
    )

    for directory in directories:

        try:

            directory.rmdir()

        except OSError:

            # Directory is not empty or cannot be removed.
            pass

    # --------------------------------------------------------
    # Remove root folder
    # --------------------------------------------------------

    try:

        folder_path.rmdir()

    except OSError:

        pass

    # --------------------------------------------------------
    # Count results
    # --------------------------------------------------------

    successful = sum(
        1
        for result in results
        if result["success"]
    )

    failed = len(results) - successful

    # --------------------------------------------------------
    # Final status
    # --------------------------------------------------------

    if failed == 0:

        status = "SECURELY ERASED"

    else:

        status = "PARTIAL FAILURE"

    return {
        "success": failed == 0,
        "status": status,
        "folder": str(folder_path),
        "total_files": len(files),
        "successful_files": successful,
        "failed_files": failed,
        "verified": failed == 0,
        "details": results
    }


# ============================================================
# TEST - SECURE FILE + FOLDER ERASURE
# ============================================================

def test_secure_erase():

    project_root = (
        Path(__file__)
        .resolve()
        .parents[2]
    )

    test_folder = (
        project_root
        / "test-data"
        / "secure_erase_test"
    )

    # --------------------------------------------------------
    # Create test folder structure
    # --------------------------------------------------------

    nested_folder = (
        test_folder
        / "documents"
    )

    nested_folder.mkdir(
        parents=True,
        exist_ok=True
    )

    file1 = (
        test_folder
        / "secret1.txt"
    )

    file2 = (
        nested_folder
        / "secret2.txt"
    )

    # --------------------------------------------------------
    # Create test files
    # --------------------------------------------------------

    with open(
        file1,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "CONFIDENTIAL FORENSIC DATA 001"
        )

    with open(
        file2,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "CONFIDENTIAL FORENSIC DATA 002"
        )

    # --------------------------------------------------------
    # Display test information
    # --------------------------------------------------------

    print(
        "\n=== Secure Folder Erasure Test ==="
    )

    print(
        f"Test folder: {test_folder}"
    )

    print(
        "\nFiles created:"
    )

    print(
        f"  {file1.name}"
    )

    print(
        f"  {file2}"
    )

    # --------------------------------------------------------
    # Securely erase folder
    # --------------------------------------------------------

    result = secure_erase_folder(
        test_folder,
        passes=3
    )

    # --------------------------------------------------------
    # Display erasure report
    # --------------------------------------------------------

    print(
        "\n=== Erasure Report ==="
    )

    print(
        f"Status: {result['status']}"
    )

    print(
        f"Total files: "
        f"{result['total_files']}"
    )

    print(
        f"Successfully erased: "
        f"{result['successful_files']}"
    )

    print(
        f"Failed: "
        f"{result['failed_files']}"
    )

    print(
        f"Deletion verified: "
        f"{result['verified']}"
    )

    # --------------------------------------------------------
    # Final status
    # --------------------------------------------------------

    if result["success"]:

        print(
            "\nStatus: "
            "SECURE FOLDER ERASURE VERIFIED"
        )

    else:

        print(
            "\nStatus: "
            "FOLDER ERASURE REQUIRES REVIEW"
        )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

 test_secure_erase()

