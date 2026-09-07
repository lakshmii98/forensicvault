from pathlib import Path


# ============================================================
# ForensicVault - File Carving Engine
# ============================================================


# ============================================================
# FILE SIGNATURES (MAGIC BYTES)
# ============================================================

FILE_SIGNATURES = {
    "JPEG": b"\xFF\xD8\xFF",
    "PNG": b"\x89PNG\r\n\x1a\n",
    "PDF": b"%PDF",
}


# ============================================================
# 1. FIND FILE SIGNATURES
# ============================================================

def find_signatures(data: bytes):
    """
    Search raw evidence bytes for known file signatures.
    """

    findings = []

    for file_type, signature in FILE_SIGNATURES.items():

        start = 0

        while True:

            position = data.find(
                signature,
                start
            )

            if position == -1:
                break

            findings.append({
                "type": file_type,
                "offset": position,
                "signature": signature.hex()
            })

            start = position + 1

    return findings


# ============================================================
# 2. EXTRACT PDF
# ============================================================

def extract_pdf(
    data: bytes,
    offset: int,
    output_path: Path
):
    """
    Extract a PDF from the evidence using its
    PDF header and EOF marker.
    """

    end_marker = b"%%EOF"

    end_position = data.find(
        end_marker,
        offset
    )

    if end_position == -1:
        return False

    # Include EOF marker
    end_position += len(end_marker)

    pdf_data = data[
        offset:end_position
    ]

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        output_path,
        "wb"
    ) as file:
        file.write(pdf_data)

    return True


# ============================================================
# 2B. EXTRACT JPEG
# ============================================================

def extract_jpeg(
    data: bytes,
    offset: int,
    output_path: Path
):
    """
    Extract a JPEG from raw evidence using
    the JPEG header and end-of-image marker.
    """

    start_marker = b"\xFF\xD8\xFF"
    end_marker = b"\xFF\xD9"

    # Verify JPEG header
    if not data.startswith(
        start_marker,
        offset
    ):
        return False

    # Search for JPEG end marker
    end_position = data.find(
        end_marker,
        offset + len(start_marker)
    )

    if end_position == -1:
        return False

    # Include JPEG end marker
    end_position += len(end_marker)

    jpeg_data = data[
        offset:end_position
    ]

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        output_path,
        "wb"
    ) as file:
        file.write(jpeg_data)

    return True


# ============================================================
# 2C. EXTRACT PNG
# ============================================================

def extract_png(
    data: bytes,
    offset: int,
    output_path: Path
):
    """
    Extract a PNG from raw evidence using
    the PNG signature and IEND chunk.
    """

    start_marker = b"\x89PNG\r\n\x1a\n"
    end_marker = b"IEND"

    # Verify PNG signature
    if not data.startswith(
        start_marker,
        offset
    ):
        return False

    # Search for IEND chunk
    end_position = data.find(
        end_marker,
        offset + len(start_marker)
    )

    if end_position == -1:
        return False

    # Include IEND + CRC
    end_position += 8

    png_data = data[
        offset:end_position
    ]

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        output_path,
        "wb"
    ) as file:
        file.write(png_data)

    return True


# ============================================================
# 3. VALIDATE RECOVERED PDF
# ============================================================

def validate_pdf(pdf_data: bytes):
    """
    Perform basic structural validation
    on a recovered PDF.
    """

    checks = {
        "pdf_header":
            pdf_data.startswith(
                b"%PDF"
            ),

        "eof_marker":
            b"%%EOF" in pdf_data,

        "has_object":
            b"obj" in pdf_data,

        "has_trailer":
            b"trailer" in pdf_data,
    }

    passed = sum(checks.values())
    total = len(checks)

    confidence = (
        passed / total
    ) * 100

    return {
        "checks": checks,
        "passed": passed,
        "total": total,
        "confidence": round(
            confidence,
            2
        ),
    }


# ============================================================
# 3B. VALIDATE RECOVERED JPEG
# ============================================================

def validate_jpeg(jpeg_data: bytes):
    """
    Perform basic structural validation
    on a recovered JPEG.
    """

    checks = {
        "jpeg_header":
            jpeg_data.startswith(
                b"\xFF\xD8\xFF"
            ),

        "jpeg_end_marker":
            jpeg_data.endswith(
                b"\xFF\xD9"
            ),

        "minimum_size":
            len(jpeg_data) > 100,
    }

    passed = sum(checks.values())
    total = len(checks)

    confidence = (
        passed / total
    ) * 100

    return {
        "checks": checks,
        "passed": passed,
        "total": total,
        "confidence": round(
            confidence,
            2
        ),
    }


# ============================================================
# 3C. VALIDATE RECOVERED PNG
# ============================================================

def validate_png(png_data: bytes):
    """
    Perform basic structural validation
    on a recovered PNG.
    """

    png_header = b"\x89PNG\r\n\x1a\n"

    checks = {
        "png_header":
            png_data.startswith(
                png_header
            ),

        "ihdr_chunk":
            b"IHDR" in png_data,

        "iend_chunk":
            b"IEND" in png_data,

        "minimum_size":
            len(png_data) > 50,
    }

    passed = sum(checks.values())
    total = len(checks)

    confidence = (
        passed / total
    ) * 100

    return {
        "checks": checks,
        "passed": passed,
        "total": total,
        "confidence": round(
            confidence,
            2
        ),
    }


# ============================================================
# 3D. ANALYZE FRAGMENT
# ============================================================

def analyze_fragment(fragment_path):
    """
    Analyze an individual binary fragment.

    For JPEG:
        - Detect JPEG start marker.
        - Detect JPEG end marker.
        - Record fragment size.
    """

    fragment_path = Path(fragment_path)

    with open(
        fragment_path,
        "rb"
    ) as file:

        data = file.read()

    return {
        "path": fragment_path,
        "data": data,

        "is_start":
            data.startswith(
                b"\xFF\xD8\xFF"
            ),

        "is_end":
            data.endswith(
                b"\xFF\xD9"
            ),

        "size":
            len(data)
    }


# ============================================================
# 3E. FRAGMENT CONTINUITY SCORE
# ============================================================

def continuity_score(
    first,
    second,
    overlap=16
):
    """
    Estimate how well two fragments connect.

    The function compares the ending bytes of the first
    fragment with the beginning bytes of the second.

    Higher score = stronger byte continuity.
    """

    max_overlap = min(
        overlap,
        len(first),
        len(second)
    )

    best_score = 0

    for size in range(
        1,
        max_overlap + 1
    ):

        if first[-size:] == second[:size]:
            best_score = size

    return best_score


# ============================================================
# 3F. AUTOMATIC FRAGMENT ORDERING
# ============================================================

def automatically_order_fragments(
    fragments,
    file_type="JPEG"
):
    """
    Automatically determine the most plausible order
    of fragmented files.

    JPEG strategy:

        1. Identify the fragment containing JPEG header.
        2. Identify the fragment containing JPEG end marker.
        3. Use byte continuity to select middle fragments.
        4. Verify that the end fragment is last.

    This is a heuristic approach and is intended to identify
    the most plausible ordering rather than guarantee perfect
    recovery for arbitrary fragmented evidence.
    """

    if not fragments:

        return {
            "success": False,
            "message": "No fragments supplied."
        }

    # --------------------------------------------------------
    # Analyze every fragment
    # --------------------------------------------------------

    analyzed = []

    for fragment in fragments:

        fragment_path = Path(fragment)

        if not fragment_path.exists():

            return {
                "success": False,
                "message":
                    f"Fragment not found: {fragment_path}"
            }

        analyzed.append(
            analyze_fragment(fragment_path)
        )

    # --------------------------------------------------------
    # JPEG ordering
    # --------------------------------------------------------

    if file_type == "JPEG":

        # Find START candidates
        start_candidates = [
            item
            for item in analyzed
            if item["is_start"]
        ]

        # Find END candidates
        end_candidates = [
            item
            for item in analyzed
            if item["is_end"]
        ]

        # ----------------------------------------------------
        # Validate START
        # ----------------------------------------------------

        if len(start_candidates) != 1:

            return {
                "success": False,
                "message":
                    "Expected exactly one JPEG start "
                    f"fragment, found {len(start_candidates)}."
            }

        # ----------------------------------------------------
        # Validate END
        # ----------------------------------------------------

        if len(end_candidates) != 1:

            return {
                "success": False,
                "message":
                    "Expected exactly one JPEG end "
                    f"fragment, found {len(end_candidates)}."
            }

        start = start_candidates[0]
        end = end_candidates[0]

        # ----------------------------------------------------
        # Start building ordered list
        # ----------------------------------------------------

        ordered = [start]

        remaining = [
            item
            for item in analyzed
            if item["path"] != start["path"]
            and item["path"] != end["path"]
        ]

        # ----------------------------------------------------
        # Select middle fragments
        # ----------------------------------------------------

        while remaining:

            current = ordered[-1]

            candidates = []

            for candidate in remaining:

                score = continuity_score(
                    current["data"],
                    candidate["data"]
                )

                candidates.append(
                    (score, candidate)
                )

            # Highest continuity score first
            candidates.sort(
                key=lambda x: x[0],
                reverse=True
            )

            best_score, best_candidate = candidates[0]

            ordered.append(
                best_candidate
            )

            remaining.remove(
                best_candidate
            )

        # ----------------------------------------------------
        # Add END fragment
        # ----------------------------------------------------

        ordered.append(end)

    else:

        # ----------------------------------------------------
        # Generic fallback
        # ----------------------------------------------------

        ordered = analyzed

    # --------------------------------------------------------
    # Final order
    # --------------------------------------------------------

    order = [
        str(item["path"])
        for item in ordered
    ]

    # --------------------------------------------------------
    # Verify JPEG end is last
    # --------------------------------------------------------

    if file_type == "JPEG":

        if ordered[-1]["path"] != end["path"]:

            return {
                "success": False,
                "message":
                    "JPEG end fragment was not placed last.",
                "order": order
            }

    # --------------------------------------------------------
    # Return result
    # --------------------------------------------------------

    return {
        "success": True,
        "order": order,
        "fragments": ordered
    }

# ============================================================
# 3G. MISSING / CORRUPTED FRAGMENT DETECTION
# ============================================================

def detect_fragment_integrity(
    fragments,
    file_type="JPEG"
):
    """
    Detect missing or suspicious fragments before reconstruction.

    Checks:
        1. Fragment exists
        2. Fragment is not empty
        3. JPEG start fragment exists
        4. JPEG end fragment exists
        5. Fragment ordering can be determined
    """

    report = {
        "success": True,
        "total_fragments": len(fragments),
        "valid_fragments": 0,
        "issues": [],
        "status": "HEALTHY"
    }

    if not fragments:
        report["success"] = False
        report["status"] = "NO FRAGMENTS"
        report["issues"].append(
            "No fragments supplied."
        )
        return report

    analyzed = []

    # --------------------------------------------------------
    # Check each fragment
    # --------------------------------------------------------

    for fragment in fragments:

        fragment_path = Path(fragment)

        if not fragment_path.exists():

            report["issues"].append(
                f"Missing fragment: {fragment_path.name}"
            )

            continue

        try:

            analysis = analyze_fragment(
                fragment_path
            )

            analyzed.append(
                analysis
            )

            # Empty fragment
            if analysis["size"] == 0:

                report["issues"].append(
                    f"Empty fragment: "
                    f"{fragment_path.name}"
                )

                continue

            report["valid_fragments"] += 1

        except Exception as error:

            report["issues"].append(
                f"Cannot read {fragment_path.name}: "
                f"{error}"
            )

    # --------------------------------------------------------
    # JPEG-specific checks
    # --------------------------------------------------------

    if file_type == "JPEG":

        start_fragments = [
            item
            for item in analyzed
            if item["is_start"]
        ]

        end_fragments = [
            item
            for item in analyzed
            if item["is_end"]
        ]

        # Missing START
        if len(start_fragments) == 0:

            report["issues"].append(
                "JPEG start fragment is missing."
            )

        elif len(start_fragments) > 1:

            report["issues"].append(
                "Multiple JPEG start fragments detected."
            )

        # Missing END
        if len(end_fragments) == 0:

            report["issues"].append(
                "JPEG end fragment is missing."
            )

        elif len(end_fragments) > 1:

            report["issues"].append(
                "Multiple JPEG end fragments detected."
            )

    # --------------------------------------------------------
    # Final status
    # --------------------------------------------------------

    if report["issues"]:

        report["status"] = "SUSPICIOUS"

    else:

        report["status"] = "HEALTHY"

    return report
# ============================================================
# 4. FRAGMENTED FILE RECONSTRUCTION
# ============================================================

def reconstruct_fragments(
    fragments,
    output_path: Path,
    file_type: str = "JPEG"
):
    """
    Reconstruct a file from ordered binary fragments.

    The fragments must already be in the expected order.

    file_type determines which structural validator
    is used after reconstruction.
    """

    if not fragments:

        return {
            "success": False,
            "message": "No fragments supplied."
        }

    try:

        fragment_data = []

        # ----------------------------------------------------
        # Read every fragment
        # ----------------------------------------------------

        for fragment in fragments:

            fragment_path = Path(
                fragment
            )

            if not fragment_path.exists():

                return {
                    "success": False,
                    "message":
                        f"Fragment not found: "
                        f"{fragment_path}"
                }

            with open(
                fragment_path,
                "rb"
            ) as file:

                fragment_data.append(
                    file.read()
                )

        # ----------------------------------------------------
        # Join fragments
        # ----------------------------------------------------

        reconstructed = b"".join(
            fragment_data
        )

        # ----------------------------------------------------
        # Create output directory
        # ----------------------------------------------------

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        # ----------------------------------------------------
        # Save reconstructed file
        # ----------------------------------------------------

        with open(
            output_path,
            "wb"
        ) as file:

            file.write(
                reconstructed
            )

        # ----------------------------------------------------
        # Select validator
        # ----------------------------------------------------

        if file_type == "JPEG":

            validation = validate_jpeg(
                reconstructed
            )

        elif file_type == "PNG":

            validation = validate_png(
                reconstructed
            )

        elif file_type == "PDF":

            validation = validate_pdf(
                reconstructed
            )

        else:

            return {
                "success": False,
                "message":
                    f"Unsupported file type: "
                    f"{file_type}"
            }

        # ----------------------------------------------------
        # Return reconstruction result
        # ----------------------------------------------------

        return {
            "success": True,

            "output":
                str(output_path),

            "size":
                len(reconstructed),

            "confidence":
                validation["confidence"],

            "validation":
                validation
        }

    except Exception as error:

        return {
            "success": False,
            "message": str(error)
        }


# ============================================================
# 4B. AUTOMATIC FRAGMENT RECONSTRUCTION
# ============================================================

def auto_reconstruct_fragments(
    fragments,
    output_path,
    file_type="JPEG"
):
    """
    Automatically order fragments, reconstruct the file,
    and validate the reconstructed result.
    """

    # --------------------------------------------------------
    # Automatically determine order
    # --------------------------------------------------------

    ordering = automatically_order_fragments(
        fragments,
        file_type
    )

    if not ordering["success"]:

        return ordering

    # --------------------------------------------------------
    # Extract ordered fragment paths
    # --------------------------------------------------------

    ordered_fragments = [
        item["path"]
        for item in ordering["fragments"]
    ]

    # --------------------------------------------------------
    # Reconstruct using detected order
    # --------------------------------------------------------

    result = reconstruct_fragments(
        ordered_fragments,
        output_path,
        file_type
    )

    if not result["success"]:

        return result

    # --------------------------------------------------------
    # Add automatic ordering information
    # --------------------------------------------------------

    result["automatic_order"] = [
        str(path)
        for path in ordered_fragments
    ]

    result["ordering_success"] = True

    return result


# ============================================================
# 5. CARVE EVIDENCE
# ============================================================

def carve_evidence(
    evidence_path: str
):
    """
    Read a binary evidence file and search
    for recoverable file signatures.
    """

    path = Path(
        evidence_path
    )

    if not path.exists():

        raise FileNotFoundError(
            f"Evidence file not found: "
            f"{evidence_path}"
        )

    with open(
        path,
        "rb"
    ) as file:

        data = file.read()

    findings = find_signatures(
        data
    )

    return data, findings


# ============================================================
# 6. FRAGMENT RECONSTRUCTION TEST
# ============================================================

def test_fragment_reconstruction():
    """
    Test automatic reconstruction using the synthetic
    fragmented JPEG.

    The fragments are deliberately supplied in the WRONG order:

        fragment_03
        fragment_01
        fragment_02

    The system should automatically determine:

        fragment_01
        fragment_02
        fragment_03
    """

    project_root = (
        Path(__file__)
        .resolve()
        .parents[2]
    )

    fragments_folder = (
        project_root
        / "test-data"
        / "jpeg_fragments"
    )

    output_file = (
        project_root
        / "recovered"
        / "reconstructed_test.jpg"
    )

    # --------------------------------------------------------
    # DELIBERATELY WRONG ORDER
    # --------------------------------------------------------

    fragments = [

        fragments_folder
        / "fragment_03.bin",

        fragments_folder
        / "fragment_01.bin",

        fragments_folder
        / "fragment_02.bin",
    ]

    print(
        "\n=== Fragmented JPEG Reconstruction Test ==="
    )
    # --------------------------------------------------------
    # FRAGMENT INTEGRITY CHECK
    # --------------------------------------------------------

    integrity = detect_fragment_integrity(
        fragments,
        file_type="JPEG"
    )

    print(
        "\n=== Fragment Integrity Check ==="
    )

    print(
        f"Fragments supplied: "
        f"{integrity['total_fragments']}"
    )

    print(
        f"Valid fragments: "
        f"{integrity['valid_fragments']}"
    )

    print(
        f"Integrity status: "
        f"{integrity['status']}"
    )

    if integrity["issues"]:

        for issue in integrity["issues"]:

            print(
                f"WARNING: {issue}"
            )

    else:

        print(
            "No missing or corrupted fragments detected."
        )
    print(
        "\nSupplied order:"
    )

    for fragment in fragments:

        print(
            f"  {fragment.name}"
        )

    # --------------------------------------------------------
    # AUTOMATIC RECONSTRUCTION
    # --------------------------------------------------------

    result = auto_reconstruct_fragments(
        fragments,
        output_file,
        file_type="JPEG"
    )

    # --------------------------------------------------------
    # DISPLAY AUTOMATIC ORDER
    # --------------------------------------------------------

    print(
        "\n=== Automatic Fragment Ordering ==="
    )

    if result.get("automatic_order"):

        for index, fragment in enumerate(
            result["automatic_order"],
            start=1
        ):

            print(
                f"{index}. "
                f"{Path(fragment).name}"
            )

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    if result["success"]:

        print(
            "\n=== Reconstruction Result ==="
        )

        print(
            f"Reconstructed file -> "
            f"{result['output']}"
        )

        print(
            f"Reconstructed size: "
            f"{result['size']} bytes"
        )

        validation = result[
            "validation"
        ]

        print(
            f"Confidence: "
            f"{validation['confidence']}%"
        )

        print(
            f"Checks passed: "
            f"{validation['passed']}/"
            f"{validation['total']}"
        )

        print(
            "\n=== JPEG Validation ==="
        )

        for check, passed in (
            validation["checks"].items()
        ):

            status = (
                "PASS"
                if passed
                else "FAIL"
            )

            print(
                f"{check}: {status}"
            )

        # ----------------------------------------------------
        # Final status
        # ----------------------------------------------------

        if validation["confidence"] == 100:

            print(
                "\nStatus: "
                "VALID RECONSTRUCTED JPEG"
            )

        elif validation["confidence"] >= 66.67:

            print(
                "\nStatus: "
                "RECONSTRUCTED BUT "
                "REQUIRES REVIEW"
            )

        else:

            print(
                "\nStatus: "
                "RECONSTRUCTION FAILED "
                "VALIDATION"
            )

    else:

        print(
            "\nStatus: "
            "RECONSTRUCTION FAILED"
        )

        print(
            f"Reason: "
            f"{result['message']}"
        )


# ============================================================
# 7. MAIN PROGRAM
# ============================================================

if __name__ == "__main__":

    # ========================================================
    # FIND PROJECT ROOT
    # ========================================================

    project_root = (
        Path(__file__)
        .resolve()
        .parents[2]
    )

    # ========================================================
    # EVIDENCE FILE
    # ========================================================

    evidence_file = (
        project_root
        / "test-data"
        / "png_test_evidence.bin"
    )

    # ========================================================
    # RECOVERED FILES FOLDER
    # ========================================================

    recovered_folder = (
        project_root
        / "recovered"
    )

    recovered_folder.mkdir(
        exist_ok=True
    )

    # ========================================================
    # READ EVIDENCE AND FIND SIGNATURES
    # ========================================================

    data, findings = carve_evidence(
        str(evidence_file)
    )

    # ========================================================
    # CARVING ENGINE OUTPUT
    # ========================================================

    print(
        "\n=== ForensicVault Carving Engine ==="
    )

    print(
        f"Evidence size: "
        f"{len(data)} bytes"
    )

    print(
        f"Signatures found: "
        f"{len(findings)}"
    )

    # ========================================================
    # PROCESS EACH FINDING
    # ========================================================

    for finding in findings:

        print(
            f"{finding['type']} "
            f"found at offset "
            f"{finding['offset']}"
        )

        # ====================================================
        # PDF RECOVERY
        # ====================================================

        if finding["type"] == "PDF":

            output_file = (
                recovered_folder
                / "recovered_001.pdf"
            )

            success = extract_pdf(
                data,
                finding["offset"],
                output_file
            )

            if success:

                print(
                    f"Recovered PDF -> "
                    f"{output_file}"
                )

                with open(
                    output_file,
                    "rb"
                ) as file:

                    recovered_pdf = (
                        file.read()
                    )

                validation = validate_pdf(
                    recovered_pdf
                )

                print(
                    "\n=== PDF Validation ==="
                )

                print(
                    f"Confidence: "
                    f"{validation['confidence']}%"
                )

                print(
                    f"Checks passed: "
                    f"{validation['passed']}/"
                    f"{validation['total']}"
                )

                for check, result in (
                    validation["checks"].items()
                ):

                    status = (
                        "PASS"
                        if result
                        else "FAIL"
                    )

                    print(
                        f"{check}: {status}"
                    )

                if validation[
                    "confidence"
                ] == 100:

                    print(
                        "\nStatus: "
                        "VALID RECOVERED PDF"
                    )

                elif validation[
                    "confidence"
                ] >= 75:

                    print(
                        "\nStatus: "
                        "MOSTLY VALID PDF"
                    )

                elif validation[
                    "confidence"
                ] >= 50:

                    print(
                        "\nStatus: "
                        "PARTIALLY VALID PDF"
                    )

                else:

                    print(
                        "\nStatus: "
                        "INVALID OR "
                        "CORRUPTED PDF"
                    )

            else:

                print(
                    "PDF recovery failed."
                )

        # ====================================================
        # JPEG RECOVERY
        # ====================================================

        elif finding["type"] == "JPEG":

            output_file = (
                recovered_folder
                / "recovered_jpeg_001.jpg"
            )

            success = extract_jpeg(
                data,
                finding["offset"],
                output_file
            )

            if success:

                print(
                    f"Recovered JPEG -> "
                    f"{output_file}"
                )

                with open(
                    output_file,
                    "rb"
                ) as file:

                    recovered_jpeg = (
                        file.read()
                    )

                validation = validate_jpeg(
                    recovered_jpeg
                )

                print(
                    "\n=== JPEG Validation ==="
                )

                print(
                    f"Confidence: "
                    f"{validation['confidence']}%"
                )

                print(
                    f"Checks passed: "
                    f"{validation['passed']}/"
                    f"{validation['total']}"
                )

                for check, result in (
                    validation["checks"].items()
                ):

                    status = (
                        "PASS"
                        if result
                        else "FAIL"
                    )

                    print(
                        f"{check}: {status}"
                    )

                if validation[
                    "confidence"
                ] == 100:

                    print(
                        "\nStatus: "
                        "VALID RECOVERED JPEG"
                    )

                elif validation[
                    "confidence"
                ] >= 66.67:

                    print(
                        "\nStatus: "
                        "MOSTLY VALID JPEG"
                    )

                else:

                    print(
                        "\nStatus: "
                        "INVALID OR "
                        "CORRUPTED JPEG"
                    )

            else:

                print(
                    "JPEG recovery failed."
                )

        # ====================================================
        # PNG RECOVERY
        # ====================================================

        elif finding["type"] == "PNG":

            output_file = (
                recovered_folder
                / "recovered_png_001.png"
            )

            success = extract_png(
                data,
                finding["offset"],
                output_file
            )

            if success:

                print(
                    f"Recovered PNG -> "
                    f"{output_file}"
                )

                with open(
                    output_file,
                    "rb"
                ) as file:

                    recovered_png = (
                        file.read()
                    )

                validation = validate_png(
                    recovered_png
                )

                print(
                    "\n=== PNG Validation ==="
                )

                print(
                    f"Confidence: "
                    f"{validation['confidence']}%"
                )

                print(
                    f"Checks passed: "
                    f"{validation['passed']}/"
                    f"{validation['total']}"
                )

                for check, result in (
                    validation["checks"].items()
                ):

                    status = (
                        "PASS"
                        if result
                        else "FAIL"
                    )

                    print(
                        f"{check}: {status}"
                    )

                if validation[
                    "confidence"
                ] == 100:

                    print(
                        "\nStatus: "
                        "VALID RECOVERED PNG"
                    )

                elif validation[
                    "confidence"
                ] >= 75:

                    print(
                        "\nStatus: "
                        "MOSTLY VALID PNG"
                    )

                elif validation[
                    "confidence"
                ] >= 50:

                    print(
                        "\nStatus: "
                        "PARTIALLY VALID PNG"
                    )

                else:

                    print(
                        "\nStatus: "
                        "INVALID OR "
                        "CORRUPTED PNG"
                    )

            else:

                print(
                    "PNG recovery failed."
                )

    # ========================================================
    # AUTOMATIC FRAGMENT RECONSTRUCTION TEST
    # ========================================================

    test_fragment_reconstruction()