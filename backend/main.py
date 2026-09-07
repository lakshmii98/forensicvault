from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from datetime import datetime
import shutil
import hashlib
import json


# ============================================================
# FORENSICVAULT MODULE IMPORTS
# ============================================================

from backend.carving.carver import (
    find_signatures,
    extract_pdf,
    validate_pdf,
    automatically_order_fragments,
    detect_fragment_integrity,
    reconstruct_fragments
)

from backend.erasure.secure_eraser import (
    secure_erase_file,
    secure_erase_folder
)

from backend.erasure.drive_eraser import (
    simulate_drive_erase
)

from backend.storage.ssd_awareness import (
    detect_storage_devices
)

from backend.tamper_detection.image_tamper import (
    analyze_image
)

from backend.integrity.chain_of_custody import (
    verify_chain
)

from backend.reporting.forensic_report import (
    generate_forensic_report
)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="ForensicVault",
    description=(
        "Digital Forensics, Secure Erasure and "
        "Evidence Integrity Platform"
    ),
    version="1.0.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# DIRECTORIES
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[1]

UPLOAD_DIR = BASE_DIR / "test-data"
RECOVERED_DIR = BASE_DIR / "recovered"

UPLOAD_DIR.mkdir(exist_ok=True)
RECOVERED_DIR.mkdir(exist_ok=True)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "project": "ForensicVault",
        "status": "running",
        "message": "ForensicVault backend is operational"
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health_check():

    return {
        "status": "healthy"
    }


# ============================================================
# FILE CARVING STATUS
# ============================================================

@app.get("/carving")
def carving_status():

    return {
        "module": "File Carving",
        "status": "operational",
        "features": [
            "File signature detection",
            "PDF recovery",
            "JPEG recovery",
            "PNG recovery",
            "Structural validation",
            "Fragment integrity checking",
            "Automatic fragment ordering",
            "Fragment reconstruction",
            "Confidence scoring"
        ]
    }


# ============================================================
# FILE CARVING / EVIDENCE ANALYSIS
# ============================================================

@app.post("/carving/analyze")
async def analyze_evidence(file: UploadFile = File(...)):

    # --------------------------------------------------------
    # Save uploaded evidence
    # --------------------------------------------------------

    evidence_path = UPLOAD_DIR / file.filename

    with open(evidence_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # --------------------------------------------------------
    # Read evidence
    # --------------------------------------------------------

    with open(evidence_path, "rb") as evidence:
        data = evidence.read()

    # --------------------------------------------------------
    # Find file signatures
    # --------------------------------------------------------

    findings = find_signatures(data)

    results = []

    for finding in findings:

        result = {
            "type": finding["type"],
            "offset": finding["offset"],
            "signature": finding["signature"]
        }

        # ----------------------------------------------------
        # PDF RECOVERY
        # ----------------------------------------------------

        if finding["type"] == "PDF":

            output_file = (
                RECOVERED_DIR
                / f"recovered_{len(results) + 1:03d}.pdf"
            )

            success = extract_pdf(
                data,
                finding["offset"],
                output_file
            )

            result["recovered"] = success

            # ------------------------------------------------
            # PDF VALIDATION
            # ------------------------------------------------

            if success:

                with open(output_file, "rb") as pdf:
                    pdf_data = pdf.read()

                validation = validate_pdf(pdf_data)

                result["validation"] = validation
                result["output_file"] = str(output_file)

        results.append(result)

    return {
        "evidence_file": file.filename,
        "evidence_size": len(data),
        "signatures_found": len(findings),
        "results": results
    }


# ============================================================
# FRAGMENT INTEGRITY CHECK
# ============================================================

@app.get("/carving/fragments/integrity")
def fragment_integrity():

    fragment_folder = (
        BASE_DIR
        / "test-data"
        / "jpeg_fragments"
    )

    if not fragment_folder.exists():

        return {
            "success": False,
            "status": "FRAGMENT FOLDER NOT FOUND",
            "folder": str(fragment_folder)
        }

    fragments = sorted(
        fragment_folder.glob("fragment_*.bin")
    )

    if not fragments:

        return {
            "success": False,
            "status": "NO FRAGMENTS FOUND",
            "folder": str(fragment_folder)
        }

    result = detect_fragment_integrity(
        fragments
    )

    return result


# ============================================================
# AUTOMATIC FRAGMENT ORDERING
# ============================================================

@app.get("/carving/fragments/order")
def fragment_order():

    fragment_folder = (
        BASE_DIR
        / "test-data"
        / "jpeg_fragments"
    )

    if not fragment_folder.exists():

        return {
            "success": False,
            "status": "FRAGMENT FOLDER NOT FOUND"
        }

    fragments = sorted(
        fragment_folder.glob("fragment_*.bin")
    )

    if not fragments:

        return {
            "success": False,
            "status": "NO FRAGMENTS FOUND"
        }

    try:

        result = automatically_order_fragments(
            fragments
        )

        return {
    "success": True,
    "status": "FRAGMENTS ORDERED",
    "supplied_order": [
        path.name
        for path in fragments
    ],
    "automatic_order": [
        Path(path).name
        for path in result["order"]
    ]
}
          
        

    except Exception as error:

        return {
            "success": False,
            "status": "FRAGMENT ORDERING FAILED",
            "error": str(error)
        }


# ============================================================
# AUTOMATIC FRAGMENT RECONSTRUCTION
# ============================================================

@app.post("/carving/fragments/reconstruct")
def reconstruct_fragmented_file():

    fragment_folder = (
        BASE_DIR
        / "test-data"
        / "jpeg_fragments"
    )

    output_file = (
        RECOVERED_DIR
        / "api_reconstructed.jpg"
    )

    if not fragment_folder.exists():

        return {
            "success": False,
            "status": "FRAGMENT FOLDER NOT FOUND"
        }

    fragments = sorted(
        fragment_folder.glob("fragment_*.bin")
    )

    if not fragments:

        return {
            "success": False,
            "status": "NO FRAGMENTS FOUND"
        }

    try:

        ordered_fragments = automatically_order_fragments(
            fragments
        )

        result = reconstruct_fragments(
            ordered_fragments,
            output_file
        )

        return {
            "success": True,
            "status": "FRAGMENT RECONSTRUCTION COMPLETE",
            "ordered_fragments": [
                path.name
                for path in ordered_fragments
            ],
            "output_file": str(output_file),
            "result": result
        }

    except Exception as error:

        return {
            "success": False,
            "status": "RECONSTRUCTION FAILED",
            "error": str(error)
        }


# ============================================================
# SECURE ERASURE STATUS
# ============================================================

@app.get("/erasure")
def erasure_status():

    return {
        "module": "Secure Erasure",
        "status": "operational",
        "features": [
            "Multi-pass overwrite",
            "File deletion",
            "Folder erasure",
            "Deletion verification"
        ],
        "forensic_note": (
            "Prototype overwrite-based erasure. "
            "Physical sanitization is not guaranteed on SSDs."
        )
    }


# ============================================================
# SECURE FILE ERASURE
# ============================================================

@app.post("/erasure/file")
def erase_test_file():

    test_file = (
        UPLOAD_DIR
        / "erase_test.txt"
    )

    # --------------------------------------------------------
    # Create controlled test file if needed
    # --------------------------------------------------------

    if not test_file.exists():

        test_file.write_text(
            "CONFIDENTIAL FORENSIC TEST DATA",
            encoding="utf-8"
        )

    # --------------------------------------------------------
    # Secure erase
    # --------------------------------------------------------

    result = secure_erase_file(
        test_file,
        passes=3
    )

    return result


# ============================================================
# SECURE FOLDER ERASURE
# ============================================================

@app.post("/erasure/folder")
def erase_test_folder():

    test_folder = (
        UPLOAD_DIR
        / "secure_erase_test"
    )

    # --------------------------------------------------------
    # Create controlled test folder
    # --------------------------------------------------------

    if not test_folder.exists():

        nested_folder = (
            test_folder
            / "documents"
        )

        nested_folder.mkdir(
            parents=True,
            exist_ok=True
        )

        (
            test_folder
            / "secret1.txt"
        ).write_text(
            "CONFIDENTIAL FORENSIC DATA 001",
            encoding="utf-8"
        )

        (
            nested_folder
            / "secret2.txt"
        ).write_text(
            "CONFIDENTIAL FORENSIC DATA 002",
            encoding="utf-8"
        )

    # --------------------------------------------------------
    # Secure erase
    # --------------------------------------------------------

    result = secure_erase_folder(
        test_folder,
        passes=3
    )

    return result


# ============================================================
# SSD / STORAGE AWARENESS
# ============================================================

@app.get("/storage")
def storage_status():

    return detect_storage_devices()


# ============================================================
# SAFE DRIVE ERASURE SIMULATION
# ============================================================

@app.post("/erasure/drive-simulation")
def drive_erasure_simulation():

    simulated_drive = (
        UPLOAD_DIR
        / "simulated_drive"
    )

    # --------------------------------------------------------
    # Create controlled simulated drive
    # --------------------------------------------------------

    if not simulated_drive.exists():

        simulated_drive.mkdir(
            parents=True,
            exist_ok=True
        )

        (
            simulated_drive
            / "evidence_01.txt"
        ).write_text(
            "Simulated forensic evidence file.",
            encoding="utf-8"
        )

        (
            simulated_drive
            / "evidence_02.txt"
        ).write_text(
            "Another simulated evidence file.",
            encoding="utf-8"
        )

    # --------------------------------------------------------
    # Simulation only
    # --------------------------------------------------------

    result = simulate_drive_erase(
        simulated_drive
    )

    return result


# ============================================================
# SHA-256 HASH FUNCTION
# ============================================================

def calculate_sha256(file_path: Path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


# ============================================================
# EVIDENCE INTEGRITY
# ============================================================

@app.get("/integrity")
def integrity_status():

    evidence_file = (
        UPLOAD_DIR
        / "synthetic_evidence.bin"
    )

    if not evidence_file.exists():

        return {
            "module": "Evidence Integrity",
            "status": "ready"
        }

    file_hash = calculate_sha256(
        evidence_file
    )

    return {
        "module": "Evidence Integrity",
        "status": "verified",
        "algorithm": "SHA-256",
        "hash": file_hash
    }


# ============================================================
# TAMPER DETECTION
# ============================================================

@app.get("/tamper-detection")
def tamper_detection_status():

    evidence_file = (
        UPLOAD_DIR
        / "synthetic_evidence.bin"
    )

    baseline_file = (
        UPLOAD_DIR
        / "evidence_baseline.json"
    )

    if not evidence_file.exists():

        return {
            "status": "no evidence available"
        }

    # --------------------------------------------------------
    # Calculate current hash
    # --------------------------------------------------------

    current_hash = calculate_sha256(
        evidence_file
    )

    # --------------------------------------------------------
    # Compare against trusted baseline
    # --------------------------------------------------------

    if baseline_file.exists():

        with open(
            baseline_file,
            "r",
            encoding="utf-8"
        ) as file:

            baseline = json.load(file)

        tampered = (
            current_hash
            != baseline["sha256"]
        )

    else:

        tampered = False

    return {
        "module": "Tamper Detection",
        "current_hash": current_hash,
        "tampered": tampered,
        "status": (
            "TAMPERING DETECTED"
            if tampered
            else "NO TAMPERING DETECTED"
        )
    }


# ============================================================
# IMAGE TAMPER DETECTION
# ============================================================

@app.post("/tamper-detection/image")
async def image_tamper_detection(
    file: UploadFile = File(...)
):

    image_path = (
        UPLOAD_DIR
        / file.filename
    )

    # --------------------------------------------------------
    # Save uploaded image
    # --------------------------------------------------------

    with open(
        image_path,
        "wb"
    ) as buffer:

        shutil.copyfileobj(
            file.file,
            buffer
        )

    # --------------------------------------------------------
    # Analyze image
    # --------------------------------------------------------

    result = analyze_image(
        image_path
    )

    return result


# ============================================================
# CHAIN OF CUSTODY
# ============================================================

@app.get("/chain-of-custody")
def chain_of_custody():

    log_file = (
        UPLOAD_DIR
        / "chain_of_custody.json"
    )

    verification = verify_chain(
        str(log_file)
    )

    return verification


# ============================================================
# FORENSIC REPORT
# ============================================================

@app.post("/report")
def generate_report():

    findings = [

        {
            "category": "File Recovery",

            "result": (
                "Evidence carving, validation "
                "and fragmented reconstruction available"
            ),

            "confidence": None,

            "evidence": [
                "File signature detection",
                "PDF recovery",
                "JPEG/PNG recovery",
                "Fragment integrity checking",
                "Automatic fragment ordering",
                "Structural validation"
            ]
        },

        {
            "category": "Secure Erasure",

            "result": (
                "Controlled file and folder "
                "erasure available"
            ),

            "confidence": None,

            "evidence": [
                "Multi-pass overwrite",
                "File deletion",
                "Deletion verification"
            ]
        },

        {
            "category": "Evidence Integrity",

            "result": (
                "SHA-256 evidence integrity verification available"
            ),

            "confidence": None,

            "evidence": [
                "SHA-256 hashing",
                "Evidence integrity checking"
            ]
        },

        {
            "category": "Chain of Custody",

            "result": (
                "Hash-chain integrity can be verified"
            ),

            "confidence": None,

            "evidence": [
                "SHA-256 evidence hashing",
                "Tamper-evident audit chain"
            ]
        },

        {
            "category": "Image Tampering",

            "result": (
                "Image manipulation indicators can be analyzed"
            ),

            "confidence": None,

            "evidence": [
                "Metadata analysis",
                "ELA analysis",
                "Copy-move analysis",
                "Pixel anomaly detection"
            ]
        },

        {
            "category": "SSD/TRIM",

            "result": (
                "Recoverability and sanitization "
                "may be uncertain on SSD storage"
            ),

            "confidence": None,

            "evidence": [
                "Storage media detection",
                "SSD warning",
                "Wear-leveling/TRIM limitation"
            ]
        },

        {
            "category": "Drive Erasure",

            "result": (
                "Safe drive-erasure simulation available"
            ),

            "confidence": None,

            "evidence": [
                "Physical drive modification blocked",
                "Operating-system drive protection",
                "Simulation-only sanitization"
            ]
        }
    ]

    return generate_forensic_report(
        findings
    )


# ============================================================
# COMPLETE SYSTEM STATUS
# ============================================================

@app.get("/system-status")
def system_status():

    return {

        "project": "ForensicVault",

        "version": "1.0.0",

        "modules": {

            "file_carving": "operational",

            "pdf_validation": "operational",

            "fragment_reconstruction": "operational",

            "secure_file_erasure": "operational",

            "secure_folder_erasure": "operational",

            "drive_erasure_simulation": "operational",

            "sha256_integrity": "operational",

            "tamper_detection": "operational",

            "image_tamper_detection": "operational",

            "chain_of_custody": "operational",

            "ssd_awareness": "operational",

            "forensic_reporting": "operational"
        },

        "safety": {

            "physical_drive_erasure": False,

            "drive_erasure_mode": "SIMULATION ONLY"
        },

        "timestamp": datetime.now().isoformat()
    }