# 🔐 ForensicVault

### Digital Evidence Recovery, Integrity Verification & Secure Erasure Platform

> **ForensicVault** is a digital forensics platform designed to assist investigators in recovering fragmented digital evidence, validating recovered artifacts, detecting possible image manipulation, preserving evidence integrity, and performing controlled secure data erasure.

---

## 🎯 Problem Statement

Digital evidence can become difficult to recover and validate when files are fragmented, partially corrupted, manipulated, or intentionally deleted.

Traditional recovery approaches may recover file fragments without providing sufficient information about:

* Whether the recovered file is structurally valid
* How fragmented pieces should be ordered
* How confident the reconstruction is
* Whether recovered evidence has been modified
* Whether deleted data has been securely erased
* Whether evidence integrity can be demonstrated throughout the investigation

**ForensicVault addresses these challenges through an integrated digital forensics workflow.**

---

## 💡 Proposed Solution

ForensicVault combines **file carving, fragment reconstruction, evidence validation, tamper analysis, cryptographic integrity verification, and secure erasure** into a unified forensic workspace.

### Core Workflow

```text
Digital Evidence
       │
       ▼
┌─────────────────────┐
│ Evidence Acquisition│
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ File Signature       │
│ Detection & Carving  │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Fragment Analysis    │
│ & Automatic Ordering  │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Reconstruction &     │
│ Structural Validation │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Confidence Scoring    │
└──────────┬──────────┘
           │
     ┌─────┴─────┐
     ▼           ▼
Tamper         SHA-256
Analysis       Integrity
     │           │
     └─────┬─────┘
           ▼
┌─────────────────────┐
│ Chain of Custody &   │
│ Forensic Reporting   │
└─────────────────────┘
```

---

## 🚀 Key Capabilities

### 1. Advanced File Carving

* Detects file signatures from evidence data.
* Supports recovery and validation of common evidence formats.
* Performs structural validation of recovered artifacts.

### 2. Fragmented File Reconstruction

* Analyzes fragmented evidence pieces.
* Automatically proposes fragment ordering.
* Reconstructs fragmented files.
* Validates reconstructed output.
* Generates a recovery confidence score.

### 3. Evidence Integrity

* Generates **SHA-256 hashes** for evidence.
* Maintains a tamper-evident hash chain.
* Detects changes to previously recorded evidence.
* Supports evidence integrity verification.

### 4. Image Tamper Analysis

The platform provides multiple indicators for possible image manipulation, including:

* Metadata analysis
* Error Level Analysis (ELA)
* Pixel-level anomaly analysis
* Copy-move detection

> Tamper analysis provides **possible manipulation indicators**, rather than claiming definitive proof of manipulation.

### 5. Secure File & Folder Erasure

* Controlled multi-pass overwrite.
* File deletion verification.
* Recursive folder erasure.
* Flushes data and synchronizes writes before deletion.

### 6. SSD / TRIM Awareness

The system identifies storage characteristics and warns investigators about limitations of traditional overwrite-based sanitization on SSDs.

### 7. Controlled Drive Erasure Simulation

A protected simulation demonstrates the drive-erasure workflow without allowing destructive operations against arbitrary physical drives.

### 8. Chain of Custody

Evidence-related records can be linked through cryptographic hashes to provide tamper-evident integrity tracking.

---

## 🏗️ System Architecture

```text
                    ┌──────────────────────┐
                    │   React Frontend     │
                    │   Forensic Dashboard │
                    └──────────┬───────────┘
                               │ REST API
                               ▼
                    ┌──────────────────────┐
                    │    FastAPI Backend   │
                    └──────────┬───────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        ▼                      ▼                      ▼
┌───────────────┐      ┌───────────────┐      ┌───────────────┐
│ File Carving  │      │ Integrity &   │      │ Tamper        │
│ & Recovery    │      │ Chain of      │      │ Detection     │
│ Engine        │      │ Custody       │      │ Engine        │
└───────────────┘      └───────────────┘      └───────────────┘
        │                      │                      │
        ▼                      ▼                      ▼
┌───────────────┐      ┌───────────────┐      ┌───────────────┐
│ Fragment      │      │ SHA-256       │      │ Image         │
│ Reconstruction│      │ Hash Chain    │      │ Analysis      │
└───────────────┘      └───────────────┘      └───────────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Secure Erasure &     │
                    │ Storage Awareness    │
                    └──────────────────────┘
```

---

## 🛠️ Technology Stack

| Layer            | Technologies                            |
| ---------------- | --------------------------------------- |
| Frontend         | React, Vite, JavaScript, CSS            |
| Backend          | Python, FastAPI, Uvicorn                |
| Image Processing | Pillow, OpenCV, NumPy                   |
| Cryptography     | SHA-256                                 |
| Storage Analysis | Windows PowerShell / Physical Disk APIs |
| Development      | Git, GitHub, VS Code                    |

---

## 📁 Project Structure

```text
ForensicVault/
│
├── backend/
│   ├── carving/
│   │   ├── carver.py
│   │   └── reconstruction & validation modules
│   │
│   ├── erasure/
│   │   ├── secure_eraser.py
│   │   └── drive_eraser.py
│   │
│   ├── integrity/
│   │   ├── hash_chain.py
│   │   ├── hashing.py
│   │   └── chain_of_custody.py
│   │
│   ├── reporting/
│   ├── storage/
│   ├── tamper/
│   ├── tamper_detection/
│   └── main.py
│
├── frontend/
│   ├── src/
│   ├── public/
│   └── package.json
│
├── test-data/
├── recovered/
├── requirements.txt
└── test_reconstruction.py
```

---

## ⚙️ Installation & Setup

### Prerequisites

* Python 3.10+
* Node.js 18+
* npm
* Git

### Backend

```bash
git clone https://github.com/lakshmii98/forensicvault.git
cd forensicvault

python -m venv .venv
```

Windows:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Start the API:

```powershell
python -m uvicorn backend.main:app --reload
```

Backend:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

### Frontend

Open another terminal:

```powershell
cd frontend
npm install
npm run dev
```

---

## 🧪 Validation & Testing

ForensicVault includes controlled test evidence for validating core functionality.

### Tested Capabilities

* File signature detection
* PNG recovery and validation
* JPEG recovery and validation
* Fragment integrity analysis
* Automatic fragment ordering
* Fragment reconstruction
* Reconstruction confidence scoring
* Secure file/folder deletion
* SHA-256 integrity verification
* SSD detection and awareness
* Controlled drive-erasure simulation

Example reconstruction result:

```text
Fragmented JPEG Reconstruction

Fragments detected:       3
Automatic ordering:       SUCCESS
Reconstruction:           SUCCESS
JPEG header:              PASS
JPEG end marker:          PASS
Minimum size:             PASS
Confidence:               100%
Status:                   VALID RECONSTRUCTED JPEG
```

---

## 🔒 Security & Safety Considerations

ForensicVault is designed around **evidence preservation and controlled testing**.

### Drive Erasure

Physical drive destruction is intentionally restricted.

The current implementation provides a **controlled simulation** rather than arbitrary physical-drive wiping.

### SSD Sanitization

Traditional overwrite techniques cannot guarantee physical sanitization on SSDs because of mechanisms such as:

* Wear leveling
* TRIM
* Flash translation layers
* Filesystem and controller behavior

Production deployment should use appropriate **device-specific sanitization mechanisms**.

### Fragment Reconstruction

Fragment ordering is based on available evidence and continuity analysis. Reconstruction cannot be guaranteed for every arbitrarily fragmented or corrupted file.

---

## 📊 Expected Impact

ForensicVault aims to improve digital forensic workflows by providing:

* **Faster evidence recovery**
* **Automated fragment analysis**
* **Evidence validation**
* **Tamper-evident integrity tracking**
* **Improved forensic transparency**
* **Controlled data sanitization**
* **Centralized investigation workflow**

The modular architecture also allows additional file formats, forensic algorithms, storage technologies, and reporting capabilities to be integrated in future versions.

---

## 🔮 Future Scope

* Support for additional file formats
* Advanced filesystem-aware carving
* ML-assisted fragment classification
* Improved copy-move and manipulation detection
* Integration with forensic disk-image formats
* Hardware-backed evidence integrity
* Production-grade device sanitization
* Advanced automated forensic report generation
* Multi-user investigation and case management

---

## ⚠️ Disclaimer

ForensicVault is an academic/prototype digital forensics project developed for controlled testing and demonstration.

The platform should not be treated as a replacement for certified forensic tools or professional forensic procedures. Results should be independently validated before being used in legal or investigative contexts.

---

## 👥 Development

The project follows a modular team-development approach using Git and GitHub.

Contributors should create feature branches and submit Pull Requests to `main` for review.

```text
main
 ├── backend development
 ├── frontend development
 └── feature branches
          │
          ▼
     Pull Request
          │
          ▼
       Review
          │
          ▼
        main
```

---

## 📌 Project Status

**Core forensic backend:** ✅ Implemented & tested

**Fragment reconstruction:** ✅ Implemented & validated

**Integrity verification:** ✅ Implemented

**Secure erasure:** ✅ Implemented for controlled testing

**SSD awareness:** ✅ Implemented

**Drive erasure:** ⚠️ Controlled simulation

**Frontend:** 🔄 Integration & refinement

---

### ForensicVault

**Recover. Validate. Preserve. Secure.**
