# ForensicVault 

### Digital Evidence Recovery, Integrity & Secure Erasure Platform

ForensicVault is a digital forensics platform designed to assist in the recovery, validation, integrity verification, tamper analysis, and controlled secure erasure of digital evidence.

## 🚀 Key Features

- 🔍 File carving and evidence recovery
- 🧩 Automatic fragmented file ordering
- 🔧 Fragment reconstruction and validation
- 📊 Recovery confidence scoring
- 🖼️ Image tamper detection
- 🔐 SHA-256 evidence integrity and hash chain
- 📋 Chain of custody support
- 🗑️ Secure file and folder erasure
- 💾 SSD/TRIM awareness
- ⚠️ Controlled drive-erasure simulation
- 📄 Forensic report generation

## 🛠️ Technology Stack

**Backend:** Python, FastAPI, Uvicorn, Pillow, OpenCV, NumPy

**Frontend:** React, Vite, JavaScript, CSS

## 📁 Project Structure

```text
ForensicVault/
├── backend/
│   ├── carving/
│   ├── erasure/
│   ├── integrity/
│   ├── reporting/
│   ├── storage/
│   └── tamper_detection/
├── frontend/
├── test-data/
├── recovered/
├── requirements.txt
└── test_reconstruction.py
