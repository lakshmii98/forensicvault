from pathlib import Path
from io import BytesIO
from PIL import Image
from reportlab.pdfgen import canvas


# Find the project root
ROOT = Path(__file__).resolve().parents[2]

# Folder where synthetic evidence will be stored
TEST_DATA = ROOT / "test-data"
TEST_DATA.mkdir(exist_ok=True)


def create_jpeg():
    """Create a small real JPEG file in memory."""
    image = Image.new("RGB", (300, 200), (30, 120, 200))

    buffer = BytesIO()
    image.save(buffer, format="JPEG", quality=90)

    return buffer.getvalue()


def create_png():
    """Create a small real PNG file in memory."""
    image = Image.new("RGB", (200, 150), (220, 80, 80))

    buffer = BytesIO()
    image.save(buffer, format="PNG")

    return buffer.getvalue()


def create_pdf():
    """Create a real PDF file in memory."""
    buffer = BytesIO()

    pdf = canvas.Canvas(buffer)
    pdf.setTitle("ForensicVault Test Evidence")

    pdf.drawString(100, 750, "ForensicVault")
    pdf.drawString(100, 730, "Synthetic Forensic Evidence Test")
    pdf.drawString(100, 710, "This PDF was recovered from synthetic evidence.")

    pdf.save()

    return buffer.getvalue()


def main():
    print("Creating synthetic forensic evidence...")

    jpeg_data = create_jpeg()
    png_data = create_png()
    pdf_data = create_pdf()

    evidence = bytearray()

    # Add meaningless padding
    evidence.extend(b"A" * 5000)

    # Real JPEG
    jpeg_offset = len(evidence)
    evidence.extend(jpeg_data)

    evidence.extend(b"X" * 7000)

    # Real PNG
    png_offset = len(evidence)
    evidence.extend(png_data)

    evidence.extend(b"Y" * 6000)

    # Real PDF
    pdf_offset = len(evidence)
    evidence.extend(pdf_data)

    evidence.extend(b"Z" * 5000)

    # -------------------------------------------------
    # Simulate deletion/header damage
    # -------------------------------------------------

    # Scrub JPEG header
    evidence[jpeg_offset:jpeg_offset + 2] = b"\x00\x00"

    # Scrub PNG signature
    evidence[png_offset:png_offset + 8] = b"\x00" * 8

    # PDF remains intact
    output_file = TEST_DATA / "synthetic_evidence.bin"

    with open(output_file, "wb") as file:
        file.write(evidence)

    print()
    print("Synthetic evidence created successfully!")
    print(f"File: {output_file}")
    print(f"Size: {len(evidence)} bytes")
    print()
    print("Embedded files:")
    print(f"JPEG -> offset {jpeg_offset} -> HEADER SCRUBBED")
    print(f"PNG  -> offset {png_offset} -> HEADER SCRUBBED")
    print(f"PDF  -> offset {pdf_offset} -> header intact")
    print()
    print("This is a SAFE synthetic test file.")
    print("No real drive is modified.")


if __name__ == "__main__":
    main()