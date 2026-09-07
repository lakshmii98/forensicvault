from pathlib import Path
from io import BytesIO
from PIL import Image

project_root = Path(__file__).resolve().parents[2]
output_file = project_root / "test-data" / "jpeg_test_evidence.bin"

# Create a real JPEG
image = Image.new("RGB", (300, 200), (30, 120, 200))

buffer = BytesIO()
image.save(buffer, format="JPEG", quality=90)
jpeg_data = buffer.getvalue()

# Put unrelated bytes before and after the JPEG
evidence = (
    b"A" * 5000
    + jpeg_data
    + b"B" * 5000
)

output_file.write_bytes(evidence)

print("JPEG test evidence created successfully!")
print(f"File: {output_file}")
print(f"Size: {len(evidence)} bytes")
print(f"JPEG offset: {5000} bytes")