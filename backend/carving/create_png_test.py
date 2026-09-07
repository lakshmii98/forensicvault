from pathlib import Path
from io import BytesIO
from PIL import Image


project_root = (
    Path(__file__).resolve().parents[2]
)

output_file = (
    project_root
    / "test-data"
    / "png_test_evidence.bin"
)


# Create synthetic PNG
image = Image.new(
    "RGB",
    (300, 200),
    (220, 80, 80)
)

buffer = BytesIO()

image.save(
    buffer,
    format="PNG"
)

png_data = buffer.getvalue()


# Embed PNG inside binary evidence
evidence = (
    b"A" * 5000
    + png_data
    + b"B" * 5000
)


output_file.write_bytes(
    evidence
)


print(
    "PNG test evidence created successfully!"
)

print(
    f"File: {output_file}"
)

print(
    f"Size: {len(evidence)} bytes"
)

print(
    "PNG offset: 5000 bytes"
)