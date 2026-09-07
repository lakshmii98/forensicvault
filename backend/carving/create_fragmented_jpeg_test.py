from pathlib import Path
from io import BytesIO
from PIL import Image


# ============================================================
# Create a synthetic JPEG
# ============================================================

project_root = (
    Path(__file__).resolve().parents[2]
)

fragments_folder = (
    project_root
    / "test-data"
    / "jpeg_fragments"
)

fragments_folder.mkdir(
    parents=True,
    exist_ok=True
)


image = Image.new(
    "RGB",
    (400, 300),
    (30, 120, 200)
)

buffer = BytesIO()

image.save(
    buffer,
    format="JPEG",
    quality=90
)

jpeg_data = buffer.getvalue()

print(
    f"Original JPEG size: {len(jpeg_data)} bytes"
)


# ============================================================
# Split JPEG into 3 fragments
# ============================================================

split_1 = len(jpeg_data) // 3
split_2 = (len(jpeg_data) * 2) // 3

fragment_1 = jpeg_data[:split_1]

fragment_2 = jpeg_data[split_1:split_2]

fragment_3 = jpeg_data[split_2:]


# ============================================================
# Save fragments
# ============================================================

(fragment_1_path := fragments_folder / "fragment_01.bin").write_bytes(
    fragment_1
)

(fragment_2_path := fragments_folder / "fragment_02.bin").write_bytes(
    fragment_2
)

(fragment_3_path := fragments_folder / "fragment_03.bin").write_bytes(
    fragment_3
)


print()
print("Fragmented JPEG created successfully!")

print(
    f"Fragment 1: {len(fragment_1)} bytes"
)

print(
    f"Fragment 2: {len(fragment_2)} bytes"
)

print(
    f"Fragment 3: {len(fragment_3)} bytes"
)

print()
print(
    f"Fragments folder: {fragments_folder}"
)