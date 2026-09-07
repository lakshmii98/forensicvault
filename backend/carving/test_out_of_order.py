from pathlib import Path


# ============================================================
# ForensicVault - Out-of-Order Fragment Test
# ============================================================

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


# ------------------------------------------------------------
# Load fragments deliberately OUT OF ORDER
# ------------------------------------------------------------

fragment_01 = (
    fragments_folder / "fragment_01.bin"
)

fragment_02 = (
    fragments_folder / "fragment_02.bin"
)

fragment_03 = (
    fragments_folder / "fragment_03.bin"
)


# ------------------------------------------------------------
# Deliberately wrong order
# ------------------------------------------------------------

fragments = [
    fragment_03,
    fragment_01,
    fragment_02,
]


print(
    "=== Out-of-Order Fragment Test ==="
)

print()

for fragment in fragments:

    print(
        f"Loaded: {fragment.name}"
    )

print()

print(
    "Fragments were intentionally supplied "
    "in the wrong order."
)

print()

# ------------------------------------------------------------
# Show first bytes of each fragment
# ------------------------------------------------------------

for fragment in fragments:

    data = fragment.read_bytes()

    print(
        f"{fragment.name} -> "
        f"{len(data)} bytes"
    )

    print(
        f"First 10 bytes: "
        f"{data[:10].hex()}"
    )

    print()