from pathlib import Path

from backend.carving.carver import (
    carve_evidence,
    reconstruct_fragments
)


evidence = Path("test-data/synthetic_evidence.bin")

data, findings = carve_evidence(str(evidence))

pdf = [f for f in findings if f["type"] == "PDF"][0]

raw = data[pdf["offset"]:]

third = len(raw) // 3

fragments = [
    raw[:third],
    raw[third:third * 2],
    raw[third * 2:]
]

output = Path("recovered/fragment_reconstructed.pdf")

result = reconstruct_fragments(
    fragments,
    output
)

print("\n=== Fragment Reconstruction ===")
print(f"Fragments: {len(fragments)}")
print(f"Output: {result['output']}")
print(f"Size: {result['size']} bytes")
print(f"Confidence: {result['confidence']}%")
print(f"Validation: {result['validation']}")