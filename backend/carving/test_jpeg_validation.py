from pathlib import Path
from backend.carving.carver import validate_jpeg

data = Path("recovered/test_jpeg.jpg").read_bytes()

result = validate_jpeg(data)

print("=== JPEG Validation ===")
print(f"Confidence: {result['confidence']}%")
print(f"Checks passed: {result['passed']}/{result['total']}")

for check, passed in result["checks"].items():
    status = "PASS" if passed else "FAIL"
    print(f"{check}: {status}")