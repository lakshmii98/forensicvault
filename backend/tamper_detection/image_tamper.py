from pathlib import Path
from PIL import Image, ImageChops, ImageEnhance, ExifTags
import cv2
import numpy as np


def metadata_check(image_path):
    image = Image.open(image_path)
    exif = image.getexif()

    metadata = {}
    editing_software = None

    for tag_id, value in exif.items():
        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
        metadata[tag_name] = str(value)

        if tag_name.lower() == "software":
            editing_software = str(value)

    editing_tools = [
        "photoshop",
        "adobe",
        "gimp",
        "lightroom",
        "snapseed",
        "picsart",
        "canva"
    ]

    detected = False

    if editing_software:
        software_lower = editing_software.lower()

        for tool in editing_tools:
            if tool in software_lower:
                detected = True
                break

    return {
        "software": editing_software,
        "editing_software_detected": detected,
        "metadata": metadata
    }


def ela_analysis(image_path, output_path):
    original = Image.open(image_path).convert("RGB")

    temp_path = Path(output_path).parent / "ela_temp.jpg"

    original.save(
        temp_path,
        "JPEG",
        quality=90
    )

    compressed = Image.open(temp_path).convert("RGB")

    difference = ImageChops.difference(
        original,
        compressed
    )

    extrema = difference.getextrema()

    max_difference = max(
        channel[1]
        for channel in extrema
    )

    if max_difference == 0:
        max_difference = 1

    scale = 255.0 / max_difference

    ela_image = ImageEnhance.Brightness(
        difference
    ).enhance(scale)

    ela_image.save(output_path)

    temp_path.unlink(missing_ok=True)

    ela_score = float(
        np.mean(np.asarray(difference))
    )

    return {
        "ela_score": round(ela_score, 2),
        "heatmap": str(output_path)
    }


def copy_move_detection(image_path, output_path):
    image = cv2.imread(str(image_path))

    if image is None:
        raise ValueError("Could not read image.")

    gray = cv2.cvtColor(
        image,
        cv2.COLOR_BGR2GRAY
    )

    orb = cv2.ORB_create(
        nfeatures=2000
    )

    keypoints, descriptors = orb.detectAndCompute(
        gray,
        None
    )

    if descriptors is None or len(keypoints) < 10:
        cv2.imwrite(str(output_path), image)

        return {
            "matches": 0,
            "suspicious": False,
            "overlay": str(output_path)
        }

    matcher = cv2.BFMatcher(
        cv2.NORM_HAMMING,
        crossCheck=True
    )

    matches = matcher.match(
        descriptors,
        descriptors
    )

    good_matches = []

    for match in matches:
        if match.queryIdx != match.trainIdx:
            good_matches.append(match)

    suspicious = len(good_matches) >= 15

    overlay = image.copy()

    if suspicious:
        for match in good_matches[:50]:

            point1 = tuple(
                map(
                    int,
                    keypoints[match.queryIdx].pt
                )
            )

            point2 = tuple(
                map(
                    int,
                    keypoints[match.trainIdx].pt
                )
            )

            cv2.circle(
                overlay,
                point1,
                8,
                (0, 0, 255),
                2
            )

            cv2.circle(
                overlay,
                point2,
                8,
                (0, 0, 255),
                2
            )

            cv2.line(
                overlay,
                point1,
                point2,
                (0, 0, 255),
                1
            )

    cv2.imwrite(
        str(output_path),
        overlay
    )

    return {
        "matches": len(good_matches),
        "suspicious": suspicious,
        "overlay": str(output_path)
    }

def pixel_anomaly_detection(image_path, output_path):
    image = cv2.imread(str(image_path))

    if image is None:
        raise ValueError("Could not read image.")

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    blurred = cv2.GaussianBlur(gray, (21, 21), 0)

    difference = cv2.absdiff(gray, blurred)

    _, mask = cv2.threshold(
        difference,
        25,
        255,
        cv2.THRESH_BINARY
    )

    mask = cv2.dilate(mask, None, iterations=2)

    suspicious_pixels = int(np.sum(mask > 0))
    total_pixels = mask.size

    anomaly_ratio = suspicious_pixels / total_pixels

    suspicious = anomaly_ratio > 0.01

    heatmap = cv2.applyColorMap(
        mask,
        cv2.COLORMAP_JET
    )

    cv2.imwrite(
        str(output_path),
        heatmap
    )

    return {
        "anomaly_ratio": round(anomaly_ratio, 4),
        "suspicious": suspicious,
        "heatmap": str(output_path)
    }
def analyze_image(image_path):

    image_path = Path(image_path)

    if not image_path.exists():
        raise FileNotFoundError(
            f"Image not found: {image_path}"
        )

    output_dir = image_path.parent / "tamper_results"
    output_dir.mkdir(exist_ok=True)

    ela_output = output_dir / "ela_heatmap.jpg"
    copy_move_output = output_dir / "copy_move_overlay.jpg"
    anomaly_output = output_dir / "anomaly_heatmap.jpg"

    anomaly = pixel_anomaly_detection(
    image_path,
    anomaly_output
)

    metadata = metadata_check(image_path)

    ela = ela_analysis(
        image_path,
        ela_output
    )

    copy_move = copy_move_detection(
        image_path,
        copy_move_output
    )

    possible_tampering = (
    metadata["editing_software_detected"]
    or copy_move["suspicious"]
    or ela["ela_score"] > 5
    or anomaly["suspicious"]
)

    return {
        "file": image_path.name,
        "metadata": metadata,
        "ela": ela,
        "copy_move": copy_move,
        "anomaly": anomaly,
        "possible_tampering": possible_tampering
    }


if __name__ == "__main__":

    project_root = Path(__file__).resolve().parents[2]

    test_image = (
        project_root
        / "test-data"
        / "tamper_test.jpg"
    )

    print("\n=== ForensicVault Image Tamper Detection ===")

    if not test_image.exists():

        print("Test image not found.")
        print(f"Expected location: {test_image}")

    else:

        result = analyze_image(test_image)

        print("\n=== Metadata Analysis ===")

        print(
            f"Software: "
            f"{result['metadata']['software']}"
        )

        print(
            "Editing software detected:",
            result["metadata"]["editing_software_detected"]
        )

        print("\n=== ELA Analysis ===")

        print(
            f"ELA Score: "
            f"{result['ela']['ela_score']}"
        )

        print(
            f"Heatmap created at: "
            f"{result['ela']['heatmap']}"
        )

        print("\n=== Copy-Move Detection ===")

        print(
            f"Matches: "
            f"{result['copy_move']['matches']}"
        )

        print(
            "Possible duplicate region:",
            result["copy_move"]["suspicious"]
        )

        print("\n=== Final Assessment ===")

        if result["possible_tampering"]:
            print("⚠️ POSSIBLE IMAGE MANIPULATION DETECTED")
        else:
            print("✅ NO STRONG TAMPERING INDICATORS DETECTED")

        print("\nAnalysis completed successfully.")