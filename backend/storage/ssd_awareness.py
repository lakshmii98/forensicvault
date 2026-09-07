import subprocess
import json


def detect_storage_devices():
    """
    Detect physical storage devices on Windows
    and identify whether they are SSD or HDD.
    """

    try:
        command = [
            "powershell",
            "-Command",
            "Get-PhysicalDisk | Select-Object DeviceId, FriendlyName, MediaType, Size | ConvertTo-Json"
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            return {
                "success": False,
                "status": "STORAGE DETECTION FAILED",
                "devices": []
            }

        output = result.stdout.strip()

        if not output:
            return {
                "success": False,
                "status": "NO STORAGE DEVICES FOUND",
                "devices": []
            }

        data = json.loads(output)

        # PowerShell returns a dictionary for one disk
        # and a list for multiple disks.
        if isinstance(data, dict):
            data = [data]

        devices = []

        for disk in data:
            media_type = str(
                disk.get("MediaType", "Unknown")
            )

            if media_type.lower() == "ssd":
                warning = (
                    "SSD detected: traditional overwrite-based "
                    "erasure may not guarantee physical sanitization "
                    "because of wear leveling/TRIM."
                )
            elif media_type.lower() == "hdd":
                warning = (
                    "HDD detected: overwrite-based sanitization "
                    "is more applicable, subject to filesystem/device behavior."
                )
            else:
                warning = (
                    "Storage type could not be confidently identified."
                )

            devices.append({
                "device_id": disk.get("DeviceId"),
                "name": disk.get("FriendlyName"),
                "media_type": media_type,
                "size": disk.get("Size"),
                "warning": warning
            })

        return {
            "success": True,
            "status": "STORAGE DETECTION COMPLETE",
            "devices": devices
        }

    except Exception as error:
        return {
            "success": False,
            "status": "STORAGE DETECTION ERROR",
            "error": str(error),
            "devices": []
        }


def display_storage_report():
    """Display a forensic storage awareness report."""

    print("\n=== ForensicVault Storage Awareness ===")

    result = detect_storage_devices()

    print(f"Status: {result['status']}")

    if not result["success"]:
        if "error" in result:
            print(f"Error: {result['error']}")
        return

    print(f"Devices detected: {len(result['devices'])}")

    for index, device in enumerate(result["devices"], start=1):
        print(f"\n--- Storage Device {index} ---")
        print(f"Device ID: {device['device_id']}")
        print(f"Name: {device['name']}")
        print(f"Media Type: {device['media_type']}")

        if device["size"]:
            size_gb = int(device["size"]) / (1024 ** 3)
            print(f"Size: {size_gb:.2f} GB")

        print(f"⚠ Forensic Note: {device['warning']}")

    print("\n=== Forensic Recommendation ===")

    if any(
        device["media_type"].lower() == "ssd"
        for device in result["devices"]
    ):
        print(
            "SSD detected."
        )
        print(
            "Do NOT assume overwrite-based erasure guarantees "
            "physical sanitization."
        )
        print(
            "Use device-specific sanitization procedures "
            "for production forensic workflows."
        )
    else:
        print(
            "No SSD detected. Standard overwrite-based "
            "prototype erasure can be demonstrated with caution."
        )


if __name__ == "__main__":
    display_storage_report()