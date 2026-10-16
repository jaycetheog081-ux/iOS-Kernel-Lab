#!/usr/bin/env python3

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path


DEVICE = "iPhone14,5"
IOS_VERSION = "27.0"
BUILD = "24A437"

ROOT = Path(os.environ.get("RUNNER_TEMP", ".")) / "ios-kernel-lab"
FIRMWARE_DIR = ROOT / "firmware"
REPORT_DIR = Path("reports")

API_URL = f"https://api.ipsw.me/v4/device/{DEVICE}?type=ipsw"

KERNEL_TERMS = (
    "kernelcache",
    "kernelcollection",
    "kernel",
    "kernels",
)

SECURITY_TERMS = (
    "trustcache",
    "trust_cache",
    "endpointsecurity",
    "devicetree",
    "sep-firmware",
    "buildmanifest.plist",
    "restore.plist",
)


def fetch_json(url):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "iOS-Kernel-Lab/1.0"},
    )

    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def select_firmware(data):
    matches = [
        item
        for item in data.get("firmwares", [])
        if item.get("version") == IOS_VERSION
        and item.get("buildid") == BUILD
    ]

    if not matches:
        available = [
            f"{item.get('version')} ({item.get('buildid')})"
            for item in data.get("firmwares", [])
        ]

        raise RuntimeError(
            f"Firmware {IOS_VERSION} ({BUILD}) was not found for "
            f"{DEVICE}. Available entries: {available[:20]}"
        )

    return matches[0]


def download_file(url, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "iOS-Kernel-Lab/1.0"},
    )

    with urllib.request.urlopen(request, timeout=120) as response:
        with destination.open("wb") as output:
            while True:
                chunk = response.read(1024 * 1024)

                if not chunk:
                    break

                output.write(chunk)


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as source:
        while True:
            chunk = source.read(8 * 1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def inspect_archive(path):
    report = {
        "archive_entries": [],
        "kernel_candidates": [],
        "security_candidates": [],
        "build_manifest": None,
        "warnings": [],
    }

    with zipfile.ZipFile(path, "r") as archive:
        for item in archive.infolist():
            name = item.filename
            lowered = name.lower()

            entry = {
                "name": name,
                "size_bytes": item.file_size,
                "compressed_size_bytes": item.compress_size,
            }

            report["archive_entries"].append(entry)

            if any(term in lowered for term in KERNEL_TERMS):
                report["kernel_candidates"].append(entry)

            if any(term in lowered for term in SECURITY_TERMS):
                report["security_candidates"].append(entry)

        try:
            import plistlib

            with archive.open("BuildManifest.plist") as stream:
                manifest = plistlib.load(stream)

            report["build_manifest"] = {
                "ProductVersion": manifest.get("ProductVersion"),
                "ProductBuildVersion": manifest.get(
                    "ProductBuildVersion"
                ),
                "SupportedProductTypes": manifest.get(
                    "SupportedProductTypes", []
                ),
                "BuildIdentities": [],
            }

            for identity in manifest.get("BuildIdentities", []):
                info = identity.get("Info", {})

                report["build_manifest"]["BuildIdentities"].append({
                    "DeviceClass": info.get("DeviceClass"),
                    "RestoreBehavior": info.get("RestoreBehavior"),
                    "Variant": info.get("Variant"),
                    "ApBoardID": info.get("ApBoardID"),
                    "ApChipID": info.get("ApChipID"),
                })

        except (KeyError, ValueError, zipfile.BadZipFile) as exc:
            report["warnings"].append(
                f"Could not parse BuildManifest.plist: {exc}"
            )

    return report


def main():
    print(f"Querying firmware metadata for {DEVICE}...")

    data = fetch_json(API_URL)
    firmware = select_firmware(data)

    url = firmware.get("url")
    if not url:
        raise RuntimeError("The firmware listing has no download URL.")

    filename = (
        firmware.get("filename")
        or f"{DEVICE}_{IOS_VERSION}_{BUILD}_Restore.ipsw"
    )

    expected_sha256 = firmware.get("sha256sum")

    FIRMWARE_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    ipsw_path = FIRMWARE_DIR / filename

    print(f"Selected: {filename}")
    print(f"Device: {DEVICE}")
    print(f"Version: {IOS_VERSION}")
    print(f"Build: {BUILD}")

    print("Downloading firmware directly to the runner...")
    download_file(url, ipsw_path)

    print("Calculating SHA-256...")
    actual_sha256 = sha256_file(ipsw_path)

    checksum_verified = None

    if expected_sha256:
        checksum_verified = (
            actual_sha256.lower() == expected_sha256.lower()
        )

        if not checksum_verified:
            raise RuntimeError(
                "SHA-256 mismatch. The downloaded firmware does not "
                "match the checksum in the firmware listing."
            )

        print("SHA-256 verification passed.")
    else:
        print(
            "WARNING: No SHA-256 checksum was supplied by the API. "
            "The calculated hash is recorded but not independently "
            "verified."
        )

    print("Inspecting archive contents...")
    inventory = inspect_archive(ipsw_path)

    manifest = inventory.get("build_manifest") or {}

    manifest_version = manifest.get("ProductVersion")
    manifest_build = manifest.get("ProductBuildVersion")

    if manifest_version and manifest_version != IOS_VERSION:
        raise RuntimeError(
            f"Manifest version mismatch: {manifest_version}"
        )

    if manifest_build and manifest_build != BUILD:
        raise RuntimeError(
            f"Manifest build mismatch: {manifest_build}"
        )

    report = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "target": {
            "device": "iPhone 13",
            "identifier": DEVICE,
            "ios_version": IOS_VERSION,
            "build": BUILD,
        },
        "firmware_listing": {
            "source": API_URL,
            "url": url,
            "filename": filename,
            "listed_size_bytes": firmware.get("filesize"),
            "listed_sha256": expected_sha256,
            "actual_sha256": actual_sha256,
            "sha256_verified": checksum_verified,
            "signed": firmware.get("signed"),
            "release_date": firmware.get("releasedate"),
        },
        "actual_file_size_bytes": ipsw_path.stat().st_size,
        **inventory,
        "analysis_limitations": [
            "Archive inventory is not vulnerability discovery.",
            "Filename matching can miss files with unexpected names.",
            "Nested images and kernel binaries have not been deeply analyzed.",
            "A suspicious component is not proof of an exploitable flaw.",
        ],
    }

    json_path = REPORT_DIR / "ios-firmware-inventory.json"
    text_path = REPORT_DIR / "ios-firmware-inventory.txt"

    json_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    lines = [
        "iOS Firmware Inventory",
        "======================",
        "",
        f"Device: {DEVICE}",
        f"iOS version: {IOS_VERSION}",
        f"Build: {BUILD}",
        f"File: {filename}",
        f"Size: {ipsw_path.stat().st_size:,} bytes",
        f"SHA-256: {actual_sha256}",
        f"Checksum verified: {checksum_verified}",
        "",
        "BUILD MANIFEST",
        "--------------",
        json.dumps(report["build_manifest"], indent=2),
        "",
        "KERNEL CANDIDATES",
        "-----------------",
    ]

    for entry in report["kernel_candidates"]:
        lines.append(
            f"{entry['name']} ({entry['size_bytes']:,} bytes)"
        )

    lines.extend(["", "SECURITY-RELATED CANDIDATES", "---------------------------"])

    for entry in report["security_candidates"]:
        lines.append(
            f"{entry['name']} ({entry['size_bytes']:,} bytes)"
        )

    lines.extend(["", "WARNINGS", "--------"])

    lines.extend(
        report["warnings"] or ["No inventory warnings."]
    )

    text_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"JSON report: {json_path}")
    print(f"Text report: {text_path}")
    print(f"Archive entries: {len(report['archive_entries'])}")
    print(f"Kernel candidates: {len(report['kernel_candidates'])}")
    print(f"Security candidates: {len(report['security_candidates'])}")


if __name__ == "__main__":
    try:
        main()
    except (
        OSError,
        ValueError,
        RuntimeError,
        urllib.error.URLError,
        zipfile.BadZipFile,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
