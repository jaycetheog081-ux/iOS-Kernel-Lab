#!/usr/bin/env python3

import hashlib
import json
import os
import plistlib
import shutil
import sys
import time
import urllib.error
import urllib.request
import zipfile

from pathlib import Path
from urllib.parse import urlparse


DEVICE = "iPhone14,5"
IOS_VERSION = "27.0"
BUILD_VERSION = "24A437"

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
KERNEL_DIR = REPORTS / "kernelcache"

WORK_DIR = (
    Path(os.environ.get("RUNNER_TEMP", "/tmp"))
    / "ios-kernel-lab"
    / "firmware"
)

API_URL = (
    f"https://api.ipsw.me/v4/device/{DEVICE}?type=ipsw"
)

USER_AGENT = "iOS-Kernel-Lab/1.0"


def log(message):
    print(f"[iOS-Kernel-Lab] {message}", flush=True)


def fetch_json(url):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT},
    )

    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        while True:
            block = file.read(8 * 1024 * 1024)

            if not block:
                break

            digest.update(block)

    return digest.hexdigest()


def download_file(url, destination, expected_size=None):
    destination.parent.mkdir(parents=True, exist_ok=True)

    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT},
    )

    log(f"Downloading firmware to {destination}")
    log("The IPSW is approximately 11 GB; this may take a while.")

    temporary = destination.with_suffix(".download")

    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            total = response.headers.get("Content-Length")

            if total:
                total = int(total)
            elif expected_size:
                total = int(expected_size)

            downloaded = 0
            last_report = 0

            with temporary.open("wb") as output:
                while True:
                    block = response.read(8 * 1024 * 1024)

                    if not block:
                        break

                    output.write(block)
                    downloaded += len(block)

                    now = time.monotonic()

                    if now - last_report >= 15:
                        if total:
                            percent = downloaded * 100 / total
                            log(
                                f"Download: {percent:.1f}% "
                                f"({downloaded:,}/{total:,} bytes)"
                            )
                        else:
                            log(f"Downloaded {downloaded:,} bytes")

                        last_report = now

        if expected_size and downloaded != int(expected_size):
            raise RuntimeError(
                f"Download size mismatch: expected {expected_size}, "
                f"received {downloaded}"
            )

        temporary.replace(destination)

    finally:
        if temporary.exists():
            temporary.unlink()

    log(f"Download complete: {downloaded:,} bytes")


def locate_firmware():
    log(f"Checking IPSW.me for {DEVICE}, iOS {IOS_VERSION}")

    data = fetch_json(API_URL)
    firmwares = data.get("firmwares", [])

    for firmware in firmwares:
        if (
            firmware.get("version") == IOS_VERSION
            and firmware.get("buildid") == BUILD_VERSION
        ):
            if firmware.get("signed") is False:
                log(
                    "Warning: IPSW.me reports this firmware "
                    "as unsigned."
                )

            return firmware

    raise RuntimeError(
        f"Could not find iOS {IOS_VERSION} build {BUILD_VERSION} "
        f"for {DEVICE} in the IPSW.me response. "
        "The listing may have changed or the target may be unavailable."
    )


def find_kernel_entry(archive):
    candidates = []

    for info in archive.infolist():
        name = info.filename.rsplit("/", 1)[-1]

        if name.startswith("kernelcache"):
            candidates.append(info)

    if not candidates:
        raise RuntimeError(
            "No kernelcache entry was found in the IPSW."
        )

    # Prefer the expected iPhone 13 kernelcache name.
    candidates.sort(
        key=lambda item: (
            item.filename.rsplit("/", 1)[-1]
            != "kernelcache.release.iphone14",
            item.file_size,
        )
    )

    return candidates[0]


def extract_member(archive, info, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)

    log(f"Extracting {info.filename}")
    log(f"Uncompressed size: {info.file_size:,} bytes")

    with archive.open(info, "r") as source:
        with destination.open("wb") as output:
            shutil.copyfileobj(
                source,
                output,
                length=8 * 1024 * 1024,
            )

    actual_size = destination.stat().st_size

    if actual_size != info.file_size:
        raise RuntimeError(
            f"Extracted size mismatch: expected {info.file_size}, "
            f"received {actual_size}"
        )

    log(f"Extracted kernelcache to {destination}")


def describe_file(path):
    with path.open("rb") as file:
        header = file.read(64)

    printable = "".join(
        chr(byte) if 32 <= byte < 127 else "."
        for byte in header
    )

    return {
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "first_64_bytes_hex": header.hex(),
        "first_64_bytes_ascii": printable,
    }


def read_build_manifest(archive):
    matches = [
        info
        for info in archive.infolist()
        if info.filename.rsplit("/", 1)[-1] == "BuildManifest.plist"
    ]

    if not matches:
        return None

    with archive.open(matches[0], "r") as source:
        manifest = plistlib.load(source)

    return {
        "ProductVersion": manifest.get("ProductVersion"),
        "ProductBuildVersion": manifest.get(
            "ProductBuildVersion"
        ),
        "SupportedProductTypes": manifest.get(
            "SupportedProductTypes", []
        ),
    }


def main():
    REPORTS.mkdir(parents=True, exist_ok=True)
    KERNEL_DIR.mkdir(parents=True, exist_ok=True)
    WORK_DIR.mkdir(parents=True, exist_ok=True)

    firmware = locate_firmware()

    download_url = firmware.get("url")

    if not download_url:
        raise RuntimeError(
            "IPSW.me did not provide a download URL."
        )

    filename = (
        f"{DEVICE}_{IOS_VERSION}_{BUILD_VERSION}_Restore.ipsw"
    )

    ipsw_path = WORK_DIR / filename

    expected_size = firmware.get("filesize")

    if not ipsw_path.exists():
        free_bytes = shutil.disk_usage(WORK_DIR).free

        if expected_size:
            required = int(expected_size) + 512 * 1024 * 1024

            if free_bytes < required:
                raise RuntimeError(
                    "Insufficient free disk space. "
                    f"Available: {free_bytes:,} bytes; "
                    f"required approximately: {required:,} bytes. "
                    "The runner needs room for the IPSW and "
                    "temporary extraction files."
                )

        download_file(
            download_url,
            ipsw_path,
            expected_size=expected_size,
        )
    else:
        log("A previously downloaded IPSW exists.")

    log("Calculating IPSW SHA-256.")
    ipsw_sha256 = sha256_file(ipsw_path)

    expected_sha256 = (
        firmware.get("sha256")
        or firmware.get("sha-256")
    )

    checksum_verified = None

    if expected_sha256:
        checksum_verified = (
            ipsw_sha256.lower() == expected_sha256.lower()
        )

        if not checksum_verified:
            raise RuntimeError(
                "IPSW SHA-256 mismatch. Stopping analysis."
            )

        log("IPSW SHA-256 verification passed.")
    else:
        log(
            "IPSW.me did not supply a SHA-256 value. "
            "The local SHA-256 will be recorded, but "
            "independent SHA-256 verification is unavailable."
        )

    kernel_output = None

    with zipfile.ZipFile(ipsw_path, "r") as archive:
        bad_member = archive.testzip()

        if bad_member:
            raise RuntimeError(
                f"ZIP integrity check failed at {bad_member}"
            )

        manifest = read_build_manifest(archive)

        if manifest:
            if (
                manifest.get("ProductVersion") != IOS_VERSION
                or manifest.get("ProductBuildVersion")
                != BUILD_VERSION
                or DEVICE not in manifest.get(
                    "SupportedProductTypes", []
                )
            ):
                raise RuntimeError(
                    "BuildManifest.plist does not match "
                    "the configured device and firmware."
                )

        kernel_info = find_kernel_entry(archive)

        kernel_name = kernel_info.filename.rsplit("/", 1)[-1]

        kernel_output = KERNEL_DIR / kernel_name

        extract_member(
            archive,
            kernel_info,
            kernel_output,
        )

        security_entries = []

        for info in archive.infolist():
            name = info.filename.lower()

            if any(
                term in name
                for term in (
                    "trustcache",
                    "trust_cache",
                    "devicetree",
                    "sep-firmware",
                )
            ):
                security_entries.append({
                    "name": info.filename,
                    "size_bytes": info.file_size,
                })

    kernel_metadata = describe_file(kernel_output)

    report = {
        "device": DEVICE,
        "ios_version": IOS_VERSION,
        "build": BUILD_VERSION,
        "firmware_filename": filename,
        "firmware_size_bytes": ipsw_path.stat().st_size,
        "firmware_sha256": ipsw_sha256,
        "expected_sha256_from_api": expected_sha256,
        "checksum_verified_against_api": checksum_verified,
        "build_manifest": manifest,
        "kernelcache": {
            "archive_path": kernel_info.filename,
            "extracted_path": str(
                kernel_output.relative_to(ROOT)
            ),
            **kernel_metadata,
        },
        "security_related_entries": security_entries,
        "analysis_status": (
            "Kernelcache extracted and fingerprinted. "
            "No vulnerability determination has been made."
        ),
    }

    json_path = REPORTS / "kernel-analysis.json"
    json_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    text_path = REPORTS / "kernel-analysis.txt"

    lines = [
        "iOS Kernelcache Analysis",
        "========================",
        "",
        f"Device: {DEVICE}",
        f"iOS version: {IOS_VERSION}",
        f"Build: {BUILD_VERSION}",
        f"IPSW size: {ipsw_path.stat().st_size:,} bytes",
        f"IPSW SHA-256: {ipsw_sha256}",
        f"Checksum verified against API: {checksum_verified}",
        "",
        "BUILD MANIFEST",
        "--------------",
        json.dumps(manifest, indent=2),
        "",
        "KERNELCACHE",
        "-----------",
        f"Archive entry: {kernel_info.filename}",
        f"Extracted file: {kernel_output}",
        f"Size: {kernel_metadata['size_bytes']:,} bytes",
        f"SHA-256: {kernel_metadata['sha256']}",
        f"First 64 bytes (hex): "
        f"{kernel_metadata['first_64_bytes_hex']}",
        f"First 64 bytes (ASCII): "
        f"{kernel_metadata['first_64_bytes_ascii']}",
        "",
        "SECURITY-RELATED ARCHIVE ENTRIES",
        "--------------------------------",
    ]

    for item in security_entries:
        lines.append(
            f"{item['name']} ({item['size_bytes']:,} bytes)"
        )

    lines.extend([
        "",
        "INTERPRETATION",
        "--------------",
        "This stage extracts and fingerprints the kernelcache.",
        "It does not prove the existence or absence of a vulnerability.",
        "The kernelcache may require additional format-aware parsing.",
        "",
    ])

    text_path.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    log(f"Created {json_path}")
    log(f"Created {text_path}")
    log(f"Kernelcache SHA-256: {kernel_metadata['sha256']}")
    log("Kernelcache extraction completed successfully.")


if __name__ == "__main__":
    try:
        main()
    except (
        OSError,
        ValueError,
        KeyError,
        RuntimeError,
        urllib.error.URLError,
        zipfile.BadZipFile,
        plistlib.InvalidFileException,
    ) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
