# iOS-Kernel-Lab

A reproducible research toolkit for inspecting iOS firmware,
cataloguing kernel-related components, and organizing public
security research.

## Initial target

- Device: iPhone 13
- Identifier: iPhone14,5
- iOS version: 27.0
- Build: 24A437

## Research goals

1. Identify and verify firmware builds.
2. Inventory IPSW archive contents.
3. Examine kernel-related files and metadata.
4. Organize public vulnerability advisories and patch information.
5. Document findings with reproducible evidence.

## Repository layout

- `scripts/inspect_ipsw.py`: Firmware retrieval and archive inventory.
- `.github/workflows/inspect-firmware.yml`: On-demand analysis workflow.
- `reports/`: Local report output; generated reports are published as
  GitHub Actions artifacts rather than committed to the repository.

## Running the workflow

1. Open the Actions tab.
2. Select "Inspect iOS Firmware".
3. Select "Run workflow".
4. Download the `ios-firmware-report` artifact when the job completes.

The workflow retrieves firmware metadata from the IPSW.me API, checks
the downloaded archive against its published SHA-256 checksum when
available, and inventories the archive.

## Scope and limitations

This project performs firmware identification and static inventory.
File names and metadata alone do not establish that a vulnerability
exists or that a particular exploit is possible.

Do not commit firmware images, private exploit material, credentials,
or sensitive device data to this repository.
