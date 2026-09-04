"""
Seed script to populate the authorized 5G device inventory database from a CSV file.
Usage:
    python scripts/seed_inventory.py [--csv scripts/sample_devices.csv] [--db data/inventory.db]
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from naswatch.logging_config import setup_logging
from naswatch.storage.models import Device, DeviceStatus, SliceAssignment
from naswatch.storage.sqlite_repo import SQLiteRepository

logger = setup_logging(level="INFO", log_format="console")


def parse_slices_field(slice_str: str) -> list[SliceAssignment]:
    """Parse slice string format '1:000001;2:000002' into SliceAssignment objects."""
    slices = []
    if not slice_str or not slice_str.strip():
        return slices

    for item in slice_str.split(";"):
        item = item.strip()
        if not item:
            continue
        parts = item.split(":")
        sst = int(parts[0])
        sd = parts[1] if len(parts) > 1 else None

        name = "Slice"
        if sst == 1:
            name = "eMBB-Public"
        elif sst == 2:
            name = "uRLLC-Critical"
        elif sst == 3:
            name = "mIoT-Sensors"
        elif sst == 4:
            name = "Enterprise-Private"

        slices.append(SliceAssignment(sst=sst, sd=sd, name=name))
    return slices


def seed_inventory_from_csv(csv_path: str, db_path: str = "data/inventory.db") -> int:
    """Read CSV file and insert devices into SQLite database."""
    csv_file = Path(csv_path)
    if not csv_file.exists():
        logger.error(f"Inventory CSV file not found: {csv_file}")
        return 0

    repo = SQLiteRepository(db_path=db_path)
    count = 0

    with open(csv_file, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            imsi = row.get("imsi", "").strip()
            imei = row.get("imei", "").strip()
            if not imsi or not imei:
                continue

            status_str = row.get("status", "ACTIVE").strip().upper()
            try:
                status = DeviceStatus(status_str)
            except ValueError:
                status = DeviceStatus.ACTIVE

            allowed_slices = parse_slices_field(row.get("allowed_slices", ""))

            device = Device(
                imsi=imsi,
                imei=imei,
                owner_name=row.get("owner_name", "Unknown").strip(),
                device_model=row.get("device_model", "Unknown").strip(),
                status=status,
                allowed_slices=allowed_slices,
                notes=row.get("notes", "").strip(),
            )

            repo.add(device)
            count += 1
            logger.info(
                f"Provisioned device: IMSI={device.imsi} | IMEI={device.imei} | "
                f"Owner={device.owner_name} | Slices={[s.slice_id for s in device.allowed_slices]}"
            )

    logger.info(f"Successfully seeded {count} authorized devices into '{db_path}'.")
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed NASWatch authorized 5G device inventory.")
    parser.add_argument(
        "--csv",
        type=str,
        default="scripts/sample_devices.csv",
        help="Path to CSV file with device records",
    )
    parser.add_argument(
        "--db",
        type=str,
        default="data/inventory.db",
        help="Path to SQLite inventory database",
    )
    args = parser.parse_args()

    seed_inventory_from_csv(args.csv, args.db)


if __name__ == "__main__":
    main()
