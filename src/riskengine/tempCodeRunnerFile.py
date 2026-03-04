# run_hars.py
"""
Authoritative HARS v1 execution entrypoint.
This is the ONLY script that runs scoring end-to-end.
"""

import sys
from pathlib import Path
import logging

from config import run_risk_engine

# -----------------------------------------------------------------------------
# CONFIGURATION
# -----------------------------------------------------------------------------

RUNTIME_DB_DIR = Path("C:/ProgramData/SmartPatch/runtime")
DEV_DB_PATH = Path("dev_db.sqlite")

LOG_LEVEL = logging.INFO

# -----------------------------------------------------------------------------
# BOOTSTRAP
# -----------------------------------------------------------------------------

def find_latest_runtime_db() -> Path:
    dbs = sorted(
        RUNTIME_DB_DIR.glob("runtime_*.sqlite"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )
    if not dbs:
        raise FileNotFoundError("No runtime database found")
    return dbs[0]


def main():
    logging.basicConfig(
        level=LOG_LEVEL,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    logging.info("Starting HARS v1 risk engine")

    try:
        runtime_db = find_latest_runtime_db()
        logging.info(f"Using runtime DB: {runtime_db}")

        if not DEV_DB_PATH.exists():
            raise FileNotFoundError(f"Dev DB not found: {DEV_DB_PATH}")

        run_risk_engine(
            runtime_db_path=runtime_db,
            dev_db_path=DEV_DB_PATH
        )

        logging.info("HARS scoring completed successfully")

    except Exception as e:
        logging.exception("HARS execution failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
