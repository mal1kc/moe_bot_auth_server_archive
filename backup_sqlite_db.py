# this script meant to be run with cron
import os
import sys
from datetime import datetime
from pathlib import Path

BACKUP_EVENTS = {
    "daily": 1,
    "weekly": 7,
    "monthly": 30,
}

BACKUP_DIR = Path(__file__).parent.parent / "db_backups"
DB_FILE_PATH = Path(__file__).parent.parent / "db.sqlite3"
BACKUP_FILE_FORMAT = "db_backup_{time}.sqlite3"


def get_backup_file_name():
    time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return BACKUP_FILE_FORMAT.format(time=time)


def backup():
    db_file_path = DB_FILE_PATH
    if not db_file_path.exists():
        print(f"db file {db_file_path} not found")
        return
    if not BACKUP_DIR.exists():
        BACKUP_DIR.mkdir()
    backup_file_name = get_backup_file_name()
    backup_file_path = BACKUP_DIR / backup_file_name
    os.system(f"cp {db_file_path} {backup_file_path}")
    print(f"backup created: {backup_file_path}")


def clean_backups():
    backup_files = [
        file
        for file in BACKUP_DIR.iterdir()
        if file.is_file()
        and file.name.startswith("db_backup_")
        and file.name.endswith(".sqlite3")
    ]
    if not backup_files:
        print("no backups found")
        return
    # sort by modification time (oldest first)
    backup_files.sort(key=lambda file: file.stat().st_mtime)
    # checking daily limit
    daily_limit = BACKUP_EVENTS["daily"]
    if len(backup_files) > daily_limit:
        for file in backup_files[: len(backup_files) - daily_limit]:
            file.unlink()
            print(f"backup deleted: {file}")
    # checking weekly limit
    weekly_limit = BACKUP_EVENTS["weekly"]
    weekly_backups = [
        file
        for file in backup_files
        if (datetime.now() - datetime.fromtimestamp(file.stat().st_mtime)).days
        < weekly_limit
    ]
    if len(weekly_backups) > weekly_limit:
        for file in weekly_backups[: len(weekly_backups) - weekly_limit]:
            file.unlink()
            print(f"backup deleted: {file}")
    # checking monthly limit
    monthly_limit = BACKUP_EVENTS["monthly"]
    monthly_backups = [
        file
        for file in backup_files
        if (datetime.now() - datetime.fromtimestamp(file.stat().st_mtime)).days
        < monthly_limit
    ]
    if len(monthly_backups) > monthly_limit:
        for file in monthly_backups[: len(monthly_backups) - monthly_limit]:
            file.unlink()
            print(f"backup deleted: {file}")


if __name__ == "__main__":
    backup()
    clean_backups()
    sys.exit(0)
