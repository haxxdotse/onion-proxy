from pathlib import Path
import os
import sys

BASE_DIR = Path(__file__).resolve().parent
if getattr(sys, "frozen", False):
    DATA_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "onion-proxy"
else:
    DATA_DIR = BASE_DIR

DATABASE_PATH = DATA_DIR / "security.db"
IGNORE_DOMAINS_PATH = (
    DATA_DIR / "ignore_domains.txt"
    if getattr(sys, "frozen", False)
    else BASE_DIR / "settings" / "ignore_domains.txt"
)

DEFAULT_ACTION = "ASK"

MAX_BODY_SIZE = 10 * 1024 * 1024

UPLOAD_METHODS = frozenset({"POST", "PUT", "PATCH"})

UPLOAD_CONTENT_TYPES = (
    "multipart/form-data",
    "application/octet-stream",
    "application/json",
    "application/x-www-form-urlencoded",
)

TEXT_CONTENT_TYPES = (
    "text/",
    "application/json",
    "application/x-www-form-urlencoded",
)

ANALYZABLE_EXTENSIONS = frozenset({
    ".txt", ".json", ".xml", ".csv", ".log", ".env",
    ".pem", ".key", ".conf", ".ini", ".yaml", ".yml",
})
