"""Small shared utilities and repository paths; importing this starts no processes."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "elasticsearch"
SCRATCH = ROOT / ".validation-local"


class Unavailable(RuntimeError):
    """The requested genuine comparison cannot be established."""


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_json(path, value):
    """Write a private result record; let I/O failures reach the owning cleanup scope."""
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def clean_environment():
    """Remove inherited Java, loader and shell overrides from owned helper launches."""
    env = os.environ.copy()
    for key in ("JAVA_HOME", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
                "JAVA_OPTS", "CLASSPATH", "ES_JAVA_HOME", "ES_JAVA_OPTS",
                "ES_PATH_CONF", "ES_HOME", "ES_TMPDIR", "LD_PRELOAD", "LD_AUDIT",
                "LD_LIBRARY_PATH", "BASH_ENV", "ENV"):
        env.pop(key, None)
    return env


def utc_now():
    return datetime.now(timezone.utc).isoformat()
