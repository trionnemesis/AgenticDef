"""Local filesystem JSON repository, atomic claim and atomic record replacement.

A crashed running claim stays blocked. Automatic reclaim/re-investigation is
deliberately absent. Do not use this adapter on a distributed filesystem.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import tempfile

from ..domain.contracts import canonical, validate
from ..domain.errors import PersistenceError
from ..domain.runtime import TERMINAL


class JsonRepository:
    def __init__(self, root):
        self.root = Path(root)
        try: self.root.mkdir(parents=True, exist_ok=True)
        except OSError as exc: raise PersistenceError("Cannot create result store") from exc

    def _dir(self, key):
        if not re.fullmatch(r"inv-[a-f0-9]{64}", key):
            raise PersistenceError("Invalid investigation key")
        target = self.root / key
        if target.is_symlink(): raise PersistenceError("Symlink investigation directory rejected")
        return target

    def _write(self, key, record):
        path = self._dir(key)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path, delete=False) as stream:
                temporary = stream.name
                stream.write(canonical(record))
                stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, path / "record.json")
            if hasattr(os, "O_DIRECTORY"):
                descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
                try: os.fsync(descriptor)
                finally: os.close(descriptor)
        except (OSError, ValueError, TypeError) as exc:
            raise PersistenceError("Could not persist investigation / 無法保存調查") from exc
        finally:
            if temporary and os.path.exists(temporary): os.unlink(temporary)

    def get_by_idempotency_key(self, key):
        path = self._dir(key)
        if not path.exists(): return None
        try:
            return json.loads((path / "record.json").read_text(encoding="utf-8"))
        except FileNotFoundError:
            # Claim won by a concurrent invocation, or a crash before first write.
            return {"investigation_id": key, "state": "RUNNING", "result": None}
        except (OSError, ValueError) as exc:
            raise PersistenceError("Unreadable existing investigation") from exc

    def create_investigation(self, key, metadata):
        try: self._dir(key).mkdir()
        except FileExistsError: return False
        except OSError as exc: raise PersistenceError("Cannot claim investigation") from exc
        self._write(key, {"investigation_id": key, "state": "RECEIVED", "metadata": deepcopy(metadata),
                          "audit": [], "evidence": [], "bodies": {}, "result": None})
        return True

    def _running(self, key):
        record = self.get_by_idempotency_key(key)
        if not record or record["state"] in TERMINAL or "audit" not in record:
            raise PersistenceError("Cannot write unowned or terminal investigation")
        return record

    def append_audit_event(self, key, event):
        record = self._running(key)
        record["audit"].append({"sequence": len(record["audit"]) + 1, **deepcopy(event)})
        if event["kind"] == "state": record["state"] = event["target"]
        self._write(key, record)

    def append_evidence(self, key, evidence, body):
        record = self._running(key)
        record["evidence"].append(deepcopy(evidence))
        record["bodies"][evidence["evidence_id"]] = deepcopy(body)
        self._write(key, record)

    def save_result(self, key, result):
        validate("result", result)
        record = self._running(key)
        record["result"] = deepcopy(result)
        self._write(key, record)

    def mark_terminal(self, key, state):
        record = self._running(key)
        if state not in TERMINAL or record["result"] is None:
            raise PersistenceError("Terminal state requires a saved result")
        record["audit"].append({"sequence": len(record["audit"]) + 1, "kind": "terminal", "target": state,
                                "at": record["result"]["timestamps"]["finished_at"]})
        record["state"] = state
        self._write(key, record)
