from copy import deepcopy

from ..domain.contracts import canonical
from ..domain.errors import ToolExecutionError


class FixtureTools:
    """Look up exact typed requests in memory. Model input is never a file path."""
    provenance = "synthetic_fixture"
    def __init__(self, entries):
        if not isinstance(entries, list) or len(entries) > 64:
            raise ToolExecutionError("Invalid fixture collection")
        self._entries = deepcopy(entries)
        self.executed = []

    def _read(self, tool, arguments):
        self.executed.append({"tool": tool, "arguments": deepcopy(arguments)})
        matches = [e for e in self._entries if e.get("tool") == tool and e.get("arguments") == arguments]
        if len(matches) != 1:
            raise ToolExecutionError("Evidence unavailable or ambiguous / 證據缺失或不唯一")
        value = matches[0]
        if not isinstance(value.get("data"), dict) or len(canonical(value).encode()) > 8192:
            raise ToolExecutionError("Invalid or oversized evidence / 證據無效或過大")
        return deepcopy({"source": "synthetic-fixture", "observed_at": value["observed_at"], "data": value["data"]})

    async def get_change_event(self, event_id):
        return self._read("get_change_event", dict(event_id=event_id))

    async def get_rbac_object(self, kind, namespace, name, version):
        return self._read("get_rbac_object", dict(kind=kind, namespace=namespace, name=name, version=version))

    async def get_subject_bindings(self, subject_id):
        return self._read("get_subject_bindings", dict(subject_id=subject_id))

    async def get_approval_record(self, change_id):
        return self._read("get_approval_record", dict(change_id=change_id))
