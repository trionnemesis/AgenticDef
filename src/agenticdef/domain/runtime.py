"""No model, network, vendor, or persistence dependencies."""
from copy import deepcopy
from hashlib import sha256
from types import MappingProxyType

from .contracts import canonical, validate
from .errors import BudgetError, ContractError, PolicyError, ScopeError, ToolNotAllowedError

TERMINAL = frozenset({"COMPLETED", "INSUFFICIENT_EVIDENCE", "INCONCLUSIVE", "FAILED"})
TRANSITIONS = {
    "RECEIVED": {"VALIDATED", "FAILED"},
    "VALIDATED": {"POLICY_LOADED", "FAILED"},
    "POLICY_LOADED": {"INVESTIGATING", "FAILED"},
    "INVESTIGATING": set(TERMINAL),
}
TOOL_ARGUMENTS = MappingProxyType({
    "get_change_event": ("event_id",),
    "get_rbac_object": ("kind", "namespace", "name", "version"),
    "get_subject_bindings": ("subject_id",),
    "get_approval_record": ("change_id",),
})


def transition(current, target):
    if target not in TRANSITIONS.get(current, set()):
        raise PolicyError(f"Forbidden state transition: {current} -> {target}")
    return target


def identity(event_id, policy_version):
    return "inv-" + sha256(canonical([event_id, policy_version]).encode()).hexdigest()


class Policy:
    def __init__(self, value):
        self._value = deepcopy(validate("policy", value))

    @property
    def version(self): return self._value["policy_version"]

    @property
    def allowed_tools(self): return tuple(self._value["allowed_tools"])

    @property
    def limits(self):
        return {k: self._value[k] for k in ("max_runtime_seconds", "max_model_calls", "max_tool_calls", "max_evidence_items")}

    @property
    def digest(self): return sha256(canonical(self._value).encode()).hexdigest()

    def admits_event(self, event_id):
        return event_id in self._value["resource_scope"]["event_ids"]

    def authorize(self, tool, arguments):
        if tool not in TOOL_ARGUMENTS or tool not in self.allowed_tools:
            raise ToolNotAllowedError("Unregistered or disallowed tool / 工具未獲允許")
        if not isinstance(arguments, dict) or set(arguments) != set(TOOL_ARGUMENTS[tool]):
            raise ContractError("Tool argument shape / 工具參數格式錯誤")
        if any(not isinstance(v, str) or len(v) > 128 or (not v and k != "namespace") for k, v in arguments.items()):
            raise ContractError("Invalid tool identifier / 無效工具識別碼")
        scope = self._value["resource_scope"]
        if tool == "get_rbac_object":
            permitted = arguments in scope["rbac_objects"]
        else:
            key = TOOL_ARGUMENTS[tool][0]
            permitted = arguments[key] in scope[{"event_id": "event_ids", "subject_id": "subject_ids", "change_id": "change_ids"}[key]]
        if not permitted:
            raise ScopeError("Resource outside trusted scope / 資源超出授權範圍")


class Budget:
    def __init__(self, policy, clock):
        self.limits = policy.limits
        self.clock = clock
        self.started = clock.monotonic()
        self.model_calls = self.tool_calls = self.evidence_items = 0
        self.stopped = False

    def remaining(self):
        return max(0.0, self.limits["max_runtime_seconds"] - (self.clock.monotonic() - self.started))

    def check(self):
        if self.stopped or self.remaining() <= 0:
            raise BudgetError("Runtime or terminal limit / 已到時限或終態")
        for counter in ("model_calls", "tool_calls", "evidence_items"):
            if getattr(self, counter) >= self.limits["max_" + counter]:
                raise BudgetError("Hard limit reached: " + counter)

    def reserve(self, kind):
        self.check()
        if kind not in ("model_calls", "tool_calls"):
            raise ContractError("Unknown budget counter")
        setattr(self, kind, getattr(self, kind) + 1)

    def usage(self):
        return dict(model_calls=self.model_calls, tool_calls=self.tool_calls,
                    evidence_items=self.evidence_items,
                    runtime_seconds=max(0, self.clock.monotonic() - self.started))
