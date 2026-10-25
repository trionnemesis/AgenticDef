"""Fixed read-only capability contract owned by the domain.

This is deliberately a closed catalog, not a registration mechanism. Adding a
capability requires changing this source and the independent normative
contracts that describe the authority boundary.
"""
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class Capability:
    name: str
    arguments: tuple[str, ...]
    scope_field: str
    scope_identifier: str | None


# Order is part of the stable adapter/model surface. RBAC scope is matched by
# the complete argument object; every other capability uses one named ID.
CAPABILITIES = (
    Capability("get_change_event", ("event_id",), "event_ids", "event_id"),
    Capability("get_rbac_object", ("kind", "namespace", "name", "version"), "rbac_objects", None),
    Capability("get_subject_bindings", ("subject_id",), "subject_ids", "subject_id"),
    Capability("get_approval_record", ("change_id",), "change_ids", "change_id"),
)
CAPABILITY_BY_NAME = MappingProxyType({capability.name: capability for capability in CAPABILITIES})
TOOL_ARGUMENTS = MappingProxyType({capability.name: capability.arguments for capability in CAPABILITIES})
