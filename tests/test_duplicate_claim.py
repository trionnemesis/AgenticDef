"""Deterministic duplicate-path parity; no timing-dependent race orchestration."""
import asyncio
from copy import deepcopy

import pytest

from agenticdef.domain.errors import ContractError, PolicyError
from agenticdef.domain.runtime import TERMINAL
from test_investigator import setup


class DuplicateRepository:
    """Expose the winner either immediately or after a deliberately lost claim."""

    def __init__(self, record, lose_claim):
        self.record = deepcopy(record)
        self.lose_claim = lose_claim
        self.reads = 0
        self.claims = 0
        self.writes = []

    def get_by_idempotency_key(self, key):
        assert key == self.record["investigation_id"]
        self.reads += 1
        if self.lose_claim and self.reads == 1:
            return None
        return deepcopy(self.record)

    def create_investigation(self, key, metadata):
        assert self.lose_claim and self.reads == 1
        assert key == self.record["investigation_id"]
        self.claims += 1
        return False

    def _unexpected_write(self, *args, **kwargs):
        self.writes.append((args, kwargs))
        pytest.fail("Duplicate lookup must not write audit, evidence, result or state")

    append_audit_event = append_evidence = save_result = mark_terminal = _unexpected_write


@pytest.fixture
def terminal_record(tmp_path):
    inv, event, _, _, _ = setup(tmp_path / "winner")
    record = asyncio.run(inv.run(event))
    assert record["state"] == "COMPLETED"
    return record


def assert_read_only(model, tools, repo, expected):
    assert model.calls == 0 and not tools.executed
    assert repo.reads == (2 if repo.lose_claim else 1)
    assert repo.claims == int(repo.lose_claim)
    assert repo.writes == []
    assert repo.record == expected


@pytest.mark.parametrize("lose_claim", [False, True], ids=["existing", "lost-claim"])
@pytest.mark.parametrize("field", [
    "event_digest", "policy_digest", "policy_version", "model_provider", "evidence_provider",
])
def test_duplicate_metadata_mismatch_is_rejected(tmp_path, terminal_record, lose_claim, field):
    terminal_record["metadata"][field] = "changed-" + terminal_record["metadata"][field]
    repo = DuplicateRepository(terminal_record, lose_claim)
    inv, event, model, tools, _ = setup(tmp_path, repo=repo)
    with pytest.raises(PolicyError, match="Idempotency key reused with changed event or policy"):
        asyncio.run(inv.run(event))
    assert_read_only(model, tools, repo, terminal_record)


@pytest.mark.parametrize("lose_claim", [False, True], ids=["existing", "lost-claim"])
@pytest.mark.parametrize("state", sorted(TERMINAL))
def test_duplicate_terminal_result_is_validated(tmp_path, terminal_record, lose_claim, state):
    terminal_record["state"] = state
    terminal_record["result"] = {"status": "likely_benign"}  # Missing required result fields.
    repo = DuplicateRepository(terminal_record, lose_claim)
    inv, event, model, tools, _ = setup(tmp_path, repo=repo)
    with pytest.raises(ContractError):
        asyncio.run(inv.run(event))
    assert_read_only(model, tools, repo, terminal_record)


@pytest.mark.parametrize("lose_claim", [False, True], ids=["existing", "lost-claim"])
def test_matching_terminal_duplicate_is_read_only(tmp_path, terminal_record, lose_claim):
    repo = DuplicateRepository(terminal_record, lose_claim)
    inv, event, model, tools, _ = setup(tmp_path, repo=repo)
    assert asyncio.run(inv.run(event)) == terminal_record
    assert_read_only(model, tools, repo, terminal_record)


@pytest.mark.parametrize("lose_claim", [False, True], ids=["existing", "lost-claim"])
@pytest.mark.parametrize("state", ["RECEIVED", "INVESTIGATING", "RUNNING"])
def test_unfinished_duplicate_does_not_restart(tmp_path, terminal_record, lose_claim, state):
    record = dict(investigation_id=terminal_record["investigation_id"], state=state, result=None)
    if state != "RUNNING":
        record.update(metadata=deepcopy(terminal_record["metadata"]), audit=[], evidence=[], bodies={})
    # RUNNING intentionally has no metadata: the atomic directory claim exists,
    # but its first record has not been persisted (or the winner crashed).
    repo = DuplicateRepository(record, lose_claim)
    inv, event, model, tools, _ = setup(tmp_path, repo=repo)
    assert asyncio.run(inv.run(event)) == record
    assert_read_only(model, tools, repo, record)
