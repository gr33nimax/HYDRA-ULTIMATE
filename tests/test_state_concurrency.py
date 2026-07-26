import copy

from hydra.core.state import AppState
from hydra.services.configuration import restore_state_in_place


def test_rollback_restores_desired_state_but_preserves_revision():
    state = AppState(revision=7)
    state.network.domain = "before.example"
    snapshot = copy.deepcopy(state)

    state.revision = 8
    state.network.domain = "after.example"
    restore_state_in_place(state, snapshot)

    assert state.network.domain == "before.example"
    assert state.revision == 8
