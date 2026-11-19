"""Single-owner business entry accounting from explicit authenticated context bindings."""
from __future__ import annotations

import copy
import hashlib

from hydra.contracts.managed_node_observations import TrafficSample
from hydra.services.managed_nodes.accounting import traffic_reset_epoch


def scoped_samples(state, bindings, raw, runtime_id, *, commit=True):
    if bindings and (not isinstance(runtime_id, str) or not runtime_id):
        raise ValueError("scoped counters require a process identity")
    baselines = state.install.setdefault("cascade_counter_baselines", {}) if commit else copy.deepcopy(
        state.install.get("cascade_counter_baselines", {}))
    result = []
    users = {user.uuid: user for user in state.users}
    for email, (user_id, context, kind) in bindings.items():
        if kind != "cascade_entry" or user_id not in users:
            continue
        count = raw.get(email, 0)
        if type(count) is not int or count < 0:
            raise ValueError("invalid scoped traffic counter")
        user = users[user_id]
        reset = traffic_reset_epoch(state, user)
        key = f"{user_id}:{context}"
        previous = baselines.get(key, {})
        old_used = previous.get("used", 0)
        old_raw = previous.get("raw", 0)
        changed = previous.get("runtime") != runtime_id or count < old_raw
        epoch = previous.get("epoch")
        if not previous:
            used = count
        elif previous.get("reset") != reset:
            used = 0
            changed = True
        elif changed:
            used = old_used + count
        else:
            used = old_used + count - old_raw
        if not epoch or changed:
            epoch = hashlib.sha256(f"{runtime_id}:{key}:{reset}:{epoch}".encode()).hexdigest()[:32]
        baselines[key] = {"used": used, "raw": count, "runtime": runtime_id, "reset": reset, "epoch": epoch,
                          "user": user_id, "context": context}
    # Retired contexts keep their final cumulative contribution after removal.
    for previous in baselines.values():
        user = users.get(previous["user"])
        if user is not None and previous["reset"] == traffic_reset_epoch(state, user):
            result.append(TrafficSample(user.uuid, previous["context"], "cascade_entry", previous["reset"],
                                        previous["epoch"], previous["used"]))
    return result
