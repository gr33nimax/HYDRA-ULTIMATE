# retirement inventory — parent review after 5804f53f

Partial review, not whole-product acceptance. Parent mechanically checked HEAD
against the final inventory: 328 retired functions, 328 unique rows, no missing,
extra or duplicate rows. Native mandatory gates passed; parent final-tree
project-venv `verify.py` is separately running (`bdae9195f`). Runtime is still the
42-line Protocol and has no production binding.

The new profile/link/identity, firewall rollback, scoped credential cleanup,
revision/askpass and shared-input regressions are useful. Complete enumeration
alone is **not** complete semantic parity. Before final acceptance, repair these
specific overbroad mappings; do not regenerate the entire table or infer purpose
from filename alone:

1. Preserved-patch paragraph for
   `test_current_node_apply_error_prevents_healthy_even_when_control_is_ok` still
   points to the stale-management test, although the newly added
   `test_online_management_with_failed_apply_renders_subscription_error` is the
   actual correct evidence. Parent read its assertions: Online, failed operation,
   `sub_state == error`, `SUB : ❌ERROR`.
2. `test_reconciling_two_nodes_does_not_stale_the_first_published_snapshot` maps to
   R-PROFILE, but that catalog does not name a two-node sync/revision/idempotence
   regression. Retain the real no-extra-apply behavior or mark the evidence gap.
3. `test_a_broken_snapshot_on_one_node_does_not_remove_another_nodes_profiles`
   maps to generic R-PROFILE. Point to a real two-node subscription assertion with
   one corrupted local bundle and the other still exported, not merely one-node
   uncommitted-pointer rejection.
4. `test_lost_apply_response_retries_the_same_generation` and
   `test_a_retry_after_a_lost_response_does_not_repeat_the_node_side_effect` need
   actual frozen-ID unknown-outcome operation recovery evidence. R-ASKPASS and
   ordinary enrollment/receipt creation are not that evidence. Existing
   `test_unknown_submit_outcome_retries_by_frozen_id_without_blind_resubmit` and
   crash/frozen-intent tests are candidates; read their bodies and bind the right row.
5. `test_wrong_node_snapshot_is_rejected_before_user_mutation` maps to R-APPLY +
   R-ACCOUNT, although the real cross-node rejection is at agent validation.
   R-TRANSPORT's exact cross-node apply-before-submit test is the candidate.
6. `test_protocol_failure_rolls_back_users_and_newly_enabled_protocol` must prove
   both restored users **and** protocol/config state. An assertion only about
   users after runtime-proof failure is not a complete equivalent. Add the missing
   failure-injection assertion without changing earlier expectations if needed.
7. `test_node_preparation_is_delegated_to_the_plugin_owner` and
   `test_a_plugin_that_cannot_prepare_its_node_config_stops_the_apply_with_its_reason`
   cannot lose canonical-owner dispatch/fail-closed material validation merely
   because the old reconciler class was removed. Separate retired API shape from
   still-valid plugin behavior and give actual new evidence.
8. `test_revision_lookup_failure_stops_install_and_reports_safe_actionable_error`
   asserts secret redaction of a revision failure. R-WIZARD + generic numeric
   R-TUI input are not error-redaction assertions. Bind the actual revision/error
   owner regression; add missing checks if absent.
9. `test_failures_are_classified_by_what_broke_not_by_the_message_alone` must map
   to actual typed/stage-specific transport/storage/apply errors, not a generic
   card-string test. Current transport saturation phase assertions cover transport,
   not automatically profile-storage/apply classification.
10. The old complete AWG/VLESS node E2E test may retire its generation API and fake
    scenario, but actual transport-material/profile encoding correctness remains a
    valid invariant. Cite current canonical protocol tests or add node-projection
    coverage. Do not call AWG required local material a product-only generation API.

For each row, use real assertion evidence or explicitly carry a residual gap into
the open implementation task. No fabricated full parity, no restoring old product,
no deleted/skipped/weakened shared tests. Runtime foundation work can remain
fail-closed while these concrete proof repairs are completed; deployment and full
acceptance remain blocked until both substantive runtime and invariant evidence
are finished. Preserve the already accepted accounting/size/store fixes.
