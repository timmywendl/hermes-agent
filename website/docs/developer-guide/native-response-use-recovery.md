# Native response-use recovery (isolated candidate)

This API supports the native Control adapter without granting production admission.
Control alone decides whether response use completed. A persisted selector grants no
identity, permission, old-turn capability or authority to replay a write.

## Existing owner path

`run_guarded` binds `agent._session_db` on the private TurnGate. Core never opens a
SessionDB. Classic CLI uses its injected SessionDB writer; managed execution uses
RuntimeSessionStore and the existing authenticated `worker.persist` owner route.
The private `native.recovery` operation reserves sequence zero for idempotent sidecar
operations, separate from sequenced transcript receipts; it neither advances that
sequence nor writes worker_receipts or the worker JSON retry journal. The existing
owner checks profile, actor, live process birth/secret, assignment, generation and
epoch; it repeats epoch/assignment/status fencing within the sidecar transaction.
No new server, database, file journal or writer is introduced.

Response-critical writes use `SessionDB._execute_write` with the existing activity
patience capped by the capability deadline. The proxy uses its already authenticated
owner link and refuses native discovery/reconnect. A missing owner, read-only/full/
busy database, expired deadline or uncertain write raises to Core, which returns a
fixed UNKNOWN and sends no response_used. This is not a hard-real-time guarantee;
the separate 2.000s response-release SLA remains NOT_PROVEN.

## Private schema and retention

Schema 33 adds `native_response_use_hints` to the existing profile state.db. Fields:
project_id, request_id, result_ref, projection_digest, original_session_id,
original_turn_id, original_control_epoch, original_channel_ref,
original_host_generation, created_at, recovery_expires_at, retained_until, state.
The primary key is project/request/result/projection. Times are owner-generated;
no caller-supplied expiry or evidence object is stored.

At most 16 records are retained. The automatic window is 600 seconds, then the
record becomes EXPIRED and blocks intake across restart. At 30 days the selector
and provenance are removed, leaving one fixed-size BLOCKED project marker in the
same table. The marker has no automatic clearance: retention cannot silently
permit a new intake. Exact completion clears all selectors for the project/request;
other requests and permanent blocked markers are unaffected. Duplicate pending
selector writes preserve the first provenance and expiry.

No FK to sessions is used; deletion/pruning of a transcript cannot discard uncertain
operational evidence. The sidecar is absent from conversation messages, model
context, Session projections and user export. No prompt, response, model output,
credentials, raw Control result or ControlEvidence object enters this table.

## Core capability APIs

Only the original hook-bound `NativeIntakeCapability` may call
`recovery_hints(project_id)` for the selected current Human project. It validates
current profile/Host/generation/turn/policy/deadline before and after the read and
returns only `{state: NONE}`, `{state: ONE, selector: {request_id, result_ref,
projection_digest}}`, `{state: AMBIGUOUS}`, `{state: EXPIRED}` or `{state: UNKNOWN}`.
Reading does not consume its single existing Control intake/pending_lookup operation.
Multiple records are AMBIGUOUS; no newest-record heuristic is used. The selector
is used only in existing exact Control readback under a new current Human capability.

`PluginHost.record_result` accepts the validated `project_id` already checked
against the current selected project and actual Control binding. Original evidence
object identity and original Human/Host/channel/epoch remain mandatory.

`CommitUseCapability.response_used` validates original committed evidence, durably
persists the selector, revalidates current state after persistence and channel-lock
acquisition, then sends the original Control RPC once. Exact matching
COMPLETED_READ_ONLY clears all hints for that project/request; every other outcome
retains them. Cleanup uncertainty returns UNKNOWN. The same exact completion
cleanup follows a fresh hook's pending_lookup readback. A capability is never
serialized, loaded or recreated from the sidecar after restart.
