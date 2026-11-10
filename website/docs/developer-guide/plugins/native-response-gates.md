---
sidebar_label: Native response gates
---

# Native trusted turns and required response gates (candidate)

This additive capability is an opt-in candidate, not a deployment or security sandbox.
The concrete consumer is an external read-only project-context plugin: it needs to
prove which native Human turn requested a query and prevent model drafts from
reaching the user before current Control evidence is available. Product Mission
state, policy, SQLite, project selection and provider routing remain external.

## Capability ownership

| Capability | Hermes native | External adapter/Control |
| --- | --- | --- |
| Human turn provenance | Issue and fence | Consume |
| Plugin host identity | Own activation and process identity | Authenticate peer and pinned registration |
| Tool invocation context | Bind outside model args | Consume |
| Required response gate | Enforce before streaming | Register validator and profile requirement |
| Response use receipt | Issue commit/transport stages | Reconcile use against Control |
| Mission / project policy / SQLite | No product ownership | Sole product owner and writer |

## Operator scope and missing plugins

An isolated profile can configure:

```yaml
plugins:
  enabled: [project-context]
  required_response_gates:
    - plugin_id: project-context
      request_terms: [Cloud Test, cloud-test, 云测试, Load Testing, Load Test, load-testing, 压测]
```

`request_terms` performs case-insensitive substring matching on this turn's input.
It is an explicit lexical scope, not semantic intent classification. Configure all
supported aliases and repository names. A request outside that scope is not
protected. Multimodal input with any configured requirement is conservatively
covered. An unreadable or malformed scope fails closed. With an empty requirement
list, ordinary chat keeps its normal streaming. The requirement belongs to the
profile host, so unloading or failing to discover the plugin cannot remove it.

For a selected turn, the facade holds output before running the Agent loop.
Stream/interim/reasoning/status callbacks and stream hook fanout do not release
drafts. Tokens are dropped rather than buffered. The model still consumes tokens;
this adds final-response latency to selected queries only. Evidence is at most
64 KiB per plugin, valid for at most 60 seconds, and the validator gets a two-second
deadline per required plugin. A plugin thread cannot be killed safely; timed-out
workers are daemon observers, their late answers never reopen the closed turn.

## Native ingress and plugin calls

The real classic terminal Enter boundary issues an opaque one-use Human envelope;
input processing carries it separately from transformed text into the Agent thread.
The six source values are `TOP_LEVEL_HUMAN`, `SCHEDULED`, `WEBHOOK`,
`AGENT_CONTINUATION`, `SUBAGENT`, `TOOL_GENERATED`. Only an issued, unconsumed object
in the same profile/session is accepted. A dict, dataclass copy, environment variable
or tool argument cannot issue an ingress. Python host code is trusted; this is not
containment against malicious code imported into the Hermes process.

**Qualified entry scope:** classic keyboard submit. The explicit internal native
issuer supports six source values and tests exercise rejection of all nonhuman
values through the real Agent. This patch does not yet add native issuance to
Gateway, cron, voice, `-q/-Q`, automatic goals or subagent entry points. Calls without
an ingress cannot gain Human admission. Source classification on those production
surfaces remains unqualified; do not report synthetic issuer tests as deployed
Gateway or scheduled-origin proof.

An in-process Python plugin can use:

```python
def register(ctx):
    ctx.register_response_gate(validate, on_commit=observe_commit)

    def query(args, *, native_context=None, **kwargs):
        # args are model-controlled. native_context is supplied by the host wrapper.
        result = control_query_using_native_identity(native_context)
        ctx.native_host.record_result(
            native_context,
            control_request_id=result.request_id,
            context_revision=result.context_revision,
            mission_revision=result.mission_revision,
            query_result_digest=result.digest,
            output=result.deterministic_projection,
            ttl=30,
        )
        return result.tool_result

    # Register query using the ordinary ctx.register_tool API.
```

`native_context` is opt-in by explicit handler parameter. Old narrow tool handlers
retain their original signature. Sync/async calls bind ContextVars around the
invocation; model args remain separate. An invocation binds plugin ID, activation
instance/generation, authenticated process PID/UID/birth/executable, profile,
actor/conversation/session/turn, invocation ID and tool name. Unload invalidates
its host and leases. Requirements cannot be satisfied by a previous activation.
`plugins.isolation: host` refuses these new live-object APIs; no implicit fallback
to in-process execution is introduced. That separate plugin-host transport still
requires its own qualification.

`ctx.native_turn_attestation()` is for a trusted intake hook, never a model tool.
The local wire contract is `hermes.native-turn/1`: canonical JSON body plus HMAC,
registered host key, a bounded active-turn lease and at most 60-second lifetime.
The verifier must authenticate kernel peer credentials and independently pin the
exact process instance (including boot, executable digest and birth in a consumer
such as the macOS Control). PID/UID strings in the envelope are not authentication.
`host.verify_attestation` is the in-process live verifier API; there is no automatic
cross-process key bootstrap. A separate-process verifier must not copy this live
Python object or turn it into a model-visible registration RPC. Replaying after
turn finish, wrong profile/generation/peer, or modifying the envelope is rejected.

## Required validation and result use

`validate(evidence) -> True` must re-query Control and verify current request,
context, Mission revision, digest and freshness. Exceptions, timeouts, no tool call,
no evidence, stale evidence and host removal deny output. Native code rechecks
expiry after the validator, so evidence that expires during validation is rejected.
Optional `transform_llm_output` runs first; the required gate runs afterwards.
The final answer is the exact Control projection, never model prose dressed with
an evidence ID. Normal final text is gated before its first transcript persistence;
recovery/early-result paths also pass the facade gate. Old transcript rows and
system prompts are not rewritten.

`on_commit(receipt) -> True` is an optional bounded two-second observer. It gets a
copy after the projected result has been committed for handoff to the renderer.
It can reconcile the consumer's response-use record. It cannot rewrite output.
An exception/lost ACK is `UNKNOWN`; it does not repeat intake or query. This is
separate from optional `post_llm_call`, which cannot prove output use.

The local receipt schema `hermes.response-receipt/1` contains Human turn ID,
plugin activation/invocation IDs, Control request ID, context/Mission revisions,
query/final output digests, gate decision, model status, output commit status,
transport status and observer ACK statuses. These stages mean:

| Stage | Meaning |
| --- | --- |
| `MODEL_COMPLETED` | Model made a call and runtime did not report failure; no delivery claim |
| `OUTPUT_GATE_PASSED` | Current native evidence passed the mandatory gate |
| `OUTPUT_COMMITTED` | Runtime handed a fixed projection or explicit denial result to its caller |
| `TRANSPORT_DELIVERED` | Native transport accepted its write/send; not proof a Human read it |

Classic terminal acknowledges only after its final response print succeeds. A
failed print or missing ACK stays `UNKNOWN`. Other renderers/transports have no ACK
integration in this candidate. The acknowledgement API verifies the original result
object, receipt identity and committed digest; a model cannot ACK a copied result.
The in-memory receipt cache is bounded to 1024 committed results. This candidate
adds no durable receipts store and no retry service.

## Version and maintenance boundary

The candidate base is upstream `5b147ab036d6d19131bff8d20701b5001eab844a`.
The observed managed installation is v0.22.3, labeled by a local carried commit
`1bf96f002dd3c694751f2159800951773c9f2720`; that local SHA was not found upstream.
A separate legacy CLI checkout reports v0.21.4 and must not be mistaken for the
running Gateway. All ten modified existing Python integration files were byte-identical between
the pinned upstream base and the managed source. This proves a patch surface,
not equality of the full production artifact or its already loaded code.

| Disposition | Content and retirement |
| --- | --- |
| KEEP | Native Agent, loader, workers, profiles, session store and transports |
| ADAPT | External plugin consumes native identity/gate; external Control remains Mission owner |
| TEMP_PATCH | This generic native capability until accepted upstream; retire only after equivalent behavior passes the same tests |
| UPSTREAM | Candidate for generic native API; no third-party product code is absorbed into Hermes |

Touched integration points: turn facade/context/finalizer, stream delivery,
chat-completion hook fanout, plugin tool/context binding, classic keyboard queue,
terminal renderer, config defaults and host-isolation capability table. Behavior
lives in sibling modules. Small existing helpers moved to siblings offset oversized
file growth; no new service, broker, provider router or product database is added.

Related upstream proposals: [admitted Gateway origin #142762](https://github.com/NousResearch/hermes-agent/pull/142762),
[pre-delivery hook #117080](https://github.com/NousResearch/hermes-agent/pull/117080),
[bot turn identity #147824](https://github.com/NousResearch/hermes-agent/pull/147824).
They overlap individual surfaces, but do not by themselves establish this
pre-stream, missing-plugin-fails-closed contract. Evaluate/reuse their accepted
surfaces when porting Gateway support; no merge or deployed status is inferred.

Build using PM in a disposable home/runtime, then run:

```sh
HERMES_PYTHON="$PWD/.venv/bin/python" scripts/run_tests.sh \
  tests/agent/test_native_response_gate.py \
  tests/agent/test_native_turn_capabilities.py \
  tests/agent/test_transform_llm_output_persistence.py -q
.venv/bin/python scripts/check
```

The suite uses real Agent/plugin/tool/SSE code with an explicitly synthetic model
and synthetic Control, and checks ordinary streaming, failures, profile changes,
keyboard issuance and terminal ACK. Consumer bridge qualification is separate.
External test paths must explicitly load `tests.conftest` before collection; the
runner alone does not install the production Home I/O guard for such paths.
Always assert the isolated Home before creating a fixture plugin or config.

For migration, reapply only this native series onto the accepted artifact base;
reconcile every carried patch and file digest, requalify the adapter, then obtain
separate Human approval for a production switch. Never replace a carried production
checkout with the upstream base. Rollback removes the candidate branch/profile or
returns to the prior accepted artifact; this patch has no product data migration.
Keep a required profile gate enabled while the capability is unavailable so facts
fail closed. Retire the patch only with equivalent source, process, scope,
pre-stream, stale-result, receipt and continuity evidence.
