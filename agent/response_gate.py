"""Mandatory output gate. Selected turns drop live drafts; ordinary turns stream.

The configured scope lives with the host so an absent plugin cannot erase the
requirement. Approved output is a bounded Control projection, not model prose.
"""
from __future__ import annotations

import contextvars
import copy
import inspect
import threading
from time import monotonic
from dataclasses import dataclass, field

from agent.native_turn import (TurnSource, consume_ingress, current_turn, digest)
from hermes_constants import hermes_home_key

UNAVAILABLE = "Current project facts are UNKNOWN: trusted Control evidence is unavailable."
_gates: dict[tuple[str, str], tuple] = {}
_gates_lock = threading.RLock()
_commits = {}


def register_gate(host, validate, *, on_commit=None):
    if not callable(validate) or (on_commit is not None and not callable(on_commit)):
        raise TypeError("gate validator must be callable")
    key = (host.profile, host.plugin_id)
    entry = (host, validate, on_commit)
    with _gates_lock:
        _gates[key] = entry

    def release():
        with _gates_lock:
            if _gates.get(key) is entry:
                _gates.pop(key)
    return release


def gate_available(host):
    with _gates_lock:
        entry = _gates.get((host.profile, host.plugin_id))
    return entry is not None and entry[0] is host and host.live()


def requirements(message):
    from agent.native_selector import select
    selection = select(hermes_home_key(), message)
    if selection is not None:
        return selection.required if selection.valid() else ("<policy-unavailable>",)
    from hermes_cli.config_effective import load_user_config_effective
    config = load_user_config_effective(fail_closed=True)
    entries = config.get("plugins", {}).get("required_response_gates", [])
    if not isinstance(entries, list):
        raise ValueError("invalid required_response_gates")
    # A multimodal request with a configured gate is conservatively covered.
    text = message.casefold() if isinstance(message, str) else None
    selected = []
    for entry in entries:
        if (not isinstance(entry, dict) or not isinstance(entry.get("plugin_id"), str)
                or not entry["plugin_id"] or not isinstance(entry.get("request_terms"), list)
                or not entry["request_terms"]
                or not all(isinstance(t, str) and t.strip() for t in entry["request_terms"])):
            raise ValueError("invalid response gate scope")
        if text is None or any(term.casefold() in text for term in entry["request_terms"]):
            selected.append(entry["plugin_id"])
    return tuple(dict.fromkeys(selected))


@dataclass
class TurnGate:
    ingress: object
    required: tuple
    evidence: dict = field(default_factory=dict)
    lock: object = field(default_factory=threading.RLock)
    closed: bool = False
    finished: bool = False
    receipt: dict = field(default_factory=dict)
    selection: object = None

    @property
    def policy_digest(self):
        return self.selection.digest if self.selection is not None else None

    @property
    def intake_allowed(self):
        return self.selection is not None and self.selection.intake_allowed and self.policy_valid()

    def policy_valid(self):
        return self.selection is not None and self.selection.valid()

    def final_output(self, candidate, *, revalidate=False):
        if not self.required:
            return candidate
        if self.closed and (not revalidate or self.receipt.get("gate_decision") != "OUTPUT_GATE_PASSED"):
            return self.receipt.get("output", UNAVAILABLE)
        self.closed = True  # No late tool/callback can replace the accepted result.
        if self.selection is not None and not self.policy_valid():
            from agent.native_selector import POLICY_UNAVAILABLE
            return self.deny(POLICY_UNAVAILABLE)
        approved = []
        for plugin_id in self.required:
            with _gates_lock:
                entry = _gates.get((hermes_home_key(), plugin_id))
            with self.lock:
                evidence = self.evidence.get(plugin_id)
            if (entry is None or evidence is None or self.ingress is None
                    or self.ingress.source is not TurnSource.TOP_LEVEL_HUMAN):
                return self.deny()
            host, validate, _ = entry
            invocation = evidence.invocation
            if (not host.live() or invocation.ingress is not self.ingress
                    or invocation.host_instance != host.instance
                    or invocation.host_generation != host.generation
                    or evidence.expires_at <= monotonic()):
                return self.deny()
            # Daemon worker + finite wait: a stalled plugin never blocks output
            # indefinitely. It receives an immutable evidence object only.
            result, done = [], threading.Event()
            def check(validator=validate, value=evidence, answer=result, signal=done):
                try:
                    answer.append(validator(value) is True)
                except Exception:  # health: allow BLE001 -- fail-closed plugin boundary; exception text can contain private input
                    answer.append(False)
                finally:
                    signal.set()
            threading.Thread(target=contextvars.copy_context().run, args=(check,), daemon=True).start()
            if (not done.wait(2) or result != [True] or not host.live()
                    or evidence.expires_at <= monotonic()):
                return self.deny()
            with _gates_lock:
                if _gates.get((hermes_home_key(), plugin_id)) is not entry:
                    return self.deny()
            approved.append(evidence)
        output = "\n\n".join(e.output for e in approved)
        self.receipt.update(gate_decision="OUTPUT_GATE_PASSED", output=output,
                            evidence=[{"plugin_id": e.invocation.plugin_id,
                                       "host_instance": e.invocation.host_instance,
                                       "host_generation": e.invocation.host_generation,
                                       "invocation_id": e.invocation.invocation_id,
                                       "control_request_id": e.control_request_id,
                                       "context_revision": e.context_revision,
                                       "mission_revision": e.mission_revision,
                                       "query_result_digest": e.query_result_digest} for e in approved])
        return output

    def deny(self, output=UNAVAILABLE):
        self.receipt.update(gate_decision="DENIED", output=output)
        return output


def gated_output(candidate):
    state = current_turn.get()
    return state.final_output(candidate) if state else candidate


_OUTPUT_CALLBACKS = ("stream_delta_callback", "reasoning_callback", "interim_assistant_callback",
                     "_stream_callback", "tool_progress_callback", "status_callback")


def run_guarded(agent, message, ingress, run):
    session = str(getattr(agent, "session_id", None) or "")
    native = consume_ingress(ingress, session)
    try:
        required = requirements(message)
    except Exception:  # health: allow BLE001 -- unreadable operator policy must never disable a required gate
        # Unreadable policy cannot be treated as no requirement.
        required = ("<policy-unavailable>",)
    from agent.native_selector import select
    selection = select(hermes_home_key(), message)
    state = TurnGate(native, required, selection=selection)
    token = current_turn.set(state)
    saved = {}
    pending = None
    try:
        if required:
            from agent.response_gate_persistence import PendingGateTail
            pending = PendingGateTail(agent, state)
            for name in (*_OUTPUT_CALLBACKS, "quiet_mode", "_safe_print", "_native_output_held"):
                saved[name] = (name in getattr(agent, "__dict__", {}), getattr(agent, name, None))
                setattr(agent, name, True if name in ("quiet_mode", "_native_output_held") else (lambda *a, **kw: None))
        try:
            result = run(state)
        except Exception:  # health: allow BLE001 -- fail-closed runtime boundary; never expose private model or tool error text
            if not required:
                raise
            result = {"final_response": UNAVAILABLE, "messages": [], "completed": False, "failed": True}
            state.deny()
        if required:
            model_completed = result.get("api_calls", 0) > 0 and not result.get("failed")
            result["final_response"] = state.final_output(result.get("final_response", ""), revalidate=True)
            # These fields are rendered after live callbacks have been restored.
            # The authoritative projection contains no unvalidated model prose.
            result.update(last_reasoning=None, pre_transform_response=None, response_reused=False)
            result["response_previewed"] = False
            if state.receipt.get("gate_decision") != "OUTPUT_GATE_PASSED":
                result.update(completed=False, failed=True)
                if "error" in result:
                    result["error"] = UNAVAILABLE
            persistence = pending.commit(result)
            state.receipt.update(contract="hermes.response-receipt/1",
                                 model_status="MODEL_COMPLETED" if model_completed else "UNKNOWN",
                                 human_turn_id=native.turn if native else None,
                                 final_output_digest=digest(result["final_response"]),
                                 output_commit_status="OUTPUT_COMMITTED",
                                 session_persistence_status=persistence,
                                 transport_delivery_status="UNKNOWN")
            result["native_response_receipt"] = {k: v for k, v in state.receipt.items() if k != "output"}
            with _gates_lock:
                while len(_commits) >= 1024:
                    _commits.pop(next(iter(_commits)))
                _commits[id(result)] = (result, result["native_response_receipt"], digest(result["final_response"]))
            notify_committed(state, result["native_response_receipt"])
        return result
    finally:
        state.closed = True
        state.finished = True
        current_turn.reset(token)
        if pending is not None:
            pending.restore()
        for name, (owned, value) in saved.items():
            if owned:
                setattr(agent, name, value)
            else:
                delattr(agent, name)
        # post_llm_call runs inside run(), before this gate's commit. Cleanup
        # belongs after final validation/commit and capability invalidation.
        try:
            from hermes_cli.lifecycle import invoke_hook
            invoke_hook("on_native_turn_end", session_id=session,
                        turn_id=native.turn if native is not None else None)
        except Exception:  # health: allow BLE001 -- cleanup observers cannot replace an already committed answer or leak exception text
            import logging
            logging.getLogger(__name__).warning("Native turn cleanup observer unavailable")


def notify_committed(state, receipt):
    """Bounded observation of a committed projection; never a delivery claim.

    Observers receive a copy, cannot rewrite the committed output, and must
    reconcile an uncertain ACK instead of replaying the request.
    """
    if receipt.get("gate_decision") != "OUTPUT_GATE_PASSED":
        return
    outcomes = {}
    for plugin_id in state.required:
        with _gates_lock:
            entry = _gates.get((hermes_home_key(), plugin_id))
        if entry is None or entry[2] is None:
            continue
        done, accepted = threading.Event(), []
        def observe(callback=entry[2], snapshot=copy.deepcopy(receipt), answer=accepted, signal=done,
                    native_host=entry[0], native_evidence=state.evidence.get(plugin_id)):
            try:
                parameters = inspect.signature(callback).parameters
                if 'commit_use' in parameters:
                    from agent.native_capabilities import commit_capability
                    cap = commit_capability(native_host, native_evidence, state, receipt)
                    answer.append(callback(snapshot, commit_use=cap) is True)
                else:
                    answer.append(callback(snapshot) is True)
            except Exception:  # health: allow BLE001 -- an observer failure keeps its ACK unknown without leaking plugin exception text
                answer.append(False)
            finally:
                signal.set()
        threading.Thread(target=contextvars.copy_context().run, args=(observe,), daemon=True).start()
        outcomes[plugin_id] = "ACKNOWLEDGED" if done.wait(2) and accepted == [True] else "UNKNOWN"
    receipt["commit_observers"] = outcomes


def acknowledge_delivery(result, *, output: str, transport: str, delivery_id: str):
    """Native transport ACK, called only after its successful write/send receipt.

    No model tool calls this API. A lost ACK leaves UNKNOWN; there is no resend.
    TRANSPORT_DELIVERED means transport accepted, not that a Human read it.
    """
    with _gates_lock:
        commit = _commits.get(id(result))
        if (commit is None or commit[0] is not result or commit[1] is not result.get("native_response_receipt")
                or commit[2] != digest(output) or not transport or not delivery_id):
            raise PermissionError("native output commit mismatch")
        commit[1].update(transport_delivery_status="TRANSPORT_DELIVERED", transport=transport,
                         delivery_id=delivery_id)
        return dict(commit[1])


def acknowledge_terminal(result, output):
    """Classic terminal calls only after its final response print succeeds."""
    if result and "native_response_receipt" in result:
        acknowledge_delivery(result, output=output, transport="terminal-stdout",
                             delivery_id=result["native_response_receipt"]["final_output_digest"])
