"""Keep a selected turn's closing answer unwritten until its final gate decision.

User/tool rows still flush normally. Only the current, not-yet-written answer is
held; existing history and its intrinsic persistence markers are never rewritten.
"""


class PendingGateTail:
    def __init__(self, agent, state):
        self.agent, self.state = agent, state
        self.pending = self.trajectory = None
        self.saved = {}
        self.flush = getattr(agent, "_flush_messages_to_session_db", None)
        self.save_trajectory = getattr(agent, "_save_trajectory", None)
        for name, replacement in (("_flush_messages_to_session_db", self.hold_tail),
                                  ("_save_trajectory", self.hold_trajectory)):
            if callable(getattr(agent, name, None)):
                self.saved[name] = (name in agent.__dict__, getattr(agent, name))
                setattr(agent, name, replacement)

    def hold_tail(self, messages, conversation_history=None):
        if (self.state.closed and messages and messages[-1].get("role") == "assistant"
                and not messages[-1].get("tool_calls")):
            self.pending = (messages, conversation_history)
            return self.flush(messages[:-1], conversation_history)
        return self.flush(messages, conversation_history)

    def hold_trajectory(self, messages, user_query, completed):
        self.trajectory = (messages, user_query)

    def commit(self, result):
        status = "NOT_ATTEMPTED"
        if self.pending is not None:
            messages, history = self.pending
            tail = messages[-1]
            tail["content"] = result["final_response"]
            for name in ("api_content", "reasoning", "reasoning_content", "reasoning_details"):
                tail.pop(name, None)
            result["messages"] = messages
            try:
                persisted = self.flush(messages, history)
            except Exception:  # health: allow BLE001 -- match best-effort transcript persistence without exposing private exception text
                persisted = False
            status = ("NOT_CONFIGURED" if getattr(self.agent, "_session_db", None) is None
                      else "DURABLE" if persisted is True else "UNKNOWN")
        if self.trajectory is not None:
            messages, user_query = self.trajectory
            try:
                self.save_trajectory(messages, user_query, result.get("completed", False))
            except Exception:  # health: allow BLE001 -- optional trajectory export cannot drop a committed denial or expose private data
                import logging
                logging.getLogger(__name__).warning("Native gated trajectory export failed")
        return status

    def restore(self):
        for name, (owned, value) in self.saved.items():
            if owned:
                setattr(self.agent, name, value)
            else:
                delattr(self.agent, name)
