"""Canonical read projections: lineage and decisions never infer lifecycle state."""
from __future__ import annotations

import json
from typing import Any

LIMITS = {"tasks": 2000, "task_runs": 10000, "task_events": 20000, "task_comments": 10000}


def parse_object(value: Any) -> dict | None:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return None
    try:
        parsed = json.loads(value)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _rows(conn, table: str, unknowns: list[str]) -> list[dict]:
    limit = LIMITS[table]
    rows = [dict(r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY {'created_at, id' if table == 'tasks' else 'id'} LIMIT ?", (limit + 1,))]
    if len(rows) > limit:
        unknowns.append(f"{table} read truncated at {limit}; older-to-newer order, later records unavailable")
    return rows[:limit]


def _creator_edges(events: list[dict]) -> tuple[dict[str, set[str]], set[str]]:
    creators: dict[str, set[str]] = {}
    roots = set()
    for event in events:
        payload = event.get("payload") or {}
        creator = payload.get("creator_task_id")
        if event["kind"] == "created" and isinstance(creator, str) and creator:
            creators.setdefault(event["task_id"], set()).add(creator)
        if event["kind"] == "decomposed" and isinstance(payload.get("child_ids"), list):
            roots.add(event["task_id"])
            for child in payload["child_ids"]:
                if isinstance(child, str):
                    creators.setdefault(child, set()).add(event["task_id"])
    return creators, roots


def _root(task_id: str, creators: dict[str, set[str]], roots: set[str], ids: set[str]) -> str | None:
    current, seen = task_id, set()
    while current in creators and current not in seen and len(creators[current]) == 1:
        seen.add(current)
        current = next(iter(creators[current]))
    return current if current in roots and current not in seen and current in ids and current not in creators else None


def _lineage(tasks: list[dict], events: list[dict], unknowns: list[str]) -> None:
    ids = {t["id"] for t in tasks}
    creators, roots = _creator_edges(events)
    roots.update(parent for parents in creators.values() for parent in parents if parent in ids and parent not in creators)
    for task in tasks:
        root = _root(task["id"], creators, roots, ids)
        task["root_id"] = root
        task["relationship_state"] = ("ROOT" if root == task["id"] else "WORK_ITEM") if root else "UNKNOWN"
    if any(t["relationship_state"] == "UNKNOWN" for t in tasks):
        unknowns.append("Some tasks have no unambiguous canonical creator/decomposition origin; dependencies do not establish Mission membership")


def _history(record: dict, body: str, author: str | None = None) -> dict:
    return {"body": body, "created_at": record.get("created_at"), "author": author or record.get("author"), "id": record.get("id")}


def _decision_response(comment: dict) -> dict:
    response = (parse_object(comment.get("body")) or {}).get("workbench_decision_response")
    return response if isinstance(response, dict) and isinstance(response.get("decision_id"), str) else {}


def _input_decisions(tasks: list[dict], events: list[dict], comments: list[dict]) -> dict:
    decisions = {}
    answered = {_decision_response(c).get("decision_id") for c in comments}
    for task in tasks:
        active = task.get("status") == "blocked" and task.get("block_kind") == "needs_input"
        requests = [e for e in events if e["task_id"] == task["id"] and e["kind"] == "blocked" and isinstance((e.get("payload") or {}).get("reason"), str)]
        for request in requests:
            key = f"blocked:{request['id']}"
            current = active and request is requests[-1]
            if request["payload"].get("kind") != "needs_input" and not current and key not in answered:
                continue
            reason = request["payload"]["reason"]
            decisions[key] = {"id": key, "task_id": task["id"], "title": task["title"], "reason": reason, "recommendation": None, "status": "pending" if current else "superseded", "history": [_history(request, reason)]}
        if active and not requests:
            key = f"task:{task['id']}"
            decisions[key] = {"id": key, "task_id": task["id"], "title": task["title"], "reason": "Human input requested; reason UNKNOWN", "recommendation": None, "status": "pending", "history": []}
    return decisions


def _explicit_decision(record: dict, source: str) -> dict | None:
    data = (record.get("payload") if source == "event" else parse_object(record.get("body"))) or {}
    explicit = data.get("workbench_decision")
    if source == "event" and record["kind"] in {"decision_requested", "human_decision_required"}:
        explicit = data
    if not isinstance(explicit, dict) or not isinstance(explicit.get("reason"), str):
        return None
    key = f"{source}:{record['id']}"
    return {"id": key, "task_id": record["task_id"], "title": explicit.get("title") or "Human decision", "reason": explicit["reason"], "recommendation": explicit.get("recommendation"), "status": "pending", "history": [_history(record, explicit["reason"], explicit.get("actor"))]}


def _decisions(tasks: list[dict], events: list[dict], comments: list[dict]) -> list[dict]:
    decisions = _input_decisions(tasks, events, comments)
    for source, records in (("event", events), ("comment", comments)):
        for record in records:
            decision = _explicit_decision(record, source)
            if decision:
                decisions[decision["id"]] = decision
    for comment in comments:
        response = _decision_response(comment)
        decision = decisions.get(response.get("decision_id"))
        if decision and decision["task_id"] == comment["task_id"]:
            decision["history"].append(_history(comment, str(response.get("response") or "")))
            decision["status"] = "responded"
    return list(decisions.values())


def snapshot(conn) -> dict:
    unknowns: list[str] = []
    tasks = _rows(conn, "tasks", unknowns)
    runs = _rows(conn, "task_runs", unknowns)
    events = _rows(conn, "task_events", unknowns)
    comments = _rows(conn, "task_comments", unknowns)
    for event in events:
        event["payload_raw"] = event.get("payload")
        event["payload"] = parse_object(event.get("payload"))
        if event["payload_raw"] and event["payload"] is None:
            unknowns.append(f"Event {event['id']} payload is malformed; raw evidence preserved")
    for run in runs:
        run["metadata_raw"] = run.get("metadata")
        run["metadata"] = parse_object(run.get("metadata"))
        run["custody_state"] = "UNKNOWN"
        if run["metadata_raw"] and run["metadata"] is None:
            unknowns.append(f"Run {run['id']} metadata is malformed; raw evidence preserved")
    if runs:
        unknowns.append("Run custody is UNKNOWN: historical run records are displayed without asserting live process ownership")
    _lineage(tasks, events, unknowns)
    return {"tasks": tasks, "runs": runs, "activity": events, "decisions": _decisions(tasks, events, comments), "unknowns": unknowns}
