"""Read-only GitHub delivery evidence pinned to a declared PR and current head."""
from __future__ import annotations

import json
import re
import subprocess
from datetime import UTC, datetime
from typing import Any

from hermes_cli import kanban_pr_acceptance as acceptance

_PR = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/pull/([1-9][0-9]*)")
_SHA = re.compile(r"[0-9a-f]{40}")
_MAX_PAGES = 20


def _object(value):
    if isinstance(value, dict):
        return value
    try:
        value = json.loads(value) if value else None
    except (ValueError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def _identities(task: dict, evidence: list[dict]) -> set[str]:
    """Only explicit identity fields count; prose/branch names never guess a PR."""
    identities = set()
    contract = task.get("completion_contract") or ""
    if _PR.fullmatch(contract):
        identities.add(contract)
    for row in evidence:
        data = _object(row.get("metadata") or row.get("payload"))
        for obj in (data, _object(data.get("acceptance")), _object(data.get("pr_acceptance"))):
            for key in ("published_pr", "pr_url"):
                url = obj.get(key)
                if isinstance(url, str) and _PR.fullmatch(url):
                    match = _PR.fullmatch(url)
                    # Repository contracts constrain historical publication identities.
                    if contract not in {"", "local-only"} and not _PR.fullmatch(contract) and match and match[1] != contract:
                        continue
                    identities.add(url)
    return identities


def _pages(endpoint: str, profile_home: str | None, key: str | None = None) -> list[dict]:
    rows = []
    separator = "&" if "?" in endpoint else "?"
    for page in range(1, _MAX_PAGES + 1):
        data = acceptance._api(f"{endpoint}{separator}per_page=100&page={page}", profile_home=profile_home)
        batch = data[key] if key else data
        if not isinstance(batch, list):
            raise ValueError("malformed GitHub page")
        rows.extend(batch)
        if len(batch) < 100:
            if key and data.get("total_count", len(rows)) != len(rows):
                raise ValueError("incomplete GitHub pages")
            return rows
    raise ValueError("GitHub evidence exceeds bounded pagination")


def _ci(checks: list[dict], statuses: list[dict], sha: str) -> dict:
    entries = []
    for check in checks:
        conclusion = check.get("conclusion")
        state = "pending" if check.get("status") != "completed" else ("success" if conclusion == "success" else "failure")
        if check.get("head_sha") != sha:
            state = "unknown"
        entries.append({"id": check.get("id"), "name": check.get("name"), "state": state, "conclusion": conclusion, "head_sha": check.get("head_sha"), "url": check.get("html_url")})
    latest: dict[str, dict] = {}
    for status in statuses:
        name = status.get("context")
        if not isinstance(name, str):
            raise ValueError("missing GitHub status context")
        if name not in latest or status.get("id", 0) > latest[name].get("id", 0):
            latest[name] = status
    for name, status in latest.items():
        entries.append({"id": status.get("id"), "name": name, "state": status.get("state", "unknown"), "head_sha": sha, "url": status.get("target_url")})
    states = {e["state"] for e in entries}
    state = next((s for s in ("unknown", "failure", "error", "pending") if s in states), "success" if entries and states == {"success"} else "unknown")
    return {"state": state, "checks": entries}


def _reviews(reviews: list[dict], sha: str, author: str | None) -> dict:
    entries: list[dict] = []
    latest: dict[str, dict] = {}
    for review in reviews:
        login = (review.get("user") or {}).get("login")
        independent = bool(login and author and login != author and (review.get("user") or {}).get("type") != "Bot")
        current = review.get("commit_id") == sha
        entry = {"id": review.get("id"), "author": login, "state": review.get("state"), "head_sha": review.get("commit_id"), "independent": independent, "current_head": current, "submitted_at": review.get("submitted_at"), "url": review.get("html_url"), "body": review.get("body")}
        entries.append(entry)
        if login and independent and review.get("state") in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
            if login not in latest or review.get("id", 0) > latest[login]["id"]:
                latest[login] = entry
    current_states = {r["state"] for r in latest.values() if r["current_head"]}
    state = "changes_requested" if "CHANGES_REQUESTED" in current_states else ("approved" if "APPROVED" in current_states else "unknown")
    return {"state": state, "entries": entries}


def _apply_acceptance(result: dict, task: dict, url: str, sha: str) -> None:
    # Reuse the lifecycle owner's exact-head required-check policy, without persisting it.
    receipt = acceptance.collect_acceptance(url, url, assignee=task.get("assignee"))
    result["ci"]["required_policy"] = receipt
    if receipt.get("head_sha") != sha or not receipt.get("ok"):
        classification = receipt.get("classification")
        result["ci"]["state"] = classification if classification in {"failure", "pending"} else "unknown"
        result["unknowns"].append("Canonical required-check acceptance is not satisfied: " + str(receipt.get("detail") or classification or "UNKNOWN"))


def collect_delivery(task: dict, evidence: list[dict]) -> dict:
    result: dict[str, Any] = {"fetched_at": datetime.now(UTC).isoformat(), "url": None, "repo": None, "number": None, "head": None, "base": None, "draft": None, "state": "UNKNOWN", "ci": {"state": "unknown", "checks": []}, "review": {"state": "unknown", "entries": []}, "files": [], "unknowns": [], "waiting_for_human_merge": False}
    identities = _identities(task, evidence)
    if len(identities) != 1:
        result["unknowns"].append("PR identity UNKNOWN: no unique explicit PR URL in canonical task/run/event evidence")
        return result
    url = next(iter(identities))
    match = _PR.fullmatch(url)
    assert match is not None
    repo, number = match[1], int(match[2])
    result.update(url=url, repo=repo, number=number)
    endpoint = f"repos/{repo}/pulls/{number}"
    try:
        profile_home = acceptance._assignee_profile_home(task.get("assignee"))
        pr = acceptance._api(endpoint, profile_home=profile_home)
        sha, base = pr["head"]["sha"], pr["base"]["ref"]
        if not _SHA.fullmatch(sha):
            raise ValueError("missing exact PR head")
        result.update(head=sha, base=base, draft=pr.get("draft"), state="MERGED" if pr.get("merged") else str(pr["state"]).upper())
        checks = _pages(f"repos/{repo}/commits/{sha}/check-runs?filter=latest", profile_home, "check_runs")
        statuses = _pages(f"repos/{repo}/commits/{sha}/statuses", profile_home)
        reviews = _pages(endpoint + "/reviews", profile_home)
        files = _pages(endpoint + "/files", profile_home)
        result["ci"] = _ci(checks, statuses, sha)
        _apply_acceptance(result, task, url, sha)
        # A changed head invalidates the entire fetched evidence snapshot.
        current = acceptance._api(endpoint, profile_home=profile_home)
        if current["head"]["sha"] != sha or current["base"]["ref"] != base or current.get("state") != pr.get("state") or current.get("draft") != pr.get("draft"):
            result["ci"]["state"] = "unknown"
            result["unknowns"].append("PR head/base/state changed while reading; refresh required")
            return result
        if isinstance(pr.get("changed_files"), int) and len(files) != pr["changed_files"]:
            raise ValueError("incomplete changed files")
        result["files"] = [{"path": f["filename"], "additions": f["additions"], "deletions": f["deletions"]} for f in files]
        result["review"] = _reviews(reviews, sha, (pr.get("user") or {}).get("login"))
        if result["ci"]["state"] == "unknown":
            result["unknowns"].append("Current-head CI evidence is missing or incomplete; no checks is UNKNOWN")
        if result["review"]["state"] == "unknown":
            result["unknowns"].append("Independent current-head approval is UNKNOWN; old-head or self reviews do not qualify")
        result["waiting_for_human_merge"] = result["state"] == "OPEN" and result["draft"] is False and result["ci"]["state"] == "success" and result["review"]["state"] == "approved" and not result["unknowns"]
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, IndexError, acceptance._GateAuthError) as exc:
        # Credentials and gh stderr are never returned to the UI.
        result["ci"]["state"] = "unknown"
        result["review"]["state"] = "unknown"
        result["unknowns"].append(f"GitHub evidence unavailable or incomplete ({type(exc).__name__}); refresh after access is restored")
    return result
