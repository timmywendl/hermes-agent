"""Persist acceptance with the same ownership snapshot as the terminal write."""
from __future__ import annotations

from hermes_cli.kanban_db_connect import write_txn
from hermes_cli.kanban_pr_acceptance import _PR, collect_acceptance


def _snapshot(conn, task_id):
    row = conn.execute("SELECT current_run_id, status, completion_contract FROM tasks WHERE id=?", (task_id,)).fetchone()
    return tuple(row) if row else None


def prepare_acceptance(conn, task_id, expected_run_id, metadata, expected_claim_lock=None):
    snapshot = _snapshot(conn, task_id)
    if snapshot is None:
        return False
    run_id, status, contract = snapshot
    enabled = wave2_enabled(conn, task_id)
    if not contract or contract == "local-only":
        return False if enabled else None
    if status not in {"running", "ready", "blocked", "review"} or (expected_run_id is not None and run_id != expected_run_id):
        return False
    published_pr = metadata.get("published_pr") if isinstance(metadata, dict) else None
    if enabled:
        proof = _wave2_review_snapshot(conn, task_id, expected_run_id, metadata, expected_claim_lock)
        if proof is None:
            return False
        receipt = collect_acceptance(contract, published_pr, assignee=proof["reviewer"])
        if receipt.get("head_sha") != proof["head"] or receipt.get("base_ref") != proof["base"]:
            receipt.update(ok=False, classification="stale", detail="PR differs from reviewed candidate")
        return (snapshot, proof), receipt
    match = _PR.fullmatch(published_pr) if isinstance(published_pr, str) else None
    # Publication binds once. Retrying cannot replace the task's PR with a green sibling.
    if match and contract == match[1]:
        with write_txn(conn):
            if _snapshot(conn, task_id) != snapshot:
                return False
            conn.execute("UPDATE tasks SET completion_contract=? WHERE id=?", (published_pr, task_id))
        snapshot = (run_id, status, published_pr)
        contract = published_pr
    # The assignee profile's gh login owns the repo: acceptance must not run as
    # the ambient login of whichever process completes the card (#122689).
    assignee = conn.execute("SELECT assignee FROM tasks WHERE id=?", (task_id,)).fetchone()["assignee"]
    return snapshot, collect_acceptance(contract, published_pr, assignee=assignee)


def record_acceptance(conn, task_id, acceptance):
    """Called under complete_task's write_txn, before its terminal UPDATE."""
    from hermes_cli.kanban_db import _append_event
    snapshot, receipt = acceptance
    proof = None
    if isinstance(snapshot[0], tuple):
        snapshot, proof = snapshot
        if _wave2_review_snapshot(conn, task_id, snapshot[0], proof["metadata"], proof["claim"]) != proof:
            return False
    if _snapshot(conn, task_id) != snapshot:
        return False
    _append_event(conn, task_id, "pr_acceptance", receipt, run_id=snapshot[0])
    if proof and receipt["ok"]:
        _append_event(conn, task_id, "wave2_verdict", {
            "reviewer": proof["reviewer"], "head": proof["head"], "base": proof["base"],
            "handoff_id": proof["handoff_id"], "owner_id": proof["owner_id"],
            "published_pr": proof["metadata"]["published_pr"], "acceptance": receipt,
        }, run_id=snapshot[0])
    if not receipt["ok"]:
        detail = f"PR acceptance {receipt['classification']}: {receipt.get('detail', '')} {receipt['recovery']}"
        conn.execute("UPDATE tasks SET last_failure_error=? WHERE id=?", (detail, task_id))
    return receipt["ok"]


def wave2_enabled(conn, task_id):
    """Creation evidence selects Wave 2; damaged Stage 3 provenance fails closed."""
    import json
    task = conn.execute('SELECT created_by,completion_contract FROM tasks WHERE id=?', (task_id,)).fetchone()
    if not task:
        return False
    row = conn.execute("SELECT payload FROM task_events WHERE task_id=? AND kind='created' ORDER BY id LIMIT 1", (task_id,)).fetchone()
    try:
        payload = json.loads(row[0]) if row else None
    except (ValueError, TypeError):
        payload = None
    if isinstance(payload, dict) and payload.get('publication_protocol') == 'wave2_v1':
        return True
    return task[0] == 'ai-colleague-stage3'


def _wave2_event(conn, task_id, kind, run_id=None):
    import json
    sql = 'SELECT id,payload FROM task_events WHERE task_id=? AND kind=?'
    args = (task_id, kind)
    if run_id is not None:
        sql += ' AND run_id=?'
        args += (run_id,)
    row = conn.execute(sql + ' ORDER BY id DESC LIMIT 1', args).fetchone()
    if not row:
        return None
    try:
        payload = json.loads(row[1])
    except (TypeError, ValueError):
        return None
    return (row[0], payload) if isinstance(payload, dict) else None


def _wave2_run(conn, task_id, run_id):
    import time
    if type(run_id) is not int:
        return None
    row = conn.execute('SELECT t.status,t.current_run_id,t.claim_lock,t.claim_expires,t.assignee,r.profile,r.claim_lock '
                       'FROM tasks t JOIN task_runs r ON r.id=t.current_run_id AND r.task_id=t.id WHERE t.id=?', (task_id,)).fetchone()
    if not row or row[0] != 'running' or row[1] != run_id or not row[2] or row[2] != row[6]:
        return None
    from hermes_cli.kanban_db import _to_epoch
    try:
        expires = _to_epoch(row[3])
    except (ValueError, OverflowError, TypeError):
        return None
    if expires is None or expires <= time.time():
        return None
    return row


def record_publication_intent(conn, task_id, *, run_id, claim_lock, repo, base, branch, head, attempt=False):
    """Persist a cooperative intent, or spend the one automatic create attempt.

    An attempt receipt is not retryable: loss of its response requires remote reconciliation.
    This does not prevent uncooperative shell/gh usage under the same UID.
    """
    import re
    from hermes_cli.kanban_db import _append_event
    from hermes_cli.kanban_pr_acceptance import _REPO
    if not (isinstance(repo, str) and _REPO.fullmatch(repo) and
            isinstance(head, str) and re.fullmatch(r'[0-9a-f]{40}', head) and
            all(isinstance(v, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,199}', v)
                and '..' not in v and not v.endswith(('/', '.')) for v in (base, branch))):
        return False
    with write_txn(conn):
        row = _wave2_run(conn, task_id, run_id)
        task = conn.execute('SELECT completion_contract,branch_name FROM tasks WHERE id=?', (task_id,)).fetchone()
        if not row or row[2] != claim_lock or not task or not wave2_enabled(conn, task_id):
            return False
        created = _wave2_event(conn, task_id, 'created')
        match = _PR.fullmatch(task[0] or '')
        if (not created or created[1].get('completion_contract') != repo or
                (match[1] if match else task[0]) != repo or (task[1] and task[1] != branch)):
            return False
        intent = {'repo': repo, 'base': base, 'branch': branch, 'head': head, 'implementer': row[5]}
        prior = _wave2_event(conn, task_id, 'wave2_publication_intent', run_id)
        exists = conn.execute("SELECT 1 FROM task_events WHERE task_id=? AND run_id=? AND kind='wave2_publication_intent'", (task_id, run_id)).fetchone()
        if (exists and not prior) or (prior and prior[1] != intent):
            return False
        if not prior:
            _append_event(conn, task_id, 'wave2_publication_intent', intent, run_id=run_id)
        if attempt:
            if conn.execute("SELECT 1 FROM task_events WHERE task_id=? AND kind='wave2_publication_attempt'", (task_id,)).fetchone() or match:
                return False
            _append_event(conn, task_id, 'wave2_publication_attempt', intent, run_id=run_id)
        return True


def prepare_wave2_handoff(conn, task_id, run_id, metadata, reviewer, expected_claim_lock=None):
    """Read remote PR identity before acquiring the writer lock."""
    if not wave2_enabled(conn, task_id):
        return None
    from hermes_cli.kanban_db import _canonical_assignee
    reviewer = _canonical_assignee(reviewer or prior_reviewer(conn, task_id) or None)
    row = _wave2_run(conn, task_id, run_id)
    intent = _wave2_event(conn, task_id, 'wave2_publication_intent', run_id)
    attempt = _wave2_event(conn, task_id, 'wave2_publication_attempt')
    if (not row or not expected_claim_lock or row[2] != expected_claim_lock or not intent or not attempt
            or not reviewer or reviewer == row[5] or not isinstance(metadata, dict)):
        return False
    if any(attempt[1].get(k) != intent[1].get(k) for k in ('repo', 'base', 'branch')):
        return False
    url = metadata.get('published_pr')
    match = _PR.fullmatch(url) if isinstance(url, str) else None
    data = intent[1]
    if not match or match[1] != data.get('repo') or metadata.get('head_sha') != data.get('head'):
        return False
    previous = _wave2_event(conn, task_id, 'wave2_handoff')
    has_previous = conn.execute("SELECT 1 FROM task_events WHERE task_id=? AND kind='wave2_handoff'", (task_id,)).fetchone()
    if (has_previous and not previous) or (previous and previous[1].get('url') != url):
        return False
    attempt_run = conn.execute('SELECT run_id FROM task_events WHERE id=? AND task_id=?', (attempt[0], task_id)).fetchone()
    if attempt_run is None:
        return False
    if previous is None:
        # The first observed PR must come from the exact reserved attempt, not
        # a later Run or a different commit on the same branch.
        if attempt_run[0] != run_id or attempt[1] != data:
            return False
    elif not _valid_first_handoff(conn, task_id, attempt):
        return False
    from hermes_cli.kanban_pr_acceptance import verify_publication
    if not verify_publication(url, data, assignee=row[4]):
        return False
    return {'url': url, 'head': data['head'], 'base': data['base'], 'branch': data['branch'],
            'implementer': row[5], 'reviewer': reviewer, 'run_id': run_id,
            'claim_lock': expected_claim_lock, 'intent_id': intent[0], 'attempt_id': attempt[0],
            'previous_handoff_id': previous[0] if previous else None}


def _valid_first_handoff(conn, task_id, attempt):
    """Only an already bound original attempt may authorize later revisions."""
    import json
    row = conn.execute("SELECT run_id,payload FROM task_events WHERE task_id=? AND kind='wave2_handoff' ORDER BY id LIMIT 1", (task_id,)).fetchone()
    attempt_row = conn.execute('SELECT run_id FROM task_events WHERE task_id=? AND id=?', (task_id, attempt[0])).fetchone()
    if row is None or attempt_row is None or row[0] != attempt_row[0]:
        return False
    try:
        value = json.loads(row[1])
    except (TypeError, ValueError):
        return False
    if not isinstance(value, dict):
        return False
    intent = _wave2_event(conn, task_id, 'wave2_publication_intent', row[0])
    url = value.get('url')
    match = _PR.fullmatch(url) if isinstance(url, str) else None
    return bool(match and match[1] == attempt[1].get('repo') and intent
                and value.get('run_id') == row[0] and value.get('intent_id') == intent[0]
                and value.get('attempt_id') == attempt[0] and value.get('previous_handoff_id') is None
                and intent[1] == attempt[1] and value.get('head') == attempt[1].get('head')
                and all(value.get(k) == attempt[1].get(k) for k in ('base', 'branch')))


def validate_wave2_handoff(conn, task_id, handoff):
    """Revalidate the pre-read against the exact still-current writer transaction."""
    row = _wave2_run(conn, task_id, handoff['run_id'])
    intent = _wave2_event(conn, task_id, 'wave2_publication_intent', handoff['run_id'])
    attempt = _wave2_event(conn, task_id, 'wave2_publication_attempt')
    previous = _wave2_event(conn, task_id, 'wave2_handoff')
    has_previous = conn.execute("SELECT 1 FROM task_events WHERE task_id=? AND kind='wave2_handoff'", (task_id,)).fetchone()
    if (not row or row[2] != handoff['claim_lock'] or not intent or intent[0] != handoff['intent_id']
            or not attempt or attempt[0] != handoff['attempt_id'] or (has_previous and not previous)
            or (previous[0] if previous else None) != handoff['previous_handoff_id']
            or (previous and (previous[1].get('url') != handoff['url'] or not _valid_first_handoff(conn, task_id, attempt)))):
        return False
    match = _PR.fullmatch(handoff['url'])
    if (not match or intent[1].get('repo') != match[1] or intent[1].get('implementer') != row[5]
            or any(intent[1].get(k) != handoff[k] for k in ('base', 'branch', 'head'))):
        return False
    if previous is None:
        attempt_run = conn.execute('SELECT run_id FROM task_events WHERE id=? AND task_id=?', (attempt[0], task_id)).fetchone()
        if not attempt_run or attempt_run[0] != handoff['run_id'] or attempt[1] != intent[1]:
            return False
    return True


def _wave2_owner_binding(conn, task_id, run_id, admitted, owner):
    """Validate the native Owner marker against this Board/Task/Run."""
    import json
    import math
    from pathlib import Path
    from hermes_cli import kanban_db as kb
    try:
        for kind in ('owner_admitted', 'owner_admission_bound'):
            count = conn.execute('SELECT count(*) FROM task_events WHERE task_id=? AND run_id=? AND kind=?',
                                 (task_id, run_id, kind)).fetchone()[0]
            if count != 1:
                return False
        marker, binding = admitted[1], owner[1]
        request = marker['request_id']
        identity = json.loads(request.removeprefix('kanban:'))
        if (not request.startswith('kanban:') or not isinstance(identity, list) or len(identity) != 3
                or identity[1:] != [task_id, run_id] or type(identity[2]) is not int
                or kb._require_slug(identity[0]) != identity[0]
                or request != 'kanban:' + json.dumps(identity, separators=(',', ':'))):
            return False
        board_file = conn.execute('PRAGMA database_list').fetchone()[2]
        if not board_file or Path(board_file).resolve() != kb.kanban_db_path(board=identity[0]).resolve():
            return False
        if (not isinstance(marker.get('db'), str) or not Path(marker['db']).is_absolute()
                or type(marker.get('pid')) is not int or marker['pid'] <= 0
                or type(marker.get('birth')) not in (int, float) or not math.isfinite(marker['birth'])
                or marker['birth'] <= 0):
            return False
        return (isinstance(binding.get('admission_id'), str) and bool(binding['admission_id'])
                and isinstance(binding.get('session_id'), str) and bool(binding['session_id'])
                and all(binding.get(k) == marker.get(k) for k in ('session_id', 'request_id')))
    except (AttributeError, KeyError, OSError, TypeError, ValueError):
        return False


def wave2_review_claim(conn, task_id, run_id, expected_claim_lock=None):
    """Resolve the native review Run and original Owner binding, never caller identity."""
    row = _wave2_run(conn, task_id, run_id)
    claimed = _wave2_event(conn, task_id, 'claimed', run_id)
    owner = _wave2_event(conn, task_id, 'owner_admission_bound', run_id)
    admitted = _wave2_event(conn, task_id, 'owner_admitted', run_id)
    handoff = _wave2_event(conn, task_id, 'wave2_handoff')
    if (not row or not expected_claim_lock or row[2] != expected_claim_lock or not claimed
            or claimed[1].get('source_status') != 'review' or not owner or not admitted or not handoff):
        return None
    value = handoff[1]
    if (not row[5] or row[4] != row[5] or row[5] != value.get('reviewer') or
            row[5] == value.get('implementer') or not _wave2_owner_binding(conn, task_id, run_id, admitted, owner)):
        return None
    return row, claimed, owner, admitted, handoff


def _wave2_review_snapshot(conn, task_id, run_id, metadata, expected_claim_lock=None):
    state = wave2_review_claim(conn, task_id, run_id, expected_claim_lock)
    if state is None or not isinstance(metadata, dict):
        return None
    row, claimed, owner, admitted, handoff = state
    value = handoff[1]
    if (metadata.get('review_verdict') != 'approved' or metadata.get('published_pr') != value.get('url')
            or metadata.get('head_sha') != value.get('head')):
        return None
    return {'claim': row[2], 'reviewer': row[5], 'head': value['head'], 'base': value['base'],
            'handoff_id': handoff[0], 'claimed_id': claimed[0], 'owner_id': owner[0],
            'admitted_id': admitted[0], 'metadata': metadata}


def prior_reviewer(conn, task_id):
    """Return the latest reviewer or False when requested-change provenance is malformed."""
    row = conn.execute("SELECT id FROM task_runs WHERE task_id=? AND outcome='changes_requested' ORDER BY id DESC LIMIT 1", (task_id,)).fetchone()
    if row is None:
        return None
    event = _wave2_event(conn, task_id, 'changes_requested', row[0])
    reviewer = event[1].get('reviewer') if event else None
    return reviewer if isinstance(reviewer, str) and reviewer.strip() else False


def wave2_review_refusal(conn, task_id, run_id, expected_claim_lock=None):
    if not wave2_enabled(conn, task_id):
        return None
    if wave2_review_claim(conn, task_id, run_id, expected_claim_lock) is None:
        return 'review Run or Owner provenance is missing'
    count = conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='changes_requested'", (task_id,)).fetchone()[0]
    if count >= 3:
        return 'review repair limit reached; preserve evidence and request a decision'
    return None


def event_gc_sql():
    """Preserve admission and delivery evidence only for selected Wave 2 tasks."""
    return (
        "DELETE FROM task_events WHERE created_at < ? AND kind NOT IN ('created', 'decomposed', 'workspace_bound') "
        "AND task_id IN (SELECT id FROM tasks WHERE status IN ('done', 'archived')) "
        "AND (kind NOT IN ('owner_admitted', 'owner_admission_bound', 'wave2_publication_intent', 'wave2_publication_attempt', 'wave2_handoff', 'wave2_verdict') "
        "OR task_id NOT IN (SELECT id FROM tasks WHERE created_by='ai-colleague-stage3' UNION "
        "SELECT task_id FROM task_events WHERE kind='created' AND CASE WHEN json_valid(payload) "
        "THEN json_extract(payload, '$.publication_protocol')='wave2_v1' ELSE 0 END))"
    )
