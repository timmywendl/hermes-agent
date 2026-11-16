---
title: "Kanban Created-Origin Retention Contract"
description: "Task-lifetime retention of structural created/decomposed Kanban events"
---

# Kanban created-origin retention contract

**Package:** `HERMES_CREATED_ORIGIN_RETENTION_V1`
**Status:** `DESIGN_ONLY` — Source Ready review pending; no runtime, test, Schema or production change in this PR.
**Base main:** `24099ef7bfb348757fb02f6d11d9196734ebca1e`
**Human decisions:** `DATA_RETENTION = ACCEPTED`; `GRAPH_TEST_SCOPE = OPTION_A_ACCEPTED` (2026-11-16, [decision comment](https://github.com/timmywendl/hermes-agent/pull/5#issuecomment-6910451008)).
**Audience:** Kanban maintainers, reviewers, and the implementer of the future authorized native package.
**Runtime APPLY:** not authorized. **Human APPLY:** not granted.

This contract exists because AI Colleague K1 needs a durable, non-blocking
Mission → Work Item relation. The existing native
`created.payload.creator_task_id` is queryable today but is deleted by ordinary
age-based GC for completed/archived Tasks. Retaining the structural `created`
event alongside the already-retained `decomposed` event is the smallest native
change that removes that loss without adding a Task field, table, Schema
migration, Store, Dispatcher or dependency edge.

## 1. Problem and current behavior

`create_task()` commits one `created` task event inside the Task creation
transaction (`hermes_cli/kanban_db.py:1176`, event at `:1304`). Its payload
records the origin and creation-time metadata:

```
assignee, status, parents, creator_task_id, tenant, workspace_kind,
workspace_path, branch_name, project_id, skills, goal_mode,
model_override, provider_override
```

`creator_task_id` is copied by `inherit_creator_origin()` inside the same
transaction (`hermes_cli/kanban_db_graph.py:8`; called at
`hermes_cli/kanban_db.py:1343`). It inherits session/subscription origin and
adds **no** `task_links` row when `parents=()`.

`gc_events()` currently deletes every event older than the cutoff for
`done`/`archived` Tasks except `decomposed`
(`hermes_cli/kanban_db.py:4032`):

```sql
DELETE FROM task_events
 WHERE created_at < ?
   AND kind != 'decomposed'
   AND task_id IN (SELECT id FROM tasks WHERE status IN ('done','archived'))
```

The Task and Run rows survive this sweep; only the event rows are deleted. A
completed/archived Work Item's `created` event — the only durable record of its
`creator_task_id` — can therefore disappear while the Task still exists. After
that, Mission → Work Item lineage is UNKNOWN, not empty.

`decomposed` is not a substitute for `created.creator_task_id`. It is written by
a different writer contract (`decompose_triage_task`), creates dependency
links into the Root, changes the Root's status/assignee, and records fan-out
graph identity rather than passive creator origin. Do not fabricate it or invoke
decomposition to retain an inert Root.

## 2. Production call chain and all GC callers

`gc_events()` has one production caller:

| Caller | Path | Role |
| --- | --- | --- |
| `_cmd_gc()` | `hermes_cli/kanban_ops.py:305` | `hermes kanban gc`; also `/kanban gc` through `hermes_cli/kanban.py:1339` |
| `gc_events()` | `hermes_cli/kanban_db.py:4032` | only implementation of event retention |
| eval | `evals/kanban_graph_identity.py:55` | non-production graph identity probe |
| tests | `tests/hermes_cli/test_kanban_graph_identity.py:28`, `tests/hermes_cli/test_kanban_gc_retention.py` | regression coverage |

No cron, dispatcher, daemon, gateway or dashboard path calls `gc_events()` in
the pinned tree. A future/new caller that still uses the old predicate is an
old-GC caller for the purposes of §7.

Zero and negative semantics are existing protections and must not change:

- Library: `gc_events(older_than_seconds=0)` builds a cutoff of "now" and
  performs the sweep for eligible rows; it does not mean "disabled".
- CLI: `--event-retention-days 0` is mapped to "skip this sweep" by
  `_cmd_gc` (`if event_days:` at `hermes_cli/kanban_ops.py:347`).
- Negative: rejected by `_retention_seconds()` (`hermes_cli/kanban_db.py:4016`)
  and by the parser type (`hermes_cli/kanban_parser.py:438`); `_cmd_gc` returns
  exit 2 before any sweep.

## 3. Reproduction on current main (disposable board only)

Observed on a disposable `HERMES_HOME`/board using the pinned source. No
production DB, Worker, model, network or real service was used.

Fixture: create a Root, create a Work Item with
`creator_task_id=Root, parents=()`, claim and complete it (one Run), then age
all of its events. Separately decompose a triage Root and age its events.

| Observation | Current main |
| --- | --- |
| Work Item events before GC | `created=1, claimed=1, completed=1` |
| Work Item Run rows before/after GC | `1 / 1` |
| `task_links` touching Work Item | `0` |
| After `gc_events(older_than_seconds=1)` | Work Item events `{}`; Task row `1`; Run row `1`; `created=0` |
| Decomposed Root after GC | `decomposed=1` retained; `created=0` deleted |
| `gc_events(older_than_seconds=0)` on an aged `done` fixture | `created` deleted |
| `_cmd_gc(event_days=0)` | exit 0; `created` retained (sweep disabled) |
| `_cmd_gc(event_days=-1)` | exit 2; `created` retained |
| `gc_events(-1)` | `ValueError: older_than_seconds must be >= 0` |

This is the red state for the retention tests in §8. It is a component-level
reproduction, not a production observation.

## 4. Proposed change

One predicate change in `gc_events()` plus its docstring:

```sql
DELETE FROM task_events
 WHERE created_at < ?
   AND kind NOT IN ('created', 'decomposed')
   AND task_id IN (SELECT id FROM tasks WHERE status IN ('done','archived'))
```

Resulting behavior:

- `created` is retained for the lifetime of its owning Task, independent of
  payload JSON, creator existence or payload validity.
- `decomposed` retains its existing Task-lifetime behavior.
- Ordinary events (claimed, completed, commented, heartbeat, blocked, etc.)
  continue to expire under the existing age window.
- Task, Run, link, claim, dispatcher and dependency behavior are unchanged.
- No DDL, index, `user_version`, backfill, data copy or new event kind.

The predicate must remain kind-based, not payload-based. Making retention depend
on JSON1 parsing or on a non-null `creator_task_id` would reintroduce malformed-
payload and legacy dependence, and would not preserve ordinary `created`
records.

## 5. Retention impact — Human decision accepted

This change extends the lifetime of the **full existing `created` payload** from
the ordinary age window to the owning Task's lifetime. It is not just
`creator_task_id`: the retained row includes the creation-time metadata listed
in §1 (assignee, workspace kind/path, branch, project, tenant, skills, model and
provider overrides, goal mode).

**Human decision (2026-11-16):** ACCEPTED. The Human explicitly accepts
Task-lifetime retention of the full existing `created` payload until explicit
deletion of its owning Task. See the [decision
comment](https://github.com/timmywendl/hermes-agent/pull/5#issuecomment-6910451008).

- Growth is **one structural row per Task**, plus pre-existing `decomposed`
  rows and pre-existing anomalous duplicates. It is not retention of the whole
  event stream.
- The retained values are the values already written today; this change does not
  add fields or collect new data.
- Workspace paths and tenant/model/provider metadata may be operationally
  sensitive. Task-lifetime retention of that payload is now an accepted Human
  data-retention decision, not an automatic consequence of this contract.
- The implementation must not claim that already-collected history is restored.
  Only future GC behavior changes.

## 6. Explicit deletion and dangling origin

`delete_task()` and `delete_archived_task()` call `_delete_task_relations()`
(`hermes_cli/kanban_db.py:3855`), which deletes that Task's `task_events`,
`task_runs`, `task_links`, `task_comments` and notify subscriptions. Explicit
deletion therefore removes the retained `created` and `decomposed` rows with the
Task; the guarantee ends at intentional deletion.

- Work Item explicit deletion ends that Work Item's lineage. Do not recreate the
  child, fabricate a Run or tombstone, or infer history from surviving rows.
- Root explicit deletion leaves surviving children whose
  `created.payload.creator_task_id` points to an absent Task. That is a dangling
  reference. It must be reported UNKNOWN/orphan and never rebound to another
  Root or treated as recovered continuity.
- Same-key deduplication/recovery across hard deletion is not guaranteed. A
  later creation with the same key is a new identity (`CREATED`), not a
  `RECOVERED` one.
- Archive, unlike deletion, preserves the Task row and is the supported way to
  retain continuity.

## 7. Legacy history, mixed-version and downgrade

- Events already deleted by an older GC cannot be reconstructed from surviving
  Task/Run rows. No title, body, Session, subscription or dependency heuristic
  may be used to backfill or guess them.
- A board with surviving Tasks that lack a retained `created` event has UNKNOWN
  lineage coverage. That is not evidence of no Work Items and not a reason to
  fail unrelated fresh facts.
- A mixed/new writer is not enough: **any old GC caller** for the selected board
  can still delete `created`. Qualify a board only when every GC caller that can
  run against it uses the accepted policy.
- A downgrade remains Schema-readable, but an old binary's GC can resume
  deleting `created`. The durability guarantee is invalid while an old GC can
  run. Stop dependent continuity qualification before downgrade/rollback,
  preserve the board and evidence, and require explicit reconciliation.
- Reverting the source is not proof of safe durable rollback.

## 8. Red → green test contract

All tests are behavior tests on disposable `HERMES_HOME` boards. They must use
`scripts/run_tests.sh`, must not write `~/.hermes/`, and must not read source
text. Current-main status is the expected red/green baseline; no test result is
claimed as already green.

New coverage in `tests/hermes_cli/test_kanban_creator_origin.py`:

| Test | Current main | After fix |
| --- | --- | --- |
| `test_created_origin_survives_done_gc` | RED (`created` deleted) | GREEN: same Root ID and full payload keys |
| `test_created_origin_survives_archived_gc` | RED | GREEN |
| `test_created_origin_survives_repeated_gc` | RED | GREEN: repeated sweeps leave `created`/Task/Run unchanged |
| `test_created_origin_survives_zero_window` | RED | GREEN: library `0` still sweeps ordinary events, retains `created` |
| `test_ordinary_events_expire_while_created_remains` | RED | GREEN: ordinary event count falls to 0; `created` remains 1 |
| `test_task_and_run_rows_unchanged_by_gc` | new; expected PASS | PASS unchanged |
| `test_explicit_work_item_delete_removes_created` | new; expected PASS | PASS unchanged |
| `test_root_delete_leaves_dangling_creator_id` | new; expected PASS | PASS unchanged; no rebinding |
| `test_creator_origin_survives_without_dependency_parent` (existing) | PASS (existing) | PASS unchanged |

Adjustments in `tests/hermes_cli/test_kanban_gc_retention.py`:

- The positive-window case in `test_cmd_gc_retention_bounds` currently asserts
  `(_event_rows(conn, tid) > 0) is expect_kept` with `expect_kept=False`
  (`tests/hermes_cli/test_kanban_gc_retention.py:89`), i.e. all events for the
  fixture disappear. After the fix, `created` remains. Add one ordinary event to
  the aged fixture (e.g. `kb.add_comment`) and split the assertion into: ordinary
  event count `0`, `created` count `1`, Task/Run rows unchanged. Keep the
  existing workspace/log ordering assertions.
- Negative-window, library-zero, CLI-zero, slash-command, workspaces-root and
  shared-scratch tests must remain green without weakening their protections.

### Accepted Option A fixture in `tests/hermes_cli/test_kanban_graph_identity.py`

Human accepted Option A on 2026-11-16. The existing disposable Root fixture
gains one ordinary event before the existing backdate/GC block, using the
existing public API:

```python
kb.add_comment(conn, root, "probe", "ordinary history")
```

Call it between the existing link assertions and the existing
`with kb.write_txn(conn)` block, before `task_events.created_at=0`. It is an
existing public API already used in tests
(`tests/hermes_cli/test_kanban_db.py:691`), opens its own write transaction and
requires only an existing task and non-empty author/body. It writes exactly one
`commented` event; do not call it inside the existing `write_txn` and do not wrap
`gc_events` in a transaction.

The existing `assert kb.gc_events(conn, older_than_seconds=1) > 0` remains. The
test additionally asserts:

- the `commented` event is collected (ordinary history);
- `created == 1` and `decomposed == 1` after GC;
- a repeated GC returns `0` and leaves those structural counts unchanged;
- the existing re-triage → `decompose_triage_task(...) is None`, task-id set and
  `PRAGMA integrity_check` protections remain.

| Test | Current main (with the ordinary event) | After fix |
| --- | --- | --- |
| `test_completed_decomposition_survives_retriage` | RED: `created == 1` fails because GC deletes it | GREEN: `commented` collected; `created`/`decomposed` 1; repeated GC 0 and stable; retry protection intact |

`task_comments` rows are not deleted by `gc_events`; the assertion is about the
event record, not the comment row. `task_runs` is empty in this fixture, so the
Task/Run snapshot is explicitly asserted as unchanged (0 runs). The
non-production `evals/kanban_graph_identity.py` ignores the `gc_events` return
value; after the change its sweep is a no-op for the structural-only fixture. It
needs no adjustment and is not a fifth file. This adds one existing test file,
not a new file. See the [Human decision
comment](https://github.com/timmywendl/hermes-agent/pull/5#issuecomment-6910451008).

## 9. Implementation whitelist (future Human APPLY only)

Exactly four existing files, no new runtime module or test file:

1. `hermes_cli/kanban_db.py` — only the `gc_events` predicate and docstring.
2. `tests/hermes_cli/test_kanban_gc_retention.py` — ordinary-vs-structural
   assertions; repeat GC; library zero; CLI zero; negative; Task/Run unchanged.
3. `tests/hermes_cli/test_kanban_creator_origin.py` — creator origin across
   done/archive/repeated GC/zero; explicit Work Item delete; dangling Root;
   no dependency edge; no history guessing.
4. `tests/hermes_cli/test_kanban_graph_identity.py` — accepted Option A
   ordinary-event fixture; ordinary-event collection; `created`/`decomposed`
   survival; repeated GC; existing decomposition retry protection.

No Schema, DDL, index, `user_version`, migration, new Store, new event kind,
dispatcher, cron or dashboard change is proposed.

User-facing `website/docs/user-guide/features/kanban.md` currently documents
`decomposed` retention. Updating it to describe retained `created` origin is a
separately authorized docs change after APPLY, not part of the four-file native
implementation whitelist.

## 10. Rollback boundary

- Revert the predicate/docstring and the three test-file changes, including the
  accepted graph-identity ordinary-event fixture; no data migration or backfill
  is involved.
- Rows retained during the change remain until normal explicit deletion; a
  revert does not delete them and must not claim to.
- After revert, an old GC resumes deleting `created`; stop claiming durable
  continuity and re-qualify any dependent AI Colleague work.
- Preserve board, evidence and native rows; do not "repair" history by deleting
  surviving structural rows.

## 11. Verification commands for the future implementation

```bash
scripts/run_tests.sh tests/hermes_cli/test_kanban_gc_retention.py
scripts/run_tests.sh tests/hermes_cli/test_kanban_creator_origin.py
scripts/run_tests.sh tests/hermes_cli/test_kanban_graph_identity.py
scripts/run_tests.sh tests/hermes_cli/ -k kanban
python scripts/check
```

No real model, Worker dispatch, production DB, data migration or production
installation is part of Source Ready or the future APPLY without separate
authorization.

## 12. Human decisions and exit criteria

Human decisions recorded on 2026-11-16 ([PR #5 comment
6910451008](https://github.com/timmywendl/hermes-agent/pull/5#issuecomment-6910451008)):

1. `DATA_RETENTION = ACCEPTED` — retain the full existing `created` event
   payload until explicit deletion of its owning Task (§5).
2. `GRAPH_TEST_SCOPE = OPTION_A_ACCEPTED` — one ordinary event in the existing
   graph-identity fixture; keep the ordinary-GC assertion; verify `created` and
   `decomposed` survive; expand the whitelist to four existing files (§8, §9).

Remaining before any native APPLY:

3. Codex independent exact-HEAD review of this contract.
4. Main Control re-review.
5. Separate explicit Human APPLY. This document and PR #5 remain `DESIGN_ONLY`;
   no runtime or test change is authorized now.

`SOURCE_READY` remains `PENDING_MAIN_CONTROL_REVIEW`. This document does not
authorize code, tests, Schema, production, AI Colleague #140, Hermes #4, K3 or
Desktop UI.
