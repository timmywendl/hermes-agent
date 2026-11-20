# Mission Workbench

Enable the existing bundled Kanban plugin in Desktop, then open **Workbench**
from the sidebar. Projects come from the existing Projects registry. Select a
Board and project to inspect its canonical tasks, creator/decomposition lineage,
runs, worklog, explicit Human decisions and delivery references.

Enter a goal to preview a plan using the configured `kanban_decomposer` auxiliary
model. The model receives the goal and the registered project's name and
description; it does not inspect repository files. Review and edit the result,
then explicitly confirm it. Confirmation atomically saves a Root Mission and its
work items in Hermes Kanban as **blocked and unassigned**. Retrying a lost response
uses the same request identity. It does not start workers or authorize execution.
An unavailable model produces an unavailable state, not a substitute plan.

The inbox distinguishes explicit decision requests from ordinary progress events.
Recording an answer appends to the original task's history; it does not unblock
the task. Existing decisions and responses remain inspectable.

Delivery evidence requires an explicit PR identity in canonical task/run/event
records. The view reads GitHub checks, required-check policy, independent reviews
and changed files at the current PR HEAD. Missing access, missing required policy,
moving HEADs and absent evidence stay UNKNOWN. A recorded run outcome is reported
evidence, not proof of physical execution ownership or independent acceptance.

Board execution remains paused. This slice provides planning and inspection; it
does not demonstrate Worker-owned engineering delivery or qualify a new execution
environment. D controls and existing STOP_UNCERTAIN records remain authoritative.
