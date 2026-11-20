# Mission Workbench

Enable the existing bundled Kanban plugin in Desktop, then open **Workbench**
from the sidebar. Projects come from the existing Projects registry. Select a
Board and project to inspect its canonical tasks, creator/decomposition lineage,
runs, worklog, explicit Human decisions and delivery references.
Selecting a project also shows its detected root project facts without requiring
a model call.
The activity view includes original task comments with their recorded authors,
timestamps and task identities. These reported notes remain separate from
verified execution and independent delivery acceptance.

Enter a goal to preview a plan using the configured `kanban_decomposer` auxiliary
model. The model receives the goal, the registered project's name and description,
and root project facts from Hermes's existing detector: manifest names, package
managers, suggested verification commands and instruction file names. The preview
shows this snapshot and its limits. Missing folders or undetected facts remain
unavailable/UNKNOWN. Source and instruction contents are not analyzed, and
verification commands are not executed. Review and edit the result,
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

Workbench does not dispatch execution. This slice provides planning and inspection; it
does not demonstrate Worker-owned engineering delivery or qualify a new execution
environment. Existing runtime controls determine execution eligibility; this view
does not attest that D is installed. D controls and existing STOP_UNCERTAIN records
remain authoritative.
