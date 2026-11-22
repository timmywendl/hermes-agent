# Q2 serial Guest Worker source candidate

Stacked on accepted Q1 `48c4c94bec337d1fca48876280f9655e4800c961`.
No Q1 files, grants, inert images or historical receipts are changed.

The Guest entry calls the original `managed_worker.run_adopted` AIAgent loop,
with the original RuntimeSessionStore/outbox and canonical Owner receipts. It is
an entry/transport adapter, not another Worker runtime or SessionDB. Delegation
and session rotation remain refused on an exact physical assignment.

## Combined original-Owner qualification package

The integrated Host source uses the accepted plan
`8ed92d2a68d70361021e774d6a3dad6b935cb277`. It preserves the Guest image's
independent source identity, PR16 `9a270a78b421565a64901182062b18a0d3b2e673`,
and imports accepted Builder PR17 `2232de50d163c5a1d630220922642983437ab9ac`
and Host PR18 `13c096f01f4d65726d89e36f9985959f8c6fcb73`. Those original branches,
the Q1 inert image and its Helper/grants remain unchanged.

`gateway.session_guest_hvf` is a finite qualification sibling of the registered
original `SessionAuthority`. It prepares a fresh disposable Board and original
admission, books the exact process identity under the Board writer transaction,
and releases the existing one-shot QEMU gate only after durable readback. It
adds no product dispatch backend. `OwnerSerialSession` alone reads and writes
the framed UART; the process observer handles separate QMP/stdout/stderr only.
Normal finalization requires complete Host process, wait, group, descriptor,
thread and Owner-accounting evidence. Cancellation keeps logical UNKNOWN even
when complete physical cleanup facts can be appended. Neither a manifest nor
a Guest reply can issue a grant or retire physical execution.

The proposed serial three-slot batch is Developer, an independent read-only
Reviewer of the **actual stopped Developer candidate**, and Cancellation. The
reviewed ext4 parser preserves the actual Guest commit and verifies its content;
it does not create an equivalent Host commit. Each slot has fresh identities,
task and assignment devices. Dynamic manifests are bound by the original Owner
before release. The fixed budget is three starts, one concurrent VM, 2 vCPU,
2 GiB RAM, at most 8 GiB disks, 60 seconds startup, 30 seconds stop/cleanup,
300 seconds per slot and 900 seconds total, with no retry, resume or reboot.

The original separately signed Canary evidence remains historical
`PASS_POLICY_EQUIVALENT_CANARY_ONLY`. Main Control rejected an equivalence waiver
and authorized exact-Helper no-VM diagnostics in Issue #139 comment 7076531521.
The old Helper, Canary reports, failed `secinit` records and original seven
Guest artifacts are unchanged.

The rebuilt, signed actual Helper now returns directly through
`--hermes-q2-sandbox-preflight` into the existing `hermes_q2_canary()` before
either gate or normal QEMU initialization. Developer and Reviewer diagnostics
both passed under its own Sandbox and CDHash
`8d24ac08f1d56cbd09d1502bc7dc84573d3a3fc9`.
Executable SHA256:
`678ca15da28d8bd691fa4b00e7daf0c42d060bf46c31b1079b704c7b19e99e14`.
The Helper itself reports its signing identity, entitlements, executable digest,
complete App inventory, role and observed inherited FD identities/access modes.
Unrestricted Calibration runs before and after each role; all denied resources
and network controls returned EPERM, not ENOENT.

The result is `PASS_EXACT_HELPER_SANDBOX_PREFLIGHT`: two actual diagnostic
invocations, zero normal QEMU runtime entries, VM creations, Guest starts or
Worker executions. Independent source/object/disassembly review proves the
early return; precise child wait and closed pipes are retained. Upstream
pre-main constructors register QMP command tables and start an RCU support
thread; they do not enter operational QMP, Hypervisor or Guest execution.
Exact process exit ends these process-owned support threads.
The full new Helper inventory, SBOM/provenance, raw self-reports and wait facts
are preserved under
`/Users/timmywen/Documents/AI_Colleague/evidence/q2-exact-helper-preflight-20261122`.

The prepared Native payload is a request, never authority. It freezes the final
combined source HEAD, original seven device identities, Helper identity,
Sandbox evidence, exact disposable paths, deterministic derivation recipe and
resource budget. A separate protected original-Owner operator action must record
an explicit subsequent Human grant. **Normal QEMU/HVF, Guest Worker, real models,
credentials, Runtime Apply, real project writes and Board dispatch remain
NOT_RUN / NOT_AUTHORIZED in this offline package.** The sections below preserve
the accepted PR16/17/18 contracts; historical source-only phase statements do
not negate the separately recorded construction and no-VM diagnostic evidence.

## Wire and dependencies

QEMU inherits one AF_UNIX socketpair descriptor. Its socket chardev connects to
the Guest's raw UART; there is no NIC, TCP, UDP, vsock or HTTP listener. QMP stays
on separate stdio. Kernel console is tty0; init/runtime stdout and stderr must
be redirected to private Guest logs, never to the protocol UART.

Each direction uses a four-byte big-endian length and strict JSON. Maximum
frame is 4 MiB, no duplicate keys/nonfinite numbers, exact Task/Run/VM/image/policy/
connection generation/Session/Owner epoch/execution binding and monotonic wire
sequence. Channels are context, persistence, inference, lifecycle and activity.
There is one outstanding request; a separate receive pump delivers Stop while a
request is in flight. Request IDs must match; loss, replay or malformed data
revokes authority, preserves UNKNOWN and never resumes. The canonical persistence
sequence/digest receipt is separate from the wire sequence, so committed lost-ACK
writes remain idempotent in the existing outbox. Default I/O budget is 30 seconds
per started header/body/write, with a 2-second receive-thread join budget. A
scoped heartbeat kind on the lifecycle channel carries bounded ping/ack counters
in both directions, independently of business dispatch. Default pulse interval is
5 seconds and the unacknowledged pulse lease is 90 seconds (at most 120); normal
silent work therefore does not spend a 30-second frame deadline. RPC completion
has a separate maximum 300-second budget. Heartbeats neither extend that deadline
nor renew admission, Owner epoch, claim or execution authority. Native APPLY must
pin these budgets and enforce its overall execution deadline independently.

Dependencies are the repository's existing Python runtime, OpenAI SDK and httpx,
Git and Linux tty/block/ext4 support. Reuse the accepted pinned QEMU/HVF build
and Apple Hypervisor contract, with a **separately frozen/signed Q2 package**.
No new Python dependency, daemon, Owner, mission store or network service.

## Separate image recipe and APPLY contract

A Q2 image is not the accepted inert Q1 initramfs. Build in an isolated ARM64
Debian build environment from verified distro packages and the repository lock.
Install the same Hermes package/runtime as the Owner-reviewed HEAD, including
`agent/guest_serial.py`, the two Guest runtime adapters and this private entry.
Root image and assignment block device are read-only. `/run`, Guest scratch directories and the
Guest-only outbox are bounded ephemeral tmpfs. No Host bind mounts or shared
filesystems. Start the Guest entry as an unprivileged UID without capabilities,
with an empty environment except image-local PATH/HOME/runtime paths; HOME is
Guest tmpfs, never Host HOME. Open the UART as a private inherited descriptor,
redirect all normal output to Guest-local bounded logs, then enter Python.
No credentials, provider config, SSH keys/agent, Host profile, Board or SessionDB
are packaged. Package SBOM/provenance must pin the distro, rootfs, initramfs,
kernel, Python wheels, source HEAD, QEMU binary and every device SHA256.

`image_contract.GuestImage` verifies distinct underlying device/inode identities,
single-link regular files, byte digests and a canonical `manifest_json`. The
manifest binds role, directory-snapshot HEAD/mount policy, each drive's path,
digest, device/inode and read-only mode; mismatches are refused before emitting
No-NIC arguments. It does not spawn. `guest_entry` validates a distinct
block-backed `/task`, exact Git HEAD, unprivileged UID and reviewer kernel RO
mount before contacting Owner. Developer and Reviewer have separate object stores
and disks built separately from `prepare_workspace` directory snapshots. The
helper does not create a block image or qualify a mount. Destinations inside the
Host source/common-dir are refused before creation; Git metadata independence is
verified after init and checkout. No linked worktree, shared common-dir,
remote, hooks, credential helper, alternates or Host FETCH_HEAD is copied. Reviewer
is detached at the supplied exact SHA; its entire device must be QEMU read-only
and mounted read-only. Developer receives a private writable task device.

Bootable Q2 image packaging, signing, Sandbox positive/negative controls, Native
Agent execution and physical retirement are **NOT_RUN** in this source-only phase.
The recipe is not an attestation that those gates passed. No Source Ready test
starts Guest Agent/Worker, performs real inference, or reopens Board dispatch.
A future APPLY must bind a new artifact manifest and grant before physical spawn;
Q1's inert grant/helper approval is not transferable to these Guest artifacts.

## Original Owner and physical lifecycle

`reserve_guest_admission` requires the registered original SessionAuthority and
persists immutable assignment bytes with its existing started admission and worker
row in one transaction. Board work projection revalidates the actual claimed Run,
workspace admission and owner-admitted event before exporting secret-free context.
It freezes that exact work projection in existing `state_meta`; a serial endpoint
refuses caller-assembled or damaged work. Reviewer HEAD is supplied explicitly by
the original Owner and frozen in the projection; a moving branch name is refused.
VM identities cannot be reused for another assignment.
OwnerSerialSession is bound to that assignment and retains its channel in the
original Owner's accounting. Slot validation, descriptor duplication and slot
publication share the existing SQLite writer transaction; competing acquisition
threads cannot replace the slot or reset its budget. An uncertain attachment
commit retains exclusion and closes its owned descriptor. Existing Stop routes to it; shutdown cannot report
zero pending work while a channel remains. STOP is attempted before durable
UNKNOWN persistence; stop-requested, stop-sent and UNKNOWN-persisted are distinct.
Shutdown retries unfinished delivery/persistence. Malformed frames/EOF always
shut down and close owned descriptors in a finally path, including revoke-write
failure. Revocation/EOF/result are never physical
retirement. Restart recovery leaves the original worker/admission UNKNOWN and
retains the assignment bytes; old epochs cannot adopt. No source-only API clears
this fence or accepts a Guest retirement receipt. Native acquisition/retirement
must use the original Owner's process-owned HVF proof path after Q2 APPLY; this
candidate intentionally exposes no physical launch grant.

## Historical PR16 D2 proposal

The following section records the PR16 source-ready proposal and its policy
status at that submission. The accepted-policy section below supersedes those
policy-status statements; the default unconfigured endpoint still fails closed.

Approve **one fixed, bounded Responses operation** through the existing original
Owner and Cockpit interface. Owner pins route, account, model, credentials,
method/path, retry/fallback and usage policy; Guest submits only input/instructions,
local function tool schemas, reasoning/text/output limits. No native remote tools,
URL/header/model selector or generic proxy. The SDK HTTP transport is entirely
in-process and serial-backed. A Guest-scoped binding also routes the existing
auxiliary/compression Responses adapters through that channel (including their
async wrapper), bypasses the Host/global client cache and closes scoped SDK
clients on exit; the ordinary auxiliary router is restored outside that scope. Responses events are buffered up to 2 MiB per reply;
no unbounded stream tunnel. Each channel permits at most 32 inference attempts;
logical result-ready closes Host operations while lost-ACK persistence replay
remains idempotent. Transport cleanup joins its service section and closes the
duplicated descriptor, retaining UNKNOWN and Owner accounting. Cancellation revokes the assignment independently of
the inference request; results are rechecked against the current epoch after it.
D2 acceptance must also bind an independent Host request deadline, cancellation
and usage receipt: heartbeat acknowledgments prove transport liveness only, never
model progress, permission renewal, successful execution or physical retirement.

D2 remains **NOT_ACCEPTED**. The Owner endpoint returns `d2_not_accepted` by default;
the callable injection is an offline fixture seam, not a production Cockpit
connector or approval switch. Live Cockpit integration, credentials, streaming
latency/usage and Native inference require the separate D2 qualification. Human's
only policy decision here is acceptance/rejection of this finite D2 operation;
Native APPLY also needs concrete reviewed artifact/grant evidence, not a policy
change to the accepted Owner architecture.

## Offline artifact construction

See [BUILD.md](BUILD.md) for the separate pinned ARM64 Q2 artifact builder,
read-only raw-image verification and remaining Native qualification requirements.
Artifact construction does not qualify boot, Worker execution or D2 inference.

## Accepted D2 policy: offline Host Responses integration

Human accepted `D2_HOST_ONLY_COCKPIT_RESPONSES` on2026-11-21 in
AI Colleague Issue139 comment7063951967. This accepts policy and offline testing,
not live credentials/models, Native Guest/Worker, Runtime Apply or Board dispatch.

`gateway.session_guest_inference.OwnerResponses` attaches only through original
`OwnerSerialSession` Host injection. There is no default HTTP transport, credential
discovery, config switch or public Guest method that enables it. A protected Host
caller supplies the original endpoint, an immutable policy, authentication headers
and an explicit HTTPX transport. Tests use only deterministic Fake Cockpit.

The fixed operation is POST to a numeric loopback `/v1/responses` URL. Redirects,
proxy environment, automatic retries/fallback and Guest route/model/header/cache
selection are excluded. Model, streaming/store mode and output budget are Host
pinned. The original Guest SDK/serial protocol remains unchanged. Host policy
`binding_id` is a declaration to bind to future protected Cockpit qualification;
it is not independent evidence of live account, route, cache or fallback policy.

Bounds:1MiB actual request including Host fields;2MiB raw SSE response;64KiB
individual SSE data event;1024 events;8192 output tokens;32 requests per original
channel and durable execution;120-second total deadline and30-second HTTP idle
timeout at most. A single original Owner helper thread handles each operation.
Heartbeat never extends that deadline or renews authority. There is no second
Owner, inference Router, service, Store or Worker runtime.

Request reservations and outcomes use original SessionDB `state_meta`, bound to
the existing Task/Run/VM/Session/Owner scope, policy digest and request digest.
Neither prompts nor HTTP authorization headers enter these records. Token usage
is recorded only when reported; actual billing remains UNKNOWN, never zero.
`RECEIVED` means the Host received and closed a valid response, not that the Guest
received it or that execution retired. A durable issued-request cursor is created
in the serial attachment writer transaction. Before another operation, exact
keys 1 through issued, immutable Owner/policy
bindings and Owner-held request digests must match; missing, malformed, reset or
unfinished history refuses I/O and revokes the channel. The cursor is never
recreated after attachment, and Owner restart cannot resume this execution.
Original Owner epoch checks run before and after I/O.

Cancellation/deadline closes authorization and suppresses late results. A blocked
HTTP operation remains strongly owned by the original serial slot until its
Future completes and its thread/client/stream can be joined/closed. Cancellation
is checked during response reads; an uninterruptible header/read cannot be proven
physically stopped by a timer. Close refuses unresolved work, still attempts all
known resource cleanup after a close failure, and retains failed resources.
STOP_UNCERTAIN remains even when a late response provides known usage or cleanup
later succeeds. None of this produces a Guest/VM retirement receipt.

Offline tests cover the real SDK→serial→original SQLite Owner→Fake Cockpit path,
fixed policy, request/response bounds, single-attempt errors/redirects, finite
usage receipts, cancellation/late completion, Owner restart, corrupted records,
failed HTTP close and SQLite-failure/serial-FD cleanup. They do not execute a
Worker, contact Cockpit or qualify actual network timeout/abort behavior.

PR17's separately frozen offline image/artifact evidence is unchanged. A future
Native grant must bind the accepted Host integration HEAD and exact Guest source
and artifact identities separately. Live Cockpit account/route/header/retry/cache
policy, credentials, real-model streaming/cancellation/billing and full original
Owner physical retirement require their own explicit operational qualification.

## FD-set access-mode repair (Main Control 7077643727)

The first Native attempt failed before HVF creation: QEMU's initial read-only
open could not select a Developer task FD supplied only as O_RDWR. That failed
grant, raw logs and STOP_UNCERTAIN remain preserved; this repair does not retire
or resume it.

Developer now inherits two independently opened task descriptors of the same
inode and size, O_RDWR and O_RDONLY, both in QEMU FD set 2. There are still three
physical devices. Reviewer task, root and assignment remain read-only. Bootstrap,
preflight and pre-release verification bind the extra descriptor's identity and
access mode; Owner closes all four Developer handles. Auto-read-only remains on.

Offline tests exercise actual kernel FD permissions and the pinned upstream
QEMU FD-set selection functions in an inert driver. They do not initialize QEMU
or prove Guest boot. A newly signed Helper must pass its own two-role no-VM
Sandbox diagnostic before a fresh three-slot request is frozen. Original seven
Guest artifacts are verified without rebuilding. New evidence is under
`/Users/timmywen/Documents/AI_Colleague/evidence/q2-fdset-access-mode-repair-20261122`.
No new Native grant is issued by this repair.

The repaired Helper subsequently passed actual Developer and Reviewer no-VM
Sandbox diagnostics, one invocation per role, after independent binary review.
Helper SHA256: `500af6a2606bf91225dbbe7861448b1b2279d7c28ab90b1b2c054734663b7efe`;
CDHash: `f2934725129058d93c9d33bf96c3fcc8ea715210`.
The Helper observed Developer's task RO handle reject writes with EBADF while
the same-inode RW handle accepted them; Reviewer remained fully read-only.
All six diagnostic/calibration children were exactly waited/reaped and their
pipes closed, with no parent FD accumulation. Execution counts: Helper
preflight 2, normal QEMU initialization 0, VM/Guest/Worker starts 0.
This is PASS_EXACT_HELPER_SANDBOX_PREFLIGHT, not a new Native qualification.
A completely fresh three-slot grant request is prepared in the new evidence
root; Main Control review and a new Human grant remain required before Slot1.
The failed campaign's serial cleanup remains UNKNOWN and is not retired.
