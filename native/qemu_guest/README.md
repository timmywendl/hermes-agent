# Q2 serial Guest Worker source candidate

Stacked on accepted Q1 `48c4c94bec337d1fca48876280f9655e4800c961`.
No Q1 files, grants, inert images or historical receipts are changed.

The Guest entry calls the original `managed_worker.run_adopted` AIAgent loop,
with the original RuntimeSessionStore/outbox and canonical Owner receipts. It is
an entry/transport adapter, not another Worker runtime or SessionDB. Delegation
and session rotation remain refused on an exact physical assignment.

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
per header/body/write, with a 2-second receive-thread join budget. Idle transport
expiry fails closed; this is a finite candidate, not an unlimited idle session.

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

`image_contract.GuestImage` verifies distinct exact artifacts and emits the finite
No-NIC device arguments; it does not spawn. `guest_entry` validates a distinct
block-backed `/task`, exact Git HEAD, unprivileged UID and reviewer kernel RO
mount before contacting Owner. Developer and Reviewer have separate object stores
and disks made from `prepare_workspace`; no linked worktree, shared common-dir,
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
zero pending work while a channel remains. Revocation/EOF/result are never physical
retirement. Restart recovery leaves the original worker/admission UNKNOWN and
retains the assignment bytes; old epochs cannot adopt. No source-only API clears
this fence or accepts a Guest retirement receipt. Native acquisition/retirement
must use the original Owner's process-owned HVF proof path after Q2 APPLY; this
candidate intentionally exposes no physical launch grant.

## Minimal D2 decision requested

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

D2 remains **NOT_ACCEPTED**. The Owner endpoint returns `d2_not_accepted` by default;
the callable injection is an offline fixture seam, not a production Cockpit
connector or approval switch. Live Cockpit integration, credentials, streaming
latency/usage and Native inference require the separate D2 qualification. Human's
only policy decision here is acceptance/rejection of this finite D2 operation;
Native APPLY also needs concrete reviewed artifact/grant evidence, not a policy
change to the accepted Owner architecture.
