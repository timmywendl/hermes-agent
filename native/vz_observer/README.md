# PR14 hard exit: independent VZ resource attribution not established

Status: **BLOCKED / NOT_QUALIFIED**, not a Host containment implementation.
This is the executable evidence for the hard exit in Main Control's
[PR14 authorization](https://github.com/spareribes/ai-colleague/issues/139#issuecomment-7058318377).
It leaves PR13's nine-path candidate and the preserved Q2 candidate unchanged.

## What was established

- **SOURCE_VERIFIED:** the installed Endpoint Security SDK exposes fork, exec,
  exit, open, close, dup, fcntl and XPC-connect notifications. `es_message_t`
  has per-event and global sequence counters for detecting delivered-stream gaps.
  No ES client was created; event delivery, loss detection and completeness are
  **NOT_RUN**, not inferred from compilation.
- **OFFICIAL_DOCUMENTATION / SOURCE_VERIFIED:** the
  [XPC-connect payload](https://developer.apple.com/documentation/endpointsecurity/es_event_xpc_connect_t)
  identifies service name/domain, with originating-process context in the enclosing
  ES message. It is not an independent per-VM delegated-resource inventory or
  release receipt. No corresponding VM-scoped rights-release interface was
  established in the inspected ES/libproc/Virtualization SDK surfaces.
- **SOURCE_VERIFIED (live OS canary):** `rights_visibility_probe.c` allocates one
  ordinary Mach receive right and send reference in its own inert process.
  `mach_port_get_refs` verifies a live send reference. Both
  `PROC_PIDLISTFDS` **and** `PROC_PIDLISTFILEPORTS` remain identical to the
  baseline. It releases its own rights and checks the snapshots again.
  A real pipe positive control additionally increases the measured FD inventory
  by two entries. This uses kernel APIs, not mocks, an ES replay or a fabricated VM.
- **DESIGN_INFERENCE:** identical file/fileport snapshots cannot distinguish that
  live non-file-backed Mach right from its absence. Snapshot completeness cannot
  therefore be promoted into complete delegated-right retirement evidence.
  The canary is **not** proof that a VZ service leaks that particular right.
- **OFFICIAL_DOCUMENTATION:**
  [VZVirtualMachineDelegate](https://developer.apple.com/documentation/virtualization/vzvirtualmachinedelegate)
  supplies callbacks about its associated VM. These do not provide the independent
  observer required by this package. Per-VM disk/share/listener/writer/delegate
  attribution and release remain **UNKNOWN**. This is not a claim that every
  possible Apple/private/vendor interface has been disproved.

## Reproduce without VM, ES activation or permissions

On macOS with Xcode's SDK installed:

```sh
xcrun clang -std=c17 -fblocks -Wall -Wextra -Werror \
  native/vz_observer/rights_visibility_probe.c -o /tmp/rights-visibility
/tmp/rights-visibility
scripts/run_tests.sh tests/native/test_vz_observer_visibility.py
```

The canary exits nonzero on failed/incomplete measurement. A successful canary
reports one live Mach send reference with unchanged file snapshots and
`per_vm_vz_release=UNKNOWN`. It reports only its own process, creates no ES
client, never loads a VM, and is not wired into a retirement authority.
It does not inspect another process's memory, credentials or user files.

## Why installation is not the next request

An actual ES client requires Apple's restricted
[`com.apple.developer.endpoint-security.client` entitlement and TCC Full Disk Access](https://developer.apple.com/documentation/endpointsecurity/es_new_client(_:_:)).
Apple's [system-extension sample](https://developer.apple.com/documentation/endpointsecurity/monitoring-system-events-with-endpoint-security)
also requires signing/provisioning and user installation/activation.
These have not been requested or performed. Enabling them would permit collection
of the documented ES events; it would not itself establish the missing VM-scoped
resource relationship. No entitlement file or inactive extension target is offered
as a substitute for that relationship.

## Single required provider/architecture decision

Identify a supported independent evidence provider/API and its exact authority
that can associate the immutable VM attempt with **all** delegated VZ resources
(including framework-service-side rights, disk/share writers and listeners), and
provide verifiable release/completeness evidence independent of the Adapter.
If no such provider exists within this architecture, Main Control must adjudicate
that unmet guarantee before authorizing another architecture or trust boundary.
No weaker retirement contract is proposed here.

Following the explicit hard exit, no further XPC service, ES extension, Desktop
packaging, Gateway integration or alternative backend was added. Original-Owner
XPC connectivity, kernel sandbox denial/positive controls, Virtualization-in-sandbox
eligibility, live ES sequence handling and native qualification are **NOT_RUN**.
This package neither proves nor disproves direct Owner XPC connectivity.
STOP_UNCERTAIN and no-successor remain unchanged; the native grant is unused.
