# Q1 process-owned HVF feasibility candidate

This is a finite, inert diagnostic invoked explicitly by the registered original
`SessionAuthority`. It is not a Worker backend and never enables Board dispatch.
Grant: [Main Control 7058818518](https://github.com/spareribes/ai-colleague/issues/139#issuecomment-7058818518).

The fixed campaign is three orderly shutdowns, SIGKILL, then SIGABRT, serially.
Every reserved attempt spends a slot before physical creation. There is no resume,
restore, retry or successor after UNKNOWN. The original Owner persists exact
Task/Run/Claim digest, Owner epoch/instance, source/build identity and child
identity using existing Board metadata plus SessionDB `state_meta`; no schema.
The child disables core dumps and waits for an Owner release frame before any
Hypervisor calls. PID booking and both ledgers are read back before release.

## Reproduce without consuming Native authorization

Use an external evidence directory. Never run the QEMU binary for a version/help
probe: every QEMU process counts against the finite Native grant.

1. Obtain QEMU **11.1.3** from `https://download.qemu.org/qemu-11.1.3.tar.xz`,
   SHA256 `5a8289c7940dc77d3873c81a6c29ba3afe1446fc9d36e77fa1658cdbecb84b22`.
   Verify its detached release signature against independently obtained key
   `CEACC9E15534EBABB82D3FA03353C9CEF108B584`. A digest alone is not publisher approval.
2. Extract to a new external source directory. Reject absolute symlinks; exclude
   only unused edk2 `EmulatorPkg/Unix/Host/X11IncludeHack -> /opt/X11/include`.
   Supply DTC at signed `subprojects/dtc.wrap` revision
   `b6910bec11614980a21e46fbccc35934b671bd81`. No floating dependency checkout.
3. Build tools: Ninja 1.13.0 (archive SHA256
   `f08641d00099a9e40d44ec0146f841c472ae58b7e6dd517bee3945cfd923cedf`),
   pkgconf 2.5.1 (`cd05c9589b9f86ecf044c10a2269822bc9eb001eced2582cfffd658b0a50c243`),
   QEMU-vendored Meson 1.11.1; supplemental wheel 0.45.1
   (`708e7481cc80179af0e556bbf0cc00b8444c7321e2700b8d8580231d13017248`).
   Use an external QEMU build environment, never mutate a Hermes environment.
   `PKG_CONFIG` points to pkgconf; `PKG_CONFIG_PATH` supplies installed GLib,
   pcre2 and gettext pkgconfig directories. The native receipt records toolchain
   and resolved dependencies, not a claim of toolchain-independent binary identity.
4. `build_candidate.py --archive ... --source ... --output NEW_DIR --python ...
   --ninja ... --zig ...` applies the versioned patch, compiles admission/canaries,
   builds HVF-only/TCG-disabled ARM64 QEMU and a static serial-only initramfs.
   Zig 0.15.2 is the previously qualified external compiler. Reuse the frozen
   Debian kernel and read-only raw disk; do not rebuild a distribution.
5. `package_candidate.py --binary ... --kernel ... --initramfs ... --disk ...
   --fixture ... --output NEW_DIR` copies dependencies into the App, rewrites
   install names, signs with exactly App Sandbox + Hypervisor entitlements,
   and writes hashes. It never executes QEMU. Public fixture only:
   SHA256 `87a34479ff2f4f9fd8c6c982a9e461f637a7bd9b88e82b03f3e765a58bf77582`.
   `qualify_sandbox.run_controls` verifies unrestricted/sandboxed/unrestricted
   controls using this explicit public Apple test keychain, never default Keychain.

`qemu-candidate.patch` is essential: vanilla 11.1.3 does **not** call
`hv_vm_destroy`. The patch joins actual vCPU threads through QEMU's existing
cleanup, unregisters the memory listener and records the real API result. Normal
qualification requires successful API result, expected Guest shutdown event,
exact Owner wait, empty process group, pipe closure and Owner accounting.
Abnormal qualification never claims an explicit destroy call. It relies on the
[Apple process/VM and thread/vCPU mapping](https://developer.apple.com/documentation/hypervisor)
plus exact kernel child wait and group/pipe observations. This is a selected
platform trust boundary; it is not an independent kernel VM enumeration API.
Any missing evidence remains UNKNOWN.

## Native entry: only after offline gates and exact-HEAD review

Use cleared environment, isolated HOME/HERMES_HOME and a dedicated new
`hvf-qualification` profile. `python -m gateway.session_hvf_adapter --prepare-home
ABS_PATH` invokes canonical GatewayRunner + original runtime initialization with
no adapters/API/Agent started. Freeze the candidate manifest against a clean
reviewed source commit. Then the sole Native entry is the same module's
`--manifest ABS_PATH`; never call Popen from a separate test driver.

Manifest fields: package/grant plus `candidate` containing absolute profile,
board, helper, plan, kernel, initramfs, disk, output, exact source_head and the
complete signed App file SHA256 inventory. Output is a new directory beside the
profile. The initial command is diagnostic-only; it creates no Worker admissions.

## Licenses and distribution

QEMU is GPL-2.0 with component-specific exceptions; see the pinned archive's
`COPYING`, `COPYING.LIB`, `LICENSE` and individual source notices. Preserve the
complete matching source archive, DTC revision, local patch, configure/link/build
scripts and third-party sources/notices when distributing a candidate binary.
Bundled GLib/gettext components have LGPL obligations and pcre2 its own notices;
retain matching source and permit replacement/relinking as applicable. The
Debian kernel requires its corresponding source/notices. The public Apple test
fixture comes from APSL Security test sources. New inert init is MIT. No third-party
binary is committed here; packaging a release requires a complete license review,
source delivery and notices, not merely an SPDX inventory.

The evidence receipt must distinguish SOURCE_VERIFIED, OFFICIAL_DOCUMENTATION,
DESIGN_INFERENCE, UNKNOWN and NOT_RUN. Passing this package qualifies only the
exact inert build/host lifecycle. Stage 3 and Worker dispatch remain unqualified.

## First Native campaign: stopped; qualification NOT_PASS

Exact executed source: `39a1443d35460d25fdecfd38cc799cdee284ce53`.
Frozen helper SHA256:
`ecfc393fb8e1dc93303befc7bd17a7fe016ba4269dc6aa3be7f1828ed1c95696`.
Only slot 1 ran. Its real Sandbox controls, `hv_vm_create`, Guest READY, two
vCPUs, 2 GiB RAM, no network and the read-only 128 MiB disk were observed.
Normal stop timed out after 30 seconds: upstream `ringbuf-write` appends to the
output ring rather than delivering Guest serial input. No Guest shutdown event
or successful `hv_vm_destroy` marker was captured. The campaign immediately
latched STOP_UNCERTAIN; slots 2–5 were not started. Absence of the child later
is not retirement evidence. The failure path did not persist the child's exact
wait status, so that status is UNKNOWN, not an inferred successful shutdown.

The subsequent source correction uses upstream's connected socket chardev over
an explicitly inherited unnamed AF_UNIX socketpair. This is a local serial
capability, with no pathname listener, NIC, netdev, TCP/UDP or network entitlement.
Both endpoints belong to the original Owner/its exact child; the parent closes
its child endpoint immediately after Popen, drains serial alongside QMP/stderr,
and includes the serial descriptor in physical completion. A real signed inert
Sandbox canary verifies duplex inherited-FD I/O without a VM.

This correction is **OFFLINE_TESTED / NATIVE_NOT_RUN**. The executed candidate,
failed Board/Owner records and grant remain unchanged. The spent grant cannot
be resumed or reused. No result in this PR qualifies normal or abnormal VM
retirement, resource nonaccumulation, Stage 3 or Worker dispatch. Main Control
must adjudicate any future bounded campaign; no authorization is inferred from
unused later slots.

## New grant PR15_HVF_RERUN_20261121_A

[Main Control 7060302726](https://github.com/spareribes/ai-colleague/issues/139#issuecomment-7060302726)
authorizes a fresh five-lifecycle campaign after offline gates and read-only
reconciliation of the exact old child/group. It does not resume the old grant.
`rerun-authorization.json` fixes the one new Profile/Board/output, immutable App
inventory and prior-history digest in reviewed source. A manifest cannot rebind
the grant to another profile or artifact inventory. Source HEAD is independently
frozen in the external manifest, avoiding a self-referential source hash.

Exit evidence now captures PID/birth/fingerprint/executable, actual Owner wait
return and signal, group census and every stdin/stdout/stderr/serial endpoint.
Both existing ledgers and a fsynced diagnostic receipt are attempted independently;
an unavailable sink is explicit UNKNOWN, never a retirement grant. Normal exits
persist physical facts while STOP_UNCERTAIN before final Owner accounting. Failed
or timed-out attempts persist facts while remaining STOP_UNCERTAIN. No old exit
status or retirement evidence is synthesized.

Duplex serial uses the inherited unnamed socket. QMP stdin remains live through
terminal SHUTDOWN delivery; closing it at serial STOP could lose the monitor event.
Normal retirement requires matching wait/identity/group/pipe/drain observations,
actual successful hv_vm_destroy and Owner accounting. Each succeeding slot starts
only after the prior one retires. Any failed slot ends the entire new campaign.
The new Native result will be recorded separately from the unchanged first failure.
Worker dispatch remains unauthorized regardless of this diagnostic result.
