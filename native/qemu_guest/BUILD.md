# Q2 offline Guest artifact package

This package constructs images. It never starts QEMU, boots a Guest, runs an
Agent/Worker, contacts Cockpit or a model, publishes artifacts, or dispatches a
Board task. Generated QEMU arguments are data for review, **not a launch command**.
No production signing key is used.

The application source is exactly accepted PR16
`9a270a78b421565a64901182062b18a0d3b2e673`. Construction helpers are a separate
stacked change. The original managed Worker, serial protocol and
RuntimeSessionStore are reused. No Owner, runtime, store or network service is
added. A one-shot Linux PID1 mounts the finite device set, drops capabilities,
groups and UID/GID, executes the original Guest entry once, waits and powers off.
It has no task admission, persistence, restart or scheduling function.

## Frozen inputs

`artifact-inputs.lock.json` contains exact versions, URLs, sizes and SHA256:

- The authenticated Debian13.7 ARM64 package index retained by Q1, plus its exact
  Release/signature hashes and the SHA256 of the already completed Q1 signature
  verification receipt. No floating Debian index is queried by the builder.
- The same vendor kernel package as Q1, with exact kernel/module payload hashes.
  The new initramfs contains only virtio block and ext4 dependencies, no vsock or
  network driver. The PCI and PL011 drivers are built into this exact kernel.
- CPython3.14.7+20260901 Linux ARM64 from the accepted `pm/lock.json`.
- The Linux ARM64 core wheel closure selected from accepted `uv.lock`, including
  transitive extras and target markers. No source distribution is executed.
- Pinned existing macOS ARM64 Zig0.15.2 and mke2fs1.47.2 binaries. Their hashes
  are checked before execution. Reproducibility is for this frozen toolchain;
  other Host toolchains have not been qualified.

Debian archives are unpacked without running maintainer scripts. Wheels are
unpacked without installation hooks; startup `.pth` injection is rejected.
Only tracked runtime files from the accepted Git commit enter `/opt/hermes`.
There is no Host checkout `.git`, profile, environment file or database copy.
Absence of `.git` also retains Hermes' existing packaged-interpreter bootstrap
contract instead of invoking source-update completion.

Q1's inert initramfs/root disk are not inputs and are not modified. The vendor
kernel is independently extracted from its locked Debian package.

## Build environment

Use an external directory, an isolated Python3.14 build-tool environment and a
case-sensitive staging filesystem. All operations are unprivileged file
construction. On macOS a dedicated case-sensitive APFS sparse image may hold the
staging trees; this Host build volume is distinct from the ext4 Guest artifacts.
The Guest disks are never mounted.

```sh
Q2_ROOT=/absolute/external/evidence
Q2_ENV=/absolute/external/build-tool-environment
uv venv --python /absolute/pinned/host/python3.14 "$Q2_ENV"
uv pip install --python "$Q2_ENV/bin/python" --only-binary=:all: \
  --require-hashes -r native/qemu_guest/build-tools.lock.txt
```

`dissect.extfs` is a pinned external read-only verification tool (AGPL-3.0-or-later).
It and the test runner are not installed in the Guest or added to Hermes runtime
dependencies. The Guest software and build tools retain their upstream license
notices; SPDX `NOASSERTION` fields are not a completed distribution license audit.

Populate `$Q2_ROOT/downloads` using only the committed input lock and
`build_inputs.fetch`; cached bytes are rehashed. A lock regeneration is a new
reviewed input decision. It requires the frozen Q1 signed index and receipt,
not an unpinned current mirror index.

```sh
"$Q2_ENV/bin/python" - "$Q2_ROOT/downloads" <<'PY'
from pathlib import Path
import json, sys
from native.qemu_guest.build_inputs import fetch
lock = json.loads(Path("native/qemu_guest/artifact-inputs.lock.json").read_text())
for item in lock["inputs"]:
    fetch(item, Path(sys.argv[1]))
PY
```

```sh
"$Q2_ENV/bin/python" -m native.qemu_guest.build_artifacts \
  --source /absolute/this/checkout \
  --downloads "$Q2_ROOT/downloads" \
  --output /absolute/case-sensitive-volume/build-A \
  --zig /absolute/pinned/zig \
  --mke2fs /absolute/pinned/mke2fs
```

Repeat in a new independent `build-B` directory. No directory is overwritten.
The compiler uses separate private caches and strips debug paths. `SOURCE_DATE_EPOCH`
is fixed at1795268786; tar/newc metadata, ext4 UUID/hash seed and inode
ownership/timestamps are deterministic. Task Git indexes are rebuilt without Host
stat caches and reflogs. Compare all seven artifact byte digests, not pathname,
inode, provenance invocation paths or other per-copy identity facts.

## Actual output devices

| Artifact | Role/policy |
| --- | --- |
| `kernel.Image` | Frozen Debian ARM64 kernel |
| `initramfs.cpio.gz` | Static one-shot init + five vendor modules |
| `root.raw` | 1GiB ext4; shared only read-only; accepted source and complete dependencies |
| `developer-task.raw` | Independent64MiB ext4, writable; UID/GID1000 |
| `reviewer-task.raw` | Independent64MiB ext4, read-only QEMU device and kernel mount |
| `developer-assignment.raw` | Independent16MiB ext4; read-only |
| `reviewer-assignment.raw` | Independent16MiB ext4; read-only |

Task devices contain a deterministic, private Git fixture, **not the real project**.
Assignment devices contain closed PR16 work data with `OFFLINE_BUILD_ONLY`
identities and `D2_NOT_ACCEPTED`. These do not correspond to any real Owner
reservation, Mission Run or execution grant. A future authorized attempt must
mint and review the exact real assignment/device digest through the original
Owner; it cannot reuse this fixture as admission authority.

The manifest's workspace `directory_snapshot` field retains PR16's source-policy
meaning. Actual ext4 device sizes, UUIDs, labels and file content are separately
verified from the resulting disk bytes.

Linux setup has no Host mounts or NIC configuration. Root and assignment are
mounted read-only. Reviewer task is read-only at both device and mount layers.
The child has UID/GID1000, empty supplementary groups, dropped capability
bounding set, `no_new_privs`, core limit0,64 processes and128 FDs.
<!-- no-tmp: ok — fixed Linux Guest mountpoints, never Host scratch paths -->
Tmpfs bounds: `/run`128MiB, `/tmp`64MiB, Guest HOME64MiB, outbox32MiB,
logs16MiB; individual file size is capped at16MiB.

These are **statically inspected policies**, not observed Linux enforcement.

## Freeze and verify

Use `artifact_inventory.verify_tree` to produce `root-content-inventory.json`,
then `artifact_inventory.emit` with the clean builder's exact Git HEAD. Emission
uses PR16 `image_contract.GuestImage` for both role manifests and device argument
generation. Copying to a final location requires regenerating identity bindings:
inode identity is intentionally local to the exact artifact copy.

The result includes canonical package/role manifests, `SHA256SUMS`, SPDX2.3 SBOM,
in-toto/SLSA provenance, exact dependency lock and image/build facts. Metadata
hashes are bound by the canonical package manifest. Every artifact and metadata
file must be a single-link regular file; links, changed bytes/identity and
role/device/policy mismatches fail closed.

```sh
"$Q2_ENV/bin/python" -m native.qemu_guest.artifact_inventory \
  /absolute/frozen/package --root-tree /absolute/case-sensitive-volume/build-A/root-tree
"$Q2_ENV/bin/python" -m native.qemu_guest.verify_images /absolute/frozen/package
```

Before emission, copy the seven raw artifacts and `build-facts.json` to that new
local package directory. The emission command requires a clean builder checkout
and records its exact HEAD. Keep the original construction outputs and failed
attempt logs. Do not upload the package or create a release.

This reads actual ext4 inodes/files, verifies complete root content against the
assembly inventory, checks UID/modes, ELF architecture/shared-library inventory,
private Git structure, assignment roles/HEAD and filesystem UUID/label/size.
It never mounts disks or executes target code.

GnuTLS contains seven public upstream cryptographic self-test private-key
vectors. `public-selftest-vectors.json` records their exact hashes, the exact
vendor library hash and public source reconciliation. Only those exact published
vectors in that exact library are recognized; unknown/SSH private keys remain
rejected. They are not Host/provider authentication credentials.

Run tests via `scripts/run_tests.sh` in the isolated test environment with the
pinned read-only verifier available. The dedicated artifact tests exercise real
ext4 construction/parsing, plus deterministic input/manifest/link/role/secret
controls. They do not run an ARM64 binary or imply boot qualification.

## Remaining qualification

Boot, Guest Worker, model calls, Cockpit, Runtime Apply and Board dispatch remain
NOT_RUN / NOT_AUTHORIZED. Source/static success and a bootable image layout are
not evidence that this Guest boots or executes correctly.

Next authorization must bind the accepted builder/source HEAD, exact final
artifact/role/assignment digests, permitted Task directory and a fresh original
Owner identity/reservation. The Q1 inert grant is spent and cannot transfer.
Review the Q2-specific Host Sandbox permissions and positive/negative controls;
then obtain a new finite Native grant before any QEMU process.
Verify real UID/capability/tmpfs/read-only enforcement, serial handshake,
cancellation, exact Owner wait, descendant/group/FD closure and durable
UNKNOWN/recovery/retirement. D2 policy and any live credentials/model operation
remain separate Human decisions. No automatic Worker dispatch restoration.

## Local candidate receipt

Two independently staged builds produced identical bytes for all seven artifacts.
This table identifies the offline candidate; these binary files are not committed
or published. Manifest inode bindings are regenerated for each final local copy.

| Artifact | Bytes | SHA256 |
| --- | ---: | --- |
| `kernel.Image` | 37660608 | `9c37ace54ef7e1919411fd912e9f34d6982ddd7f4c8ef3c8aee56f4c4d70db67` |
| `initramfs.cpio.gz` | 571100 | `16d87dcb36ed79e3b40fd69b60b0b7bda0e0ecda20851583e881c586e17dd97e` |
| `root.raw` | 1073741824 | `c814b1f8a7077b97464a0824e001c2260a3f9cc6ed42fe3c491088f8991aa01e` |
| `developer-task.raw` | 67108864 | `9449234a0f9188f501a862829590e0cbcc6803b8ba1ac7821e69ae582da74c35` |
| `reviewer-task.raw` | 67108864 | `7632388362c3ab35b3134857647a837e5baac774fc38715b28f26a68f24480cc` |
| `developer-assignment.raw` | 16777216 | `8e94f012a3eaea00d5dd790335a644304b84bcab26ca4b259141cd3776202237` |
| `reviewer-assignment.raw` | 16777216 | `86241a7a2aba6fde557fb60c387657a42319fa53c01d491df31facc710948de4` |

Offline verification on macOS ARM64: 877 passed, 15 platform skips across96 files;
48 dedicated artifact cases passed, including real ext4 construction and parsing.
20 directed behavior mutations were detected. Scoped Ruff and Mypy passed;
Code Health reported0 blocking/advisory findings. Full `scripts/check` retains
four unchanged Ruff findings in accepted Q1/Q2 tests; its other11 checks pass.
SPDX output passes the official SPDX2.3.1 JSON schema. A read-only parser checked
16,561 root-file records and604 ARM64 ELF records, actual task Git HEADs, inode
ownership, device metadata and role assignments.

These counts are construction/integrity evidence, not runtime qualification.
No target binary, Guest, Worker or model was executed. D2 remains NOT_ACCEPTED
and FIRST_WORKER_OWNED_DELIVERY remains NOT_ACHIEVED.
