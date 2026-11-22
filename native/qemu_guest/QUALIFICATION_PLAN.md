# Q2 原 Owner Native Qualification：完整冻结施工计划 V1

~~~text
PACKAGE = HERMES_Q2_ORIGINAL_OWNER_NATIVE_QUALIFICATION_V1
DATE = 2026-11-22 Asia/Shanghai
PLAN_STATUS = SUBMITTED_FOR_MAIN_CONTROL_REVIEW
CURRENT_AUTHORIZATION = PLAN_ONLY
NATIVE_GRANT = NOT_AUTHORIZED
NATIVE / GUEST / QEMU / BUILD / SIGN / RUNTIME_APPLY = NOT_RUN_THIS_PHASE
~~~

决策依据：[Main Control 7066408379](https://github.com/spareribes/ai-colleague/issues/139#issuecomment-7066408379)。
本文件是一个工作包、一次计划 Review、一次 Human grant、一次三 Slot 批次的施工合同；不是执行命令授权，也不是完成声明。

## 1. 交付目标与边界

最终要证明：

原注册 SessionAuthority 获取 → 原 Hermes Guest Worker 实际执行 → Developer 私有可写设备 →
Owner 冻结实际候选 → 全新只读 Reviewer → 原 Owner 取消 → 物理 Stop →
原 Owner exact wait → 管道/线程/FD/accounting 清退 → 新 epoch Recovery。

三个 Slot 都运行 accepted managed_worker.run_adopted / AIAgent，而非 Fake Worker。
Fake Cockpit 仅提供确定性的资格测试响应，不能据此声称真实模型或真实工程交付成功。
FIRST_WORKER_OWNED_DELIVERY 仍 NOT_ACHIEVED；本包不是实际 Mission→Codex→Claude→PR→CI 交付。

硬约束：

- 唯一执行权、Task/Run/Claim、SessionDB、Stop、Recovery 和退休权属于原 Hermes SessionAuthority。
- 复用 point-to-point AF_UNIX socketpair → QEMU UART → framed duplex serial RPC。
- OwnerSerialSession / SerialWire 独占 Host 串口协议的读取与写入；existing write lock 统一发帧。
- 无 Message Bus、Broker、Pub/Sub、Topic/Event Bus、独立 Dispatcher、新 Queue/Store、第二 Owner、
  新 Worker Runtime、Daemon、网络代理、安全框架或第二数据库。
- 一次性资格函数是原 Owner 的方法及普通 sibling；不是常驻服务或第二套调度/生命周期权威。
- 不修改 PR12–18、Q1/D/C3/preserved Q2 的原分支、Worktree、制品、旧 grant 或历史 STOP_UNCERTAIN。
- 不恢复产品 Board dispatch，不开放一般 Runtime Apply，不调用真实 endpoint/凭据/模型，
  不运行 Codex/Claude，不写真实项目，不在 Guest 中操作 GitHub，不发布二进制/Release，不改生产。

## 2. 精确基线、Worktree 与唯一最终 PR

| 身份 | 精确 HEAD | 使用方式 |
| --- | --- | --- |
| Q1 HVF | 48c4c94bec337d1fca48876280f9655e4800c961 | 复用已验证 process-owned HVF、身份、QMP、wait/group/FD 与 destroy instrumentation；不重跑旧 campaign |
| Guest / PR16 | 9a270a78b421565a64901182062b18a0d3b2e673 | 冻结的 Guest 源码，已嵌入现有 root/initramfs；不随 Host 合并变更 |
| Builder / PR17 | 2232de50d163c5a1d630220922642983437ab9ac | 完整接入已验收构建/只读检查 helper，不重建原 kernel/initramfs/root |
| Host / PR18 | 13c096f01f4d65726d89e36f9985959f8c6fcb73 | 原 Owner 固定 Responses 注入、durable cursor、UNKNOWN、deadline/late result |

计划独立 Worktree 已建立于 PR16 exact HEAD：
/Users/timmywen/Documents/AI_Colleague/worktrees/issue139-q2-native-qualification-dev-01
分支：codex/q2-native-qualification-v1。当前仅添加本计划；未合并实现、未创建 PR。

后续在同一 Worktree 完成整包，最终仅创建一个 OPEN/DRAFT stacked PR，base =
codex/pr16-q2-qemu-guest-worker。不提前预占 PR 编号，不创建 plan/helper/slot 微型 PR；
不 Merge 该 PR 或任何基线 PR。计划提交 HEAD 与未来 combined Host executable HEAD 必须分别记录。

集成顺序：以 PR16 为共同 base，合入 PR17 exact commits，再合入 PR18 exact commits，保留来源历史。
精确比较 imported 文件的 Git blob 与 accepted HEAD，而非盲目 cherry-pick。

冲突策略：

1. 真正共同修改的文件是 native/qemu_guest/README.md。保留 PR17 的 BUILD/制品说明及
   PR18 的 accepted D2 段；把 D2_NOT_ACCEPTED 明确放到历史 proposal/fixture 限定内。
   顶部记录 Guest、Builder、Host、combined Host 四种身份及“未执行/非 live”状态。
2. PR17 相对 PR16 **没有修改** gateway/session_guest_serial.py，不能把它报告成真实 merge conflict。
   该文件以 PR18 blob 6e933a3cefa6433c662e50997b9a3f67b97a8326 为基线，
   SHA256 d48f8ad61637a0dd2e4631876978b8713fb4856890d2faac95640baece22b7ee。
   后续只加入 proof-gated 正常关闭/Owner accounting 的必要差异；不能丢失 cursor、原子 attach、
   independent STOP、异常 FD finally、heartbeat 或 late-result 修复。
3. PR18 inference SHA256 ad025a0dc88eff191c30a427496ac86ca2d0a1dc0c2eb450f024b87e0f2a468a；
   原样保留。不得为本批次另写 Fake inference Runtime。
4. Guest 源码、boot_init.c、原七制品不变。若发现必须变更 Guest/root/initramfs，
   停在 launch 前，报告具体故障；本计划不授权悄悄重建、第二次 boot 或扩展制品身份。

## 3. 精确文件白名单

下列列表是最终相对 PR16 的完整可变路径集合，无目录通配授权。计划阶段只改本文件。
“原样导入”不得顺带重构。“必要修改/新增”仅限本计划的 qualification 能力。
超出路径即停止并报告最小范围决策；不得自行增加基础设施。

### 3.1 Host Runtime：7 个路径

| 路径 | 动作/职责 |
| --- | --- |
| gateway/session_guest_inference.py | 从 PR18 原样导入，固定 D2 HTTPX MockTransport operation；不修改 |
| gateway/session_guest_serial.py | PR18 基线；独占 serial、关闭/EOF/服务 join 证据；正常 physical finalizer 与异常 revoke 路径分离 |
| gateway/session_authority.py | 只增加原 Owner 的 qualification 入口及启动 Recovery 调用；仍用注册 authority/epoch 校验 |
| gateway/session_runtime_workers.py | 复用原 pending-work/accounting/shutdown，加入 Q2 physical handle 的未退休计数，不创建新调度器 |
| gateway/session_worker_guest.py | 原 reservation/assignment endpoint；只增加 Host-only proof-gated physical finalization，不能暴露 Guest retire RPC |
| gateway/session_hvf_process.py | 复用 identity/group/QMP/wait；新增 Q2 无 serial consumer 的组合 observer；Q1 路径语义保持不变 |
| gateway/session_guest_hvf.py | 新的有限 qualification sibling：candidate/manifest 验证、原 Owner acquisition/3-slot batch/物理证明与 recovery；不是新 Owner/Runtime |

### 3.2 Native/build：17 个路径

从 PR17 原样导入以下 10 项：

- native/qemu_guest/BUILD.md
- native/qemu_guest/artifact-inputs.lock.json
- native/qemu_guest/artifact_fs.py
- native/qemu_guest/artifact_inventory.py
- native/qemu_guest/boot_init.c
- native/qemu_guest/build-tools.lock.txt
- native/qemu_guest/build_artifacts.py
- native/qemu_guest/build_inputs.py
- native/qemu_guest/public-selftest-vectors.json
- native/qemu_guest/verify_images.py

必要修改/新增以下 7 项：

- native/qemu_guest/image_contract.py：保留 GuestImage 原验证，增加 Owner 预打开设备 FD/fdset 绑定的 Q2 argv 数据接口；
  不把 FD 来源变成 Guest 可选项，不允许通用 -add-fd 或附加设备。
- native/qemu_guest/qualification_artifacts.py：新 helper，调用原 ext4/prepare_workspace/只读解析器；
  仅构建实际 assignment 和 disposable Slot 设备、冻结 Slot1 实际候选及 Reviewer 派生。
- native/qemu_guest/qualification_package.py：新 helper，复用既有 Q1 构建/依赖打包函数与固定 QEMU 上游；
  构建独立 Q2 App、canary、hash inventory/SBOM/provenance，不改 Q1 output。
- native/qemu_guest/qualification_gate.c：新 Q2 bootstrap 校验，core=0、精确 FD/role/plan 验证、
  等待原 Owner release 后才进入 QEMU；不访问 DB，不决定 Mission 权限。
- native/qemu_guest/qualification_canary.m：新实际 OS 正负控制及继承 FD 能力测试；不调用 Hypervisor。
- native/qemu_guest/qualification-main.patch：只修改固定 QEMU main 的 Q2 bootstrap 接线；
  复用 Q1 已验证 hv_vm_create/destroy patch，不重写 HVF teardown。
- native/qemu_guest/qualification-fixture.json：固定非秘密 fixture、Fake Cockpit 操作脚本/内容、
  资源预算与阶段判定；不是 store/grant 或一般配置入口。

Q1 native/qemu_hvf 的 source-lock.json、helper.entitlements、admission_gate.c、
qemu-candidate.patch、Sandbox/packaging helpers 全部只读依赖；**不在写入白名单**。
Q2 App 使用同一 App Sandbox + Hypervisor entitlement 字典，无 network/file-exception/FDA entitlement。
需要编译的只是有明确 Q2 gate/FD 改动的新 Helper；不重做 Q1 已通过的五生命周期实验。

### 3.3 Test：6 个路径

- tests/native/test_qemu_guest_artifacts.py：PR17 原样导入。
- tests/gateway/test_guest_cockpit.py：PR18 原样导入。
- tests/gateway/test_guest_serial.py：原 serial 独占/正常关闭/故障关闭合同回归。
- tests/gateway/test_session_guest_hvf.py：新增原 Owner 获取、事务、退出、Recovery/accounting 与 Native budget 合同。
- tests/native/test_q2_qualification_artifacts.py：新增实际 ext4 候选/Reviewer/assignment/FD argv/别名与损坏测试。
- tests/native/test_q2_qualification_sandbox.py：新增签名 canary 的解析/判定测试；真实 OS 控制必须在授权后运行在 macOS，不能伪造 OS。

### 3.4 Docs：2 个路径

- native/qemu_guest/README.md：唯一 shared 文档冲突的合并与 qualification 状态。
- native/qemu_guest/QUALIFICATION_PLAN.md：本冻结计划、具体审查修正与最终证据入口。

总集合 = 7 Host Runtime + 17 Native/build + 6 Test + 2 Docs = 32 paths，相对 PR16。
其中 15 项是 PR17/18 既有导入集合（README 共用一次），其余为资格整合的最小明确白名单。
不修改 agent/、原 Worker/RuntimeSessionStore、hermes_state*、kanban_db*、Schema/依赖锁、
CI/Release/Desktop/Workbench；使用已有 API 和既有 metadata，不增加 table/Queue/Store。

## 4. 原七制品的精确保全

路径根：
/Users/timmywen/Documents/AI_Colleague/evidence/q2-guest-artifact-build-20261121/package

本计划阶段已重新只读核验：SHA256、size、st_dev、st_ino、nlink=1、非 symlink 全部匹配历史 receipt。
dev=16777229；以下 inode 是原件身份，**不能**复制到新副本 manifest 冒充新 inode。

| 原件 | Bytes | inode | SHA256 |
| --- | ---: | ---: | --- |
| kernel.Image | 37660608 | 180148654 | 9c37ace54ef7e1919411fd912e9f34d6982ddd7f4c8ef3c8aee56f4c4d70db67 |
| initramfs.cpio.gz | 571100 | 180148655 | 16d87dcb36ed79e3b40fd69b60b0b7bda0e0ecda20851583e881c586e17dd97e |
| root.raw | 1073741824 | 180148656 | c814b1f8a7077b97464a0824e001c2260a3f9cc6ed42fe3c491088f8991aa01e |
| developer-task.raw | 67108864 | 180148724 | 9449234a0f9188f501a862829590e0cbcc6803b8ba1ac7821e69ae582da74c35 |
| reviewer-task.raw | 67108864 | 180148725 | 7632388362c3ab35b3134857647a837e5baac774fc38715b28f26a68f24480cc |
| developer-assignment.raw | 16777216 | 180148726 | 8e94f012a3eaea00d5dd790335a644304b84bcab26ca4b259141cd3776202237 |
| reviewer-assignment.raw | 16777216 | 180148727 | 86241a7a2aba6fde557fb60c387657a42319fa53c01d491df31facc710948de4 |

既有 package manifest SHA256：
cb89585ad5a0972eecaea6b44d4434ad70027bbabf5e5d730d71ea21565e9af3
SPDX SHA256：7b6d5e8f29e67a4b485e12a543c92cdc3e29a5afc0b611870030b16427f78f0f
Provenance SHA256：11bb7de54fb616f4955b7e90474a52440d6e14d0e5b7b7eca9598ab2b7ce360e

保全过程：

1. 原七件始终只读，不 chmod、移动、挂载、hard-link、reflink/clone 或传 O_RDWR 给 QEMU。
2. 新批次使用普通独立字节副本（O_EXCL），重新 hash/fstat；复制内核/initramfs/root 的字节必须匹配。
   Root 只读；全新 task/assignment 不复用 OFFLINE_BUILD_ONLY scope。
3. 每个 slot 从原 Owner 的真实冻结 work 生成 assignment ext4，独立 task ext4，nlink=1、
   dev/inode 不重叠；每份 manifest 写它自己的实际 inode/size/digest/access mode。
4. Developer task 为唯一 O_RDWR/RW QEMU block 设备；root/assignment 和 Reviewer task 为 O_RDONLY/RO。
   原件不作为可写磁盘；不以“保留外国 PID/过期 scope”替代新 admission。
5. 启动前打开后 fstat/hash，比较 pathname 身份与前后 stat；拒绝 symlink/hardlink/rename/
   digest 或配置漂移；以打开的 FD 作为实际传递能力，消除验证后重新打开另一条路径的窗口。
6. 正常退出后原 Owner fsync 自己持有的精确 task FD、关闭后重新只读 hash；
   原七件在整包结束（包含失败）后再核验。所有旧 receipt 不覆盖。

## 5. 单一 Owner：reservation、状态机与恢复

每个 slot 使用全新 Task、Run、admission、session、execution、VM UUID、connection generation、
Owner epoch/instance、唯一 attempt UUID。不能重用同一 VM 身份或旧 slot 的密钥/lease。
原 Owner 持有 Claim；Guest 只得到非秘密绑定和 claim digest，绝不得到 claim bearer。

资格 profile/Board 是原 Schema 下的一个全新 disposable fixture，不是生产 Board，也不产生另一套权威。
slot 之间先完全关闭/注销旧 authority，再通过原 canonical runtime 初始化获得新 epoch/instance；
任何时刻仅一个 live registered original SessionAuthority，前一 epoch 的物理/DB工作必须完成后才换 epoch。
同一资格 SessionDB/Board 保留三个 slot 的历史，跨 epoch 读取上一 slot 的最终证据。
跨epoch的下一slot仅限前一slot已完整退休、原Owner已持久化planned-handoff及下一slot序号、
canonical关闭/初始化按预定顺序发生的同一批次调用。不可因进程重启就自动接着消费grant；
意外Owner退出/缺失handoff会使整个grant停止。旧epoch不接管新epoch，恢复也不重放已用slot。
资格函数不能模拟/替代 SessionAuthority，也不能以外部 Driver 的 Popen 冒充 Owner acquisition。

状态与证据：

| 阶段 | 既有持久化/物理动作 | 进入下一阶段的必要条件 |
| --- | --- | --- |
| NOT_STARTED | 验证本次唯一 Human grant、计划/source/helper/artifact 根身份、预算；不承接旧 grant | grant 全部匹配，之前无未知尝试 |
| RESERVED | Board task_runs.metadata 记录 Q2 STARTING exclusion（未证明清退即阻止后继）；SessionDB 既有 state_meta 同步索引；reserve_guest_admission 写原 worker/admission assignment | 原 Owner、Task/Run/Claim、epoch、VM、scope 绑定正确，两个 writer/readback 完成 |
| PREPARED | prepare_work 冻结 context；新 assignment/device manifest 与 FD identity 绑定 | 原 owner_admitted/workspace provenance、role/head 和 frozen bytes 均匹配 |
| CHILD_BOOKED | 原 Owner acquisition thread 在 Board write_txn 内最终检查并 Popen；QEMU gate 尚未创建 VM；精确 PID/birth/boot/fingerprint/PGID 立即登记 | 原 Owner index 和 Board child identity 均 commit/readback |
| RELEASED | 再次检查 epoch/claim/预算/FD/slot，用 QMP stdin 的 pre-QMP release frame 放行 QEMU gate | 恰好一个 hv_vm_create success；60s 内完成原 Worker context/adopt/persist/ready |
| RUNNING | 既有 serial operation；Owner 持久化、Fake Cockpit 和 bounded activity | 运行预算/epoch/claim/heartbeat 均合法 |
| RESULT_PENDING_PHYSICAL | 原 Guest execution.finish 仅返回 pending_retirement | result/finished 不是 RETIRED；新 Host operation 已关闭 |
| STOPPING | 正常 finish 或原 Owner cancel；串口控制与 UNKNOWN 写入独立 | 不以写入失败延迟 STOP；不清除物理 handle |
| EXIT_OBSERVED | QMP shutdown、destroy telemetry、exact wait、empty PGID、FD/thread close | 每项真实观测完整，normal return=0，destroy=HV_SUCCESS，2 vCPU joined |
| ACCOUNTED / RETIRED | 原 Owner 最后写 matching Board/SessionDB/proof digest，物理 worker terminal/accounting；只在无失败/无 prior uncertainty 的健康路径 | 两个 store readback、all threads joined、FD baseline 不增长、无 outstanding mutation |
| STOP_UNCERTAIN | 任一未知/失败、丢失 readback/身份/预算或 Owner 崩溃 | sticky；不自动改为 RETIRED；本批次立即禁止后续 slot |

既有两个 SQLite DB 不可假装具有跨库原子事务。采用 Q1 的先持久化 exclusion、后 booking、
最后 release 的顺序，任何中间失败保持不可再启动状态；只有所有 readback 完成才释放 HVF。
新 Q2 metadata 使用原 Task Run metadata 与 state_meta；没有第二 ledger/Store/表。
grant 消耗 slot 在 Popen **之前** commit，失败的 reservation/启动不可通过重试退款。
每个 VM slot 内最多一项 create 和一次 boot；canary 不调用 HVF，不能把一次 QEMU --help 藏在预算外。

正常退休需要一个 Host-only finalizer，不能沿用 close_transport 的无条件 revoke 后再把 UNKNOWN 清掉。
实现只允许“健康结果→禁止新操作→服务/serial/http关闭→物理证明→原 Owner最终事务”；
若其中任何步骤失败则调用原 revoke 并保留 UNKNOWN。
不向 Guest 增加 terminalize/retire RPC，不放宽原 _retire_admission_workers 的 physical gate。

Slot3 的主动取消会按现合同写 worker/admission UNKNOWN。这是**预期的撤权证据**，不是成功业务完成。
之后可以追加完整“物理清退已证实”事实，但不把该逻辑 UNKNOWN/历史记录改写成任务成功/自动 RETIRED。
Slot3 的通过标准是取消/物理清退证据完整、恢复后 UNKNOWN 仍阻止 resume/successor。
任何非预期 UNKNOWN（含清退/存储/观测失败）都判该 slot NOT_PASS 并停批次。

Recovery：

- 正常 Slot1/2 完全清退后，关闭原 Owner，再用 canonical initialization 新 epoch readback，
  精确匹配已冻结证明；才允许进入下一 slot。
- Slot3 在物理子进程已 reap 后关闭 Owner，重新初始化新 epoch，验证旧 admission/worker 不可 resume、
  UNKNOWN 不丢失；不启动第四个 VM，不人为 crash 一个仍拥有 VM 的 Owner。
- 如果真正意外 Owner crash/Host reboot，grant 不可恢复；未完成 reservation 持续 UNKNOWN。
  PID 消失、机器重启或 boot ID 变化都不能补造 missing wait/FD/accounting 证明。
- 不调用 reset/discard/reaper 清理旧状态；Q1/D/C3 的历史 UNKNOWN 一律不触碰。

## 6. 完整调用链与 Serial 唯一所有权

计划新增唯一资格入口（当前尚未实现，以下不是现在可运行的命令）：

~~~text
cleared environment + isolated qualification HOME/HERMES_HOME
  python -m gateway.session_guest_hvf --manifest ABS_BATCH_MANIFEST --run-batch
    canonical GatewayRunner runtime initialization（无平台/Gateway listener）
    registry.for_home(profile) == authority
    SessionAuthority.qualify_q2(batch)
      reserve/prepare slot through original Owner + Board writer
      acquisition thread: final Board/Owner validation -> Popen gated helper -> booking
      bind GuestOwnerEndpoint + OwnerResponses(MockTransport)
      OwnerSerialSession(endpoint, inherited socket endpoint, frozen work)
      commit/readback -> gate RELEASE
      real Guest entry -> execute_guest -> managed_worker.run_adopted -> original AIAgent
      original context/persistence/inference/activity RPC
      Owner finish/cancel -> QMP/process-only observer -> exact wait
      close/join -> original Owner proof finalizer -> durable recovery readback
~~~

禁止另写可自行 launch/admit/settle 的 test Driver；上述 CLI 仅初始化/调用原 authority，
没有自己的 Task/Run/claim/recovery 权限。没有 --slot N、resume 或 retry 快捷开关。

FD 所有权表：

| FD/资源 | 唯一业务 reader / writer | 其他允许行为 |
| --- | --- | --- |
| Host framed serial | SerialWire receive pump / existing write lock（业务、heartbeat、Stop 共用） | OwnerSerialSession 唯一业务 dispatch；物理 observer 只读它的关闭/join 事实，绝不 os.read/send |
| Child serial endpoint | QEMU socket chardev；Guest tty 单一 GuestSerialClient | parent 在 spawn 后立即关闭该 endpoint |
| 原 parent serial endpoint | attachment 后关闭原 parent copy，只保留 SerialWire 自己的 owned dup | 不能保留额外未登记 dup；observer 不得 dup/read |
| QMP stdout/stdin | 原 Owner 的 QMP observer / QMP writer | gate release 只在 QMP 初始化前由同一个 writer 写；QMP 从不承载 RPC |
| stderr | process observer drain | 读取 hv_vm_create/destroy/PID/join telemetry，有限日志 |
| root/task/assignment | Owner verify/open；QEMU fdset | 明确 access mode；生命周期结束全部 dup/fdset/parent copy 都登记关闭 |
| HTTPX Fake operation | PR18 OwnerResponses 原 helper thread | 独立 timeout/cancel，所有 future/client/stream 必须真实完成/关闭 |
| Board/SessionDB | 原 Owner | QEMU 不继承 DB FD；Guest 无路径或 handle |

不调用 Q1 observe_child 的 inert READY/STOP 分支。Q2 observer 可复用 ChildPipes 的 QMP/stdio 部分，
但 serial=None 不能被当作“serial EOF 已证实”。Q2 proof 必须从 OwnerSerialSession/SerialWire 的
真实 EOF/descriptor closed/receive pump/writer/heartbeat/service joins 逐项取得。
原 Owner 用精确 process identity 和 kernel process-group census，辅以存活期 descendants 身份快照；
任何未批准 Host descendant、无法枚举或身份缺口都停止。固定 Helper 不启用外部 backend/helper/plugin，
不允许通过 argv 动态扩展可执行子进程。这里复用 Q1 已接受的 Apple process-owned HVF 信任边界，
不是宣称拥有独立 kernel VM enumeration API，也不是对任意恶意 Host 程序的普遍 fork 监控证明。
禁止在一条 UART 混入 Q1 文本 READY/STOP、Guest 普通 stdout 或第二种诊断 framing。

EOF 时序：健康 Guest 先发 result/finished，Owner 响应 finish；之后 Guest entry 关闭 channel，
PID1 wait/sync/poweroff。只有处于已冻结的健康关闭阶段，才把预期 EOF 当作关闭事实；
它仍不产生退休权。早到 EOF、未完成 inference/persistence、错 scope/frame/epoch 一律 UNKNOWN。
普通 Worker stdout/stderr 仍进入有界 Guest 本地日志，不能为取日志额外开串口 reader。
若启动失败而 Guest 私有日志不可取，保留可取得的原始 Host证据，缺失项写 UNKNOWN；不为诊断再 boot。

## 7. 实际 Q2 App Sandbox / 设备能力

Q1 Helper 的只读 bundle 资源通路不等于 Q2 Developer 可写能力。
本计划采用已经存在的 QEMU pre-opened fdset 机制，不添加 user-selected-file exception、sandbox-exec、
共享 UID 隔离替代方案、bookmarks Broker、XPC Broker 或 ES Observer。

- 内核/initramfs 只读字节副本位于新 Q2 signed App Resources，digest 与原件完全一致；
  QEMU binary、固定依赖 dylib 和 bootstrap plan 也列入完整签名 inventory。
- Owner 在 Sandbox 外 verify/fstat 后预打开 root RO、assignment RO、task RW（仅 Developer）或 RO（Reviewer）。
  只传这三份设备 capability FD 和一份 serial FD；QMP 使用精确 stdio pipe。
- QEMU 使用 -add-fd fd=N,set=S + file=/dev/fdset/S；拒绝任意附加 FD/set/文件路径、
  未批准设备、writeback overlay、-snapshot、netdev/NIC、磁盘 hotplug 和一般 QMP control。
  QMP writer 仅有固定 introspection/shutdown 允许表。
- Helper 预检拒绝 inherited DB/socket/credential/其他项目 FD；除 stdio、serial、三个设备、
  必需 runtime OS descriptors 外不得有未解释 FD。Owner grant 在 gate 放行前对 descriptor map 做 fstat/access-mode核对。
- root/task/assignment argv 仍绑定实际路径的原 GuestImage manifest；FD argv 不能绕过 manifest verify。
  QEMU task 权限不靠 chmod 冒充 App Sandbox：read-only 依靠 O_RDONLY + QEMU readonly + Guest ro，
  Developer 写入依靠预授予的唯一 O_RDWR capability。
- QEMU11.1.3 官方源码 qemu-options.hx 描述 -add-fd/file=/dev/fdset；util/osdep.c 的
  qemu_open_internal 调 monitor_fdset_dup_fd_add。这是 SOURCE_VERIFIED，不等于 macOS Sandbox 已通过。
- 真实 Sandbox 是否允许该 FD 使用/拒绝路径重开，仍 UNKNOWN，必须由下列实际正负 controls 判定。
  若该机制不工作，停止，不偷偷改网络/file exception/更宽权限，也不再增加架构组件。

实际测试矩阵（授权后运行；本计划阶段 NOT_RUN）：

| 对象 | Unrestricted positive-before/after | 真正 Sandbox child/canary 预期 |
| --- | --- | --- |
| 已批准 helper/app signature/library/kernel/initramfs | verify/read 成功 | exact inventory/read 成功，app 内容写入被拒绝 |
| root / assignment / Reviewer task RO FD | 能读；RW 测试只在 disposable scratch mirror 校准 | 能读；对其写入/升级 O_RDWR 被拒绝；无磁盘字节变化 |
| Developer task O_RDWR FD | public scratch sector 可写/读回/恢复 | 仅精确 disposable capability 可写；直接路径重新打开应被拒绝 |
| Serial socketpair / QMP pipes | 双向 known nonce / EOF | 双向 known nonce / EOF，未传入 endpoint/路径不可连接 |
| Host HOME public marker、伪 Provider secret marker | 读取已知公开校准字节成功 | EACCES/EPERM；不读取真实生产 credential bytes |
| fixture Owner SessionDB/Board 与邻近项目 public marker | Owner 自己可读写/事务验证 | child 路径读写均拒绝，不能继承 DB FD |
| SSH Agent/Docker/其他 UDS 的 public fixture | calibration connection 成功 | 连接拒绝；只允许已继承 unnamed serial capability |
| TCP/UDP/IPv4/IPv6 listen/connect | 仅受控本机 calibration endpoints 成功 | EACCES/EPERM；不存在 client/server network entitlements |
| private scratch 与错误目录写入 | 测试目录可写 | 仅 OS 规定的该 app 私有 scratch 可用，外部写入拒绝；不夸称 macOS 无系统库/私有容器访问 |
| 角色/FD身份被替换、缺失、hardlink/symlink、额外device/network argv | negative test 可构造且字节已知 | gate 拒绝，不能进入 hv_vm_create |

negative targets 都是公开 disposable markers，包括在实际 Host HOME 下的专用 public canary 目录，
以及真正 Owner profile 内的测试 DB。不是读取生产 SessionDB/Board/SSH/private Keychain。
不得因 unrestricted control 本来 ENOENT 或无权限而“证明”Sandbox 有效；校准必须前后成功。
Keychain 用 Q1 已验证的精确 public Apple fixture，只做显式 scoped query，绝不读取默认 Keychain、
搜索列表、Provider 文件或真实 token。全部 canary 记录 code identity、errno、FD fstat/mode、回读与关闭。
Controlled localhost Sandbox calibration 是独立的无 VM OS canary，不是 Fake Cockpit listener，
不运行历史事故 Gateway/loopback 集成测试，不发外部网络请求。
若 Human grant 不包含这些 OS 控制，保持 NOT_RUN，不偷用已花费 Q1 grant。

控制执行分层必须明确：VM前先用与最终App相同entitlements/打包规则、相同预检对象代码的
无Hypervisor canary做unrestricted/sandboxed/recheck；它不是QEMU进程。
每个实际QEMU Helper也在本slot内、进入hv_vm_create之前执行自身签名/FD/Sandbox预检并留下codeidentity。
若实际Helper预检失败，该QEMU进程已消费slot，立即停止，不另起一个Helper补测。
Serial nonce和scratch-sector读写只在canary自己的独立公开fixture FD上进行，不能污染真实Worker的framed UART，
也不能预检改写实际Guest ext4元数据。实际Helper仅检查其授权FD身份/accessmode和预检允许表，
真实Developer写能力由Slot1的实际Worker写盘与停机后内容核验共同证明。
不为了跑Helper --preflight/--version而额外启动第四个QEMU；没有绕过预算的诊断模式。

## 8. 三 Slot：实际命令、输入与证据

下面是未来原 Owner 内部生成的 argv 模板，不在 Phase A 执行。Host 不接受任意用户 argv。
GATE_PLAN 在新签名 App 中冻结。slot 命令由唯一 batch 入口派生；不能手工启动任一 QEMU。

~~~text
Q2_HELPER --hermes-hvf-q2 GATE_PLAN -L APP_RESOURCES
  -nodefaults -display none -monitor none -qmp stdio
  -chardev socket,id=worker,fd=SERIAL_CHILD_FD -serial chardev:worker
  -nic none -accel hvf -machine virt -cpu host -smp 2 -m 2048 -no-reboot
  -kernel APP_RESOURCES/kernel.Image -initrd APP_RESOURCES/initramfs.cpio.gz
  -append "console=tty0 root=/dev/vda ro rdinit=/init panic=-1"
  -add-fd fd=ROOT_FD,set=1
  -drive file=/dev/fdset/1,format=raw,if=none,id=root,readonly=on
  -device virtio-blk-pci,drive=root
  -add-fd fd=TASK_FD,set=2
  -drive file=/dev/fdset/2,format=raw,if=none,id=task,readonly=ROLE_RO
  -device virtio-blk-pci,drive=task
  -add-fd fd=ASSIGNMENT_FD,set=3
  -drive file=/dev/fdset/3,format=raw,if=none,id=assignment,readonly=on
  -device virtio-blk-pci,drive=assignment
~~~

| 内部 slot invocation | TASK / ASSIGNMENT | ROLE_RO | 成功后 |
| --- | --- | --- | --- |
| authority.qualify_q2: slot1 developer | slot1/task.raw O_RDWR；slot1/assignment.raw O_RDONLY | off | 冻结实际候选，再完整 Recovery |
| authority.qualify_q2: slot2 reviewer | 从 slot1 候选构建 slot2/task.raw O_RDONLY；独立 assignment | on | read/cannot-write 证据、退休、Recovery |
| authority.qualify_q2: slot3 cancellation | 全新 developer task 副本 O_RDWR；全新 assignment | off | cancel+late suppression+清退+UNKNOWN recovery；批次结束 |

每个 role manifest 绑定 kernel/initramfs/root/task/assignment 的路径、dev/inode/size/sha256/RO，
work.json/scope/role/base HEAD、owner/task/run/claim digest、slot/VM/attempt/epoch、
fdset id/access modes、helper inventory、host head、guest source、policy digest。
原 Owner 在每次 spawn 前验证完整 manifest，不把 Guest 提供的值当作启动参数。

### Slot1 — Developer

1. 原 Owner 通过原 Kanban/workspace provenance 接口准备 disposable fixture，真实开始 admission，
   writer transaction 内创建 started Worker reservation，冻结 prepare_work 和新 assignment。
2. 新 Developer 磁盘为独立64MiB ext4，UID/GID1000；root只读1GiB；assignment只读16MiB。
   Guest unprivileged UID、no_new_privs/capability drop、tmpfs与process/FD/core/file limits由原已验收init执行。
3. 60s 内必须看到真实 Guest context challenge/readback、worker.adopt、最初的 canonical persistence receipt，
   heartbeat 和 ready。单独收到 Guest ready 文本不够。
4. 现有 MockTransport 固定 Responses tool-call 脚本，让原 AIAgent 调用真实 Guest terminal/file tool：
   检查 UID/mount/no-network/resource facts，在 /task 写 qualification/result.txt（固定公开内容），
   通过 Git 创建实际 candidate commit，并读取文件/HEAD。脚本不在 Host 代做 file mutation。
   禁止委托 subagent、联网、后台/terminal/tmux 常驻任务；tool stdout 进入原 transcript receipts。
5. Fake 最终 Response 仅在真实 tool result/persistence 匹配固定步进合同后发送完成响应；
   缺失、额外、错误工具调用立即 FAIL，不能仅根据 Agent “成功”文字通过。
6. 健康 finish→Guest entry return→原 PID1 wait/sync/poweroff；记录 QMP Guest SHUTDOWN、
   QEMU hv_vm_destroy 实际 result=0、joined=2；原 Owner exact wait return0、PGID空、全FD/thread完成。
7. 停机与 exact wait 完整通过后，Owner fsync/只读解析**实际写过的磁盘**，核验文件内容和提交，
   原盘写后 SHA、候选 commit 与 tree/content manifest 一起冻结。否则不能进入 Slot2。

### Developer → Immutable Candidate → Reviewer

- 禁止 Slot2 使用原 base fixture 代替 Slot1 输出。记录 parent Slot1 task/run/vm/attempt、
  before/after disk SHA、actual candidate commit、Git tree id、规范排序 content inventory SHA256。
- 只读 ext4 parser 从关闭的实际磁盘提取允许的有限内容，拒绝路径逃逸、symlink/hardlink/special/
  setuid、超额文件/字节及不受支持的损坏文件系统。绝不 mount untrusted Guest disk 到 Host。
- 在 disposable quarantine 重建 Git 对象库，只复制验证后的对象/必要引用，禁用 hooks、
  alternates、外部 config、credential helpers、filters、remotes和共享 common-dir。
  Git fsck --strict 及固定 fixture路径/内容/commit tree校验必须通过；
  不执行 Guest 提供的脚本、配置或checkout hooks。
- 保留实际 Guest candidate commit，不能由 Host 重新写一个“等效”提交冒充相同 HEAD。
  若真实候选无法安全验证/保留，停止；不从预期 fixture 内容重新合成成功输出。
- Owner 写只读 candidate manifest，并把 digest 锚定在原 slot1 Run metadata / state_meta。
  该快照在 Host 上不再提供 writable FD，原 raw也不再挂载。
- 用既有 prepare_workspace + ext4 生成**全新**Reviewer设备；独立 inode/fs UUID/对象库/common-dir，
  不 hardlink/reflink、不 qcow backing chain、不共享 Developer writable inode。
  精确 HEAD/content inventory 必须与 frozen candidate 完全一致。
- slot2 赋值的 reviewer_head 必须为实际候选 commit SHA，Reviewer work.json、device manifest、
  Board reviewer task base/marker 与 policy digest 必须一致；移动 branch不被接受。
- Slot1 的300s窗口包括停机、候选冻结和原Owner recovery；Slot2 的300s窗口包括Reviewer设备派生、
新reservation、运行、清退和recovery；Slot3的300s包括取消及最后recovery。
Snapshot与Reviewer设备生成在单一批次/900s总窗口内受界限约束；不能另跑Guest或向Human逐步审批。

### Slot2 — Reviewer

1. 新 epoch/Task/Run/Session/admission/VM/assignment，Developer所有工作完全退休后才获取。
2. 原 Guest Worker 在新的只读 ext4 task、只读 root/assignment 上运行，同一 accepted Guest source。
3. 固定 Fake tool-call 脚本实际读取 qualification/result.txt 与 git HEAD，内容和HEAD等于Slot1候选。
4. 尝试创建/修改该文件及写 Git对象/配置，必须失败，回传真实工具失败结果；
   Host核对taskFD O_RDONLY、QMP block readonly及唯一inode/common-dir，
   比较slot2前后raw/content SHA不变，不能只信Guest“只读”回执。
5. 真实 Worker结束、Guest正常poweroff、实际destroy成功、Ownerexactwait与全部清退。
6. 再启动canonical Owner新epoch只读恢复slot2证据，不运行新VM；才允许Slot3。

### Slot3 — Cancellation

1. 新 epoch/Task/Run/VM，独立Developer盘，不复用Slot1 VM、reservation、writerFD或serial endpoint。
2. 真实 Guest Worker完成adopt/persist/ready后发起一次合法 inference。
   既有 HTTPX MockTransport 用 threading.Event 标记 request entered，并确定性保持该请求；
   不创建HTTP listener，不发socket/网络请求，不读取credential/config。
3. Event到达后，原 Owner走既有 SessionAuthority.interrupt → interrupt_guest → channel.cancel。
   首先关闭授权并尝试 framed STOP；UNKNOWN写入与STOP独立，不能等Fake request完成才取消。
   STOP-sent、UNKNOWN-persisted、Guest收到/终止、进程退出分别记录。
4. 在确认授权已撤销后释放 held Fake transport Event，制造确定性late response；
   result不得送给Guest，不得产生后续工具动作/任务成功、正常Received覆盖UNKNOWN或新执行者。
   Fake future/stream/client/transport实际完成并关闭，线程和服务section全部join。
5. Guest停止→PID1 sync/poweroff→QEMU实际destroy=0/joined2→Owner exactwait；
   不把“cancel()已返回”当物理停止。任何30s清退超时直接STOP_UNCERTAIN/NOT_PASS。
6. 关闭原Owner后以canonical新epoch恢复；看到原assignment/取消证据、UNKNOWN/物理事实，
   验证旧epoch不可adopt、不能resume/claimsuccessor，pendingaccounting与物理证明一致。
   禁止为“验证恢复”启动第四个VM或清理原UNKNOWN。

## 9. 所有预算、停止条件和失败保全

| 项目 | 固定上限 |
| --- | --- |
| QEMU processes / HVF create / Guest boot | 各最多3，slot1/2/3各一次；不以QEMU --version/help另启动 |
| 并发 | 1；上个slot未全部清退就不得spawn |
| vCPU / RAM | 每VM 2 / 2GiB |
| 附加Guest disk总量 | 每VM≤8GiB；目标1GiB+64MiB+16MiB；无隐藏overlay/额外disk |
| 启动 | Popen起≤60s；包括gate、preflight、Guestadopt/ready |
| Stop / wait / pipe drain / thread close | 首次finish或cancel起共≤30s，不分项累加 |
| 单生命周期 | slotreservation起≤300s，含启动/工作/停止/证明/恢复 |
| 总批次 | firstreservation起≤900s，含三slot与中间snapshot/device/recovery |
| 重启 / resume / retry | 0 / 0 / 0 |
| 原有serial heartbeat | 默认5s pulse /90s lease（≤120），不续deadline/claim |
| 资格inference deadline | 固定≤30s；slot3 cancel由Event触发，必须在该deadline内 |
| frame/RPC | 现有≤4MiB/frame，≤300s/RPC；本批次实际deadline取剩余slot/batch更小值 |
| D2 | ≤1MiB request、≤2MiB response、≤64KiB event、≤1024event、≤8192output token、≤32operation |
| Guesttmpfs | /run128MiB、/tmp64MiB、HOME64MiB、outbox32MiB、log16MiB |
| Guestprocess/FD/file/core | 64 /128 /16MiB /0；root/assignment/Reviewer只读 |

进程/线程不能由Python timeout“被证明终止”；deadline到达但没有真实join/reap就是UNKNOWN。
30s stop预算包含所有等待；不靠不断重置timer延长。budget不足不启动下一slot。

任一失败/UNKNOWN立即原子标记grantSTOPPED/SPENT，禁止后续reservation/Popen；
保存原始可得facts，执行已授权的精确子进程containment（Q1已有identity-bound TERM/KILL、wait机制）
只能为了限制本次自己的子进程，不用于恢复PASS或重试。身份不能验证时绝不向猜测PID/PGID发信号。
如无法在剩余stop预算证明消失，保留STOP_UNCERTAIN及livehandle，结束批次。
不杀历史/生产/无关进程，不做系统级强制cleanup，不自动修复后继续slots。

“Rollback”仅是失败前事务回滚；不能把Popen后DB rollback解释成没有执行者。
child可能存在时保留预先commit的reservation和Owner-held Popen引用，
将spawn-return/PID未booking/commit失败作为UNKNOWN记录。DB写入失败仍独立尝试fsynced原始exit receipt；
任何sink缺失都显式报告，不伪造跨库成功，不修改旧证据。

Host receipt/log保存在新的外部evidence目录，O_EXCL创建、原始日志与派生summary分开；
包括stdout/QMP、stderr、boundedserial frame摘要/序号、实际持久化receipt、
签名entitlements、unrestricted/sandboxed/recheck结果、FD/进程组快照、每次wait返回。
不记录prompt正文/Authorization headers/secret；rawframe仅限公开fixture内容。

## 10. 回归、Mutation、静态检查和独立 Review

本阶段计划未实现/未运行新测试，不继承历史PASS为未来combined HEAD验收。

实施后、任何Native前：

1. 现有安全相关离线回归清单取两个已验收包的文件集合并去重，
   加入本白名单中的新测试；通过 scripts/run_tests.sh、HERMES_TEST_FILE_RETRIES=0、
   原PM-built test interpreter、隔离HOME运行。禁止裸pytest，禁止历史事故Gateway/loopback集成选择。
2. 保持原Guest/Worker/serial/RuntimeSessionStore、Cockpit48cases、artifact48cases、
   Q1Hvfqualification、SessionAuthority/admission/recovery/shutdown、workspace测试正常。
   新测试使用真实SQLite独立connections（WAL/DELETE）、真实inertchild、实际ext4读写和MockTransport；
   不在offline测试启动QEMU/Guest。
3. 专项行为回归：唯一serialreader/writer；QMPobserver不能消费serial；
   durable STARTING→book→release顺序；busy/retry/rollback、commit前后中断；
   OwnerEpoch变更/oldadopt拒绝；lostACK/outbox重复；snapshot/reviewer实际parent；
   子进程退出但FD/thread未完；HTTP close/revoke失败；no successor；budget预扣和不可retry。
4. Snapshot负例：Reviewer拿base替代actualcandidate、工作树与commit不一致、对象库/common-dir共享、
   candidate manifest被改、assignmentwrongrole/head、hardlink/symlink、额外FD、读写mode错误、
   设备被替换/损坏；全部在spawn前拒绝或保持UNKNOWN。
5. 定向Mutation重跑适用的PR16/17/18/Q1原定向项，并为每个新安全判定至少一项行为mutation：
   - 移除finalwriterguard/预提交reservation/bookingreadback/releasegate；
   - 允许额外slot、重试、并发、deadline刷新；
   - 第二serialreader、绕过write lock或误把serial=None视为EOF；
   - 去除deviceFDmode/fstat/digest/inode/readonly检查；
   - 将Reviewerparent改为base、允许共享object/inode；
   - 放过Guestresult/PIDmissing/不完整wait/destroy/group/pipe/thread证明；
   - 取消不发STOP、撤权失败跳过FDclose、late成功覆盖UNKNOWN；
   - 删除history/cursor/assignment/跨epochreceipt后继续；
   - physicalproof未commit即释放accounting或Recovery误resume。
   每个mutation必须造成目标行为断言失败，而非syntax/importerror；保存失败日志与源码恢复hash。
6. Scoped Ruff --preview、Mypy（明确follow-imports=skip/ignore-missing-imports的范围）、CodeHealth、
   python scripts/check --base PR16exact、gitdiffcheck/文件白名单/secretinventory。
   不修改四个冻结Ruffbaseline问题；wholecheck若仍NOT_PASS如实报告，不能声称全仓全绿。
   新代码不得引入额外Ruff/Health/Mypy问题；C/ObjC编译用-Wall/-Wextra/-Werror，GPL源码和补丁完整保留。
7. source稳定commit后由独立reviewer审查exactHEAD、完整32pathdiff与真实artifact/manifest/FD/
   ownerintegration；可重跑offline测试，不能自行Native。明确reviewer身份，不把Codex冒称Claude/MainControl。
   可行动P1/P2必须修复并重做exactHEADReview。
8. 把最终sourceHEAD、每文件SHA、helperAppinventory/CDHash/entitlements、slotmanifest规则、
   SBOM/provenance和所有结果冻结在grantpayload。Native前再核对sourceclean和摘要；
   reviewer测试不消费Native预算。

计划Review不替代以上代码exactHEADReview；未来实现不得因为计划已通过就豁免审查。
最终证据提交若只追加文档/结果JSON，必须列出执行HEAD与报告HEAD的runtime/test/helper字节等价；
任何可执行变更都需要新的审查与授权边界核对，不能在已开始的批次中修补再boot。

## 11. 精确 Manifest / Hash / 一次 Human grant

在当前PLAN_ONLY阶段，不存在combined executable HEAD、Q2 Helper二进制、
真实Owner assignment或Slot1实际candidate；因此不能诚实给出这些未来字节的SHA。
它们的状态必须是 NOT_CREATED / NOT_BUILT / NOT_MINTED，不能填零、用Q1helper/hash顶替，
也不能把本计划commit当作NativeReady源码HEAD。

已知输入精确hash见第2/4节及外部 source-artifact-audit.json。
Q1原helper36f23b811da6658c4ba27008b4588feeea86e94ea62346e84aa8c6533be0eebe
只作为历史只读基线，**不能**签发Q2 launch。
QEMU11.1.3固定上游archiveSHA：
5a8289c7940dc77d3873c81a6c29ba3afe1446fc9d36e77fa1658cdbecb84b22；
Q1记录的原始签名验证与上游keyfingerprint/依赖锁复用，不重新选latest。

一次Human grant的payload必须包含（以下是schema合同，不是已签发grant）：

~~~json
{
  "grant_id": "HUMAN_ISSUED_UNIQUE_ID",
  "package": "HERMES_Q2_ORIGINAL_OWNER_NATIVE_QUALIFICATION_V1",
  "approved_plan_commit": "REQUIRED",
  "approved_plan_sha256": "REQUIRED",
  "accepted_sources": {
    "guest": "9a270a78b421565a64901182062b18a0d3b2e673",
    "builder": "2232de50d163c5a1d630220922642983437ab9ac",
    "host_baseline": "13c096f01f4d65726d89e36f9985959f8c6fcb73",
    "q1": "48c4c94bec337d1fca48876280f9655e4800c961"
  },
  "combined_host_head": "REQUIRED_BEFORE_NATIVE",
  "source_file_inventory_sha256": "REQUIRED_BEFORE_NATIVE",
  "helper_app_inventory_sha256": "REQUIRED_BEFORE_NATIVE",
  "helper_cdhash_and_entitlements_sha256": "REQUIRED_BEFORE_NATIVE",
  "original_artifact_inventory_sha256": "REQUIRED",
  "batch_static_policy_sha256": "REQUIRED",
  "snapshot_derivation_recipe_sha256": "REQUIRED",
  "profile_board_db_and_output_absolute_paths": "REQUIRED_FRESH_FIXTURE",
  "slot_order": ["developer", "reviewer_of_actual_slot1", "cancellation"],
  "max_qemu_processes": 3,
  "max_vm_creates": 3,
  "max_concurrent_vms": 1,
  "vcpu": 2,
  "ram_bytes": 2147483648,
  "max_disk_bytes_per_vm": 8589934592,
  "startup_seconds": 60,
  "stop_wait_seconds": 30,
  "max_slot_seconds": 300,
  "max_batch_seconds": 900,
  "retries": 0,
  "reboots": 0,
  "resume": false,
  "fake_cockpit_only": true,
  "live_credentials_models": false,
  "board_dispatch": false,
  "fail_or_unknown_stops_batch": true,
  "slot_derived_manifest_rule": "OWNER_CANONICAL_BINDINGS_AND_PRECOMMITTED_HASH_CHAIN"
}
~~~

依赖解决与无环hash：

- GuestBinding.image_digest = 固定 kernel/initramfs/root 及Guestsource组成的基础image-set digest。
  不把包含自身scope的assignmentmanifest反过来作为image_digest，避免自引用hash循环。
- 先创建真实Task/Run/admission/epoch/VM identity，再prepare_work写既有state_meta。
  从该冻结work构建assignment和task，最后把完整role/device manifest digest写原Owner/Boardlaunchrecord；
  child-release前两个store readback完成，manifest不会被Guest自选。
- Slot1/3 taskassignment可在source准备阶段/实际Ownerreservation阶段冻结。
  Slot2 candidate commit与rawSHA在Slot1真实执行前**不可预知**。
  Human一次grant必须批准“从实际Slot1候选按exact reviewed recipe派生Reviewer”的规则，
  不能要求提前虚构Reviewer最终hash，也不应在slot间再向Human请求普通批准。
- Slot2manifest只能引用Slot1proof+candidate digest链；必须在Slot2spawn之前由原Owner
  canonicalize/hash/fsync并写两个现有metadata/readback。任何链断裂/recipe/source变更直接停，
  不是以单个可任意修改JSON充当新授权。
- grantledger在原SessionDB state_meta中预扣和封存source/helper/staticartifact根，不能重新生成/reset。
  Slot1/2/3消费前后状态独立记录；已花费slot永久不可复用。
- 完整批次runreceipt最终包含三个真正生成的slotmanifest、candidatehashchain和全部非秘密identities。
  动态产物通过受审查的确定性派生约束一次授权，源/静态根始终精确冻结。

工作顺序只有一次计划Review和一次Human执行grant：MainControl先审本完整计划；
随后实施/离线测试/制品冻结/独立exactHEADReview（不Native），形成具体可核验payload，
再一次性取得三slotgrant并运行整批。普通实现选择由Lead完成，不分slot审批。
如果MainControl要求先给纯计划，当前就停在计划提交；本轮不会偷跑实施或canary。
计划接受本身仍不是Nativegrant；任何缺失的最终requiredhash或实际Sandbox前置条件都会阻止boot。

## 12. Native 证据与最终判定

逐slot独立目录（不覆盖旧campaign）收集：

- grant ID/slot消费记录；Task/Run/admission/session/execution/epoch/instance/VM/attempt/claim digest；
- exactsource/Guestruntime/HelperApp签名inventory；所有静态和动态manifest hash与dev/inode/accessmode；
- Sandbox前后正控制、负控制errno、继承FD读写/nonce/EOF与实际Helpercodeidentity；
- Popen时间/PID/ppid/birth/boot/fingerprint/executable/PGID，booking/release事务readback；
- hv_vm_create真实result与次数，QMP架构/accel/vCPU/RAM/无NIC/精确block inventory；
- context/assignment challenge、adopt、原workerreceipt/outboxsequence、持久化/usage边界；
- Slot1实际写入/commit/磁盘afterSHA/contentinventory/candidatedigest；
- Slot2 parentcandidate/readsuccess/writefail/O_RDONLY/QMPreadonly、前后diskhash相同；
- Slot3 heldevent→原OwnerStop→stop-sent/UNKNOWN-persisted→late-resultnotdelivered、无后续工具动作；
- QMPGuestSHUTDOWN、actualhv_vm_destroyresult与joinedvCPU、精确Popen.wait返回码和signal；
- 全PGID/descendant census结果、stdioEOF/drain、每个设备/serialendpoint/dup关闭、
  serialpump/heartbeat/write/service/FakeHTTPfuture线程join、Ownerpendingtasks与FDcount；
- 原Owner最后accounting和matchingDBreadback、新epochRecovery不resume/不丢UNKNOWN；
- 停止原因、每项UNKNOWN、未运行slot、预算用量、所有原始日志和最终summary的SHA256。

Native资格PASS必须三个slot全部满足其具体合同，无missing事实、无超时/意外UNKNOWN；
Slot3预期取消UNKNOWN必须保留并在新epoch拒绝successor，物理cleanup证据另行完整通过。
前两slot必须有正常RETIRED证明；第三slot不得被粉饰成业务任务成功。
任何一个NOT_PASS/UNKNOWN立即终止余下slot，并给出已消费/NOT_RUN数量；不能拿部分通过称整体PASS。

最终只向MainControl交付一个stackedDraftPR和完整证据：精确执行HEAD/最终报告HEAD，
实际3slot结果、独立exactHEADReview、测试/mutation/static、原件保全hash、剩余资格。
没有真实模型、Codex/Claude、真实PR/CI/Mission闭环就不能宣布FIRST_WORKER_OWNED_DELIVERY=PASS。
CI无check仍为NOT_RUN。Human保留最终Merge与后续真实模型/工程交付授权。

## 13. 本轮 Phase A 交付声明

本轮仅创建独立Worktree、读取原源码/决策、只读rehash原制品、编写/冻结本计划并一次性回写Issue139。
没有合并实现、构建/签名、运行canary、QEMU/Guest/Native、真实模型、RuntimeApply或产品派工。
没有新建或发布最终DraftPR；未来整个qualification只使用本分支的一个最终DraftPR。

证据目录：
/Users/timmywen/Documents/AI_Colleague/evidence/q2-native-qualification-plan-20261122
其中 source-artifact-audit.json 保存所有已知source blob/SHA和原七件真实身份。
未来unknown hashes明确标记；本计划不能伪造尚未构建的源码/二进制/Slot1输出。

## 14. Phase B 实施与离线交付补充

以上第 1–13 节保留接受计划的原文；冻结身份仍为
`8ed92d2a68d70361021e774d6a3dad6b935cb277`。
Main Control 在 comment 7066910552 批准本 Worktree 的源码整合、构建、Sandbox Canary、
离线回归、Mutation 和独立 Review。该决定明确没有授予 QEMU/HVF、Guest Worker、
Runtime Apply、真实模型/凭据、真实项目写入或 Board 派工权限。

整合采用 PR16 Guest 基线、PR17 Builder 和 PR18 Host 的保留历史；原接受分支不变。
Q1 helper、原七件制品和历史失败/UNKNOWN 保留。新 Q2 Helper 独立构建，
新 campaign root 是普通独立字节副本；原七件的 inode 与 SHA 再次核验。
Developer 与 Reviewer 的任务设备由原 Owner 的冻结 assignment 派生；
Reviewer 只接受真实 Slot1 磁盘提取的 commit/content 链，不预造 candidate。

原 Owner 的持久化 grant 在 Popen 前消费 slot，STARTING 在 spawn 前提交；
最终 Board writer transaction 内重新核对原 Owner、claim、全部历史和设备 FD，
Popen、身份登记与 readback 后只放行一次原 Q1 release gate。
Q2 SerialWire 独占 UART；QMP/stdio 观察器没有 UART 能力。
Owner 保留精确 task FD 至退出后 fsync，核验只读设备字节与 inode，然后关闭能力。
物理证明之后保留 ACCOUNTING exclusion，完成既有 Worker、admission 和 Board 记账后
才写 RETIRED；任何中间失败保留 STOP_UNCERTAIN 并停止批次。
取消的逻辑 UNKNOWN 不会因物理证明完整而改成成功；新 canonical Owner epoch 重新核验历史。

实际 App Sandbox Canary 的结果为 **PASS_POLICY_EQUIVALENT_CANARY_ONLY**：
独立主 Canary.app 与 QEMU Helper 使用相同 bundle identifier、entitlements 及同一 preflight
对象，但 Mach-O CDHash 不同。它不是 exact Helper 执行证据。
最初 secondary-executable secinit SIGTRAP 及全部构建失败记录保留。
实际 QEMU Helper 的 Sandbox preflight 与 Native 三 Slot 均 **NOT_RUN**。
完整授权包明确列出该剩余条件；必须由 Main Control 裁决等价性或明确授权 exact Helper
前置验证，并另行授予一次完整三 Slot Native grant。源码交付不签发该 grant。

证据根：
`/Users/timmywen/Documents/AI_Colleague/evidence/q2-native-qualification-implementation-20261122`。
最终 source/helper/code identity、原制品与副本、工具依赖、fixture、SBOM/provenance、
静态检查、回归、Mutation、独立 exact-HEAD Review 及三 Slot 请求均由该目录的最终索引绑定。
所有旧失败日志保留；离线 synthetic physical facts 不记作 Native PASS。
FIRST_WORKER_OWNED_DELIVERY 仍为 NOT_ACHIEVED；未恢复真实 Worker 派工。

## 15. Exact-Helper 无 VM 前置验证更新

第 14 节的 Canary 状态及历史证据保持原样。Main Control 在 comment 7076531521
拒绝等价性豁免，并授权本次实际 Helper 无 VM 诊断；没有签发三 Slot grant。
`qualification-main.patch` 增加独立 `--hermes-q2-sandbox-preflight` 分支，
直接返回已有 `hermes_q2_canary()`，发生在正常 Q2 guard、admission gate 和
`qemu_init` 之前。正常 `--hermes-hvf-q2` 路径保持不变。

新 Helper 已重新构建和签名，Developer 与 Reviewer 各执行一次实际主二进制诊断。
两次均为 **PASS_EXACT_HELPER_SANDBOX_PREFLIGHT**；Helper 自己报告的 SHA256、
SecCodeCopySelf CDHash/identifier、entitlements、完整 App 清单及 role/FD 事实
均与独立 Host 核验一致。原七制品的字节与 inode 在前后保持不变。
独立 Calibration → 实际 Helper Sandbox → Calibration recheck 顺序完整，
受限文件、UNIX endpoint、网络连接与监听的负向结果均为 EPERM。
Developer 仅 task FD 可写；Reviewer 的三个设备 FD 全部只读。

HELPER_PREFLIGHT_INVOCATIONS = 2；QEMU_RUNTIME_ENTRIES = 0；
QEMU_VM_CREATES = 0；GUEST_STARTS = 0；WORKER_EXECUTIONS = 0。
这里的 runtime entry 指正常运行初始化；上游 pre-main QMP 表注册和 RCU 支撑线程
会执行，但不创建 VM、不启动 QMP 服务或 Guest。独立实际二进制反汇编、对象重建、
入口 trap 测试和精确 child wait 一起支撑无 VM 结论，不单独依赖 vm_created=false。

新证据根：
`/Users/timmywen/Documents/AI_Colleague/evidence/q2-exact-helper-preflight-20261122`。
新 source/helper/manifest/SBOM/provenance 与三 Slot 请求重新冻结；旧 Helper、Canary、
失败日志、历史 grant、STOP_UNCERTAIN 及误发对话修改的保全副本均保留。
本次结果仍不授权 Slot1–3、真实模型、生产凭据、真实项目写入或 Board 派工。

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

## Pre-READY failure RCA (Main Control 7081042775)

The second failed batch reached HVF creation, QMP running, Guest-requested
shutdown, successful `hv_vm_destroy`, and original-child reap with exit0. It did
not produce canonical Worker READY, a Worker receipt, inference, or a candidate.
The post-exit `getpgid` error is an independent Host observation race. Neither
failed campaign is retired, reset, resumable, or reusable.

Read-only examination of independent copies found matching kernel/module ABI,
resolvable required ARM64 ELF loaders/libraries, readable entry sources, and an
actual task Git HEAD matching its assignment. These are static facts, not proof
that any Guest syscall or Python import succeeded. No concrete internal Guest
startup cause is established. Missing optional Tkinter libraries are not an
established cause. Reader limitations resolving `/sbin` symlinks are not image
faults.

| Stage | Preserved evidence | Remaining boundary |
| --- | --- | --- |
| PID1 / root transition | Static executable, kernel/module identities verified | Actual calls unobservable |
| Private mounts / task mount | Device order, roles, actual disks verified statically | Actual mounts unobservable |
| UART / limits / UID / cwd | Init policy and access paths inspected | Actual operations unobservable |
| Python / Guest entry | Required ELF closure and source readability verified | Imports and entry execution unobservable |
| Pre-READY validation / serial | Assignment and task HEAD agree | No canonical first frame or READY observed |
| Guest shutdown / Host exit | QMP shutdown, destroy success, exact reap exit0 | Does not establish Worker execution or retirement |

Response B adds one bounded numeric failure receipt on the existing Developer
private task disk. The builder supplies a small diagnostic wrapper around the
unchanged accepted PR16 Guest entry; it is not another Worker. PID1 records the
child's exit/signal before poweroff. The receipt has six exact integer fields,
less than160 bytes, no exception text/traceback/prompt/path/token, atomic rename
and fsync. Read-only stopped-disk inspection checks exact device identity,
UID/GID, modes, links, size and canonical schema. Diagnostics are excluded from
candidate Git trees/snapshots and reserved against incoming source content.
Reviewer receives no diagnostic write capability.

These are **untrusted Guest diagnostic hints**, never completion, provenance of
code execution, or retirement authority. A Guest may lie about stage/errno.
SERIAL_OPERATION deliberately does not claim the first serial operation failed;
traceback classification cannot distinguish all operations. ENTRY_MAIN also
covers unclassified assignment/Git/TTY failures. Before the Developer task mount
(and for Reviewer), no durable record is available. Failed writes, pending files,
malformed data or expired inspection budget remain UNKNOWN. The tmpfs log still
disappears; no raw log is copied into the task or Worker UART.

Host natural exit now preserves the previously verified exact child identity
and terminal status across lookup/poll/group-snapshot races. Live ambiguity and
PID reuse still reject. Direct pre-READY serial EOF is recorded separately;
no receive pump means no pump-join proof. Optional diagnostic failure cannot
skip durable STOP_UNCERTAIN. Stop/wait, group, pipes, serial, threads and original
Owner accounting remain independent requirements.

New root/initramfs require a separately named immutable seven-artifact package,
SBOM/provenance and refreshed signed Helper preflight. Original artifacts and
both failed batches remain unchanged. Evidence and independent stage matrix:
`/Users/timmywen/Documents/AI_Colleague/evidence/q2-guest-pre-ready-rca-20261122`.
No normal QEMU, VM, Guest or Worker execution is authorized by this RCA. Any next
three-slot batch needs a fresh reviewed source/artifact/Helper binding, new
profile/reservations, Main Control review and a new Human grant. Old grants may
not be replayed. FIRST_WORKER_OWNED_DELIVERY remains NOT_ACHIEVED.

## Third Native failure: bounded offline bootstrap correction (7082116400)

The ac0b111 batch spent exactly one Developer slot and stopped without READY,
Worker receipt, inference or candidate. The third STOP_UNCERTAIN history joins
the two earlier histories unchanged and nonresumable. HVF destroy0, exact wait0,
empty group, closed pipes and actual serial EOF do not establish retirement.

Copies-only reconstruction binds all38 raw outputs, immutable SQLite backups,
actual root/task/assignment disks, frozen initramfs/kernel and baseline source.
Only operator entry, grant start and serial EOF have persisted monotonic times.
Child birth and QMP shutdown have wall times without a contemporaneous clock
bridge. Spawn/release/lookup/poll/wait exact monotonic timestamps are absent;
only source/stream partial ordering is proven. No runtime Q2_INIT_FAILURE marker
survived. Host q2_child_identity_unavailable does not identify the Guest stage
or which transient guard branch occurred. Guest stage remains UNKNOWN before
canonical READY. Task bytes/HEAD were unchanged and no diagnostic directory
survived; neither fact proves the failing operation.

Confirmed source defect: runtime mkdir/chown was required before enabling its
own failure recorder. This is a self-blind diagnostic prerequisite, not a proven
cause of the Native shutdown. The existing offline builder now provisions the
reserved empty Developer directory with mode0700; existing ext4 normalization
sets UID/GID1000. Both the static package and original Owner slot-device builder
use the same preparation function. Incoming reserved source paths remain
rejected, Git excludes the diagnostic path, and Reviewer has no such directory.
PID1 opens/validates the supplied directory after mounting task; it no longer
creates/chowns it as the prerequisite for enabling diagnostics.

Post-stop inspection distinguishes ABSENT, VALID_EMPTY (UNKNOWN, no receipt),
and VALID_RECEIPT (untrusted numeric hint only). Extra entries, bad ownership,
mode/link/type or malformed receipt reject. Candidate extraction validates then
excludes the reserved path, including a valid empty directory. An empty path or
a valid numeric receipt supplies no Worker-result or retirement authority.

Future Host lookup-disappearance observations record one contemporaneous poll
returncode, the exact saved identity/match, exception class, monotonic timestamp
and guard classification. None/unverified history still rejects; PID reuse and
live ambiguity remain closed. No historical branch is filled in retroactively.
Pre-READY EOF still cannot fabricate a receive-pump join or RETIRED.

New Guest bytes are separately frozen with SHA256/SBOM/provenance; previous
packages and three failed campaigns are never overwritten. The current signed
Helper is unchanged and not executed. Its bundled initramfs remains the old
package; it is not a binding for new Guest bytes. No fresh grant candidate or
profile execution is prepared by this offline correction. Any future qualified
binding requires a separate explicit decision. Early root transition, mounts,
assignment-role/task-mount and directory-validation failures can still precede
a usable task receipt; Reviewer remains intentionally read-only. No fourth VM
is authorized to resolve those unknowns. This bounded package ends after source,
artifact and evidence delivery, without claiming a specific Guest root cause.

## Early UART diagnostic prelude (Main Control 7082704659)

The pinned Debian6.12.107 arm64 config enables AMBA/PL011/TTY/OF/common-clock
built in. Reviewed kernel registration/init ordering, QEMU11.1.3 virt UART0 DT
(PL011 at0x09000000, serial0,24MHz clocks), and major204/minor64 support a static
initramfs `/dev/ttyAMA0` character entry before proc/sys/devtmpfs. newc encodes
this one0600 root-owned node directly; no privileged Host mknod is used. This is
SOURCE_VERIFIED feasibility, not a runtime-open or boot claim.

The exact original Owner hashes canonical endpoint.scope (sorted compact JSON,
no newline) and binds its64 lowercase hex bytes into the protected Helper plan
and exact QEMU argv as `HERMES_Q2_SCOPE_SHA256=...`. The pinned kernel forwards
an unrecognized no-dot NAME=value into init's environment; no `/proc/cmdline`
read is required. Console remains tty0, with no earlycon/unframed UART text.
The digest is non-secret and only binds an untrusted hint to the active scope;
it is not Guest code provenance or authority.

PID1 opens the same UART nonblocking/raw before root transition. Its boot fd is
at least4, survives root exec with a validated character-device identity and
sequence/env handoff, and remains owned even when diagnostics are disabled.
It never last-closes at root transition. Parent after fork relinquishes its
reference; the child enables CLOEXEC only after opening original Worker fd3.
The normal Worker receives neither the diagnostic fd nor scope/sequence env.

The existing4-byte big-endian length framing carries one exact canonical JSON
schema: boot=1, errno, failed, scope_sha256, seq, stage. Payload≤192 bytes,
sequence≤16, stage1..14, bounded integer errors, strictly ordered progress.
Progress follows each milestone; failure marks the attempted/current stage.
The C writer has a10ms deadline and finite I/O attempts per frame; missing UART,
clock/write failure disables diagnostics without calling Guest fail/reboot/exit.
The same pinned serial-core TX FIFO is4096 bytes (4KiB pages); all16*196 boot
bytes fit under the healthy initially-empty/sole-writer/raw/no-console assumptions.
This is conditional capacity evidence, not an atomic-write or delivery proof.
A physical partial-write timeout can damage the shared stream: Host must retain
sticky UNKNOWN and never scan/resynchronize into a purported successful RPC.
No transparency after physical transport loss is claimed.

| Stage | Progress fact if observed | Missing/failure boundary |
| --- | --- | --- |
| 1 | PID1 reached scope/UART/raw initialization | Kernel, exec, scope and initial UART-open failures remain unobservable |
| 2/3/4 | proc/sys/devtmpfs mount completed respectively | Failure hint labels attempted mount only |
| 5 | fixed modules loaded | Loader/module failure is numeric hint, not a root-cause oracle |
| 6/7 | root device observed/root mounted RO | Missing progress remains UNKNOWN |
| 8 | root exec reached new PID1 image | Same UART open description and seq survive switch |
| 9 | private runtime tmpfs mounts/directories completed | Grouped phase, not individual syscall trace |
| 10 | assignment mounted/read and role accepted | No raw assignment content crosses diagnostic frame |
| 11/12 | task mounted/role-specific diagnostic setup completed | Reviewer retains no disk write directory |
| 13 | stdio/limits/capability/UID setup completed | Cwd/nearby failure remains a bounded phase hint |
| 14 | about to exec accepted Python bootstrap | Does NOT prove Python import, entry or Worker READY |

BootSerialWire specializes the same existing SerialWire in the Host gateway
file; accepted agent/guest_serial.py and Guest RPCv2 bytes remain unchanged.
Only the existing deferred Owner service consumes prelude frames; the original
heartbeat pump starts after the first normal v2 frame. Prelude seq is separate:
normal first request/heartbeat remains seq1. Late boot frames, wrong scope,
sequence/stage gaps, extra/duplicate keys, oversized/noncanonical data reject.
There is no second UART reader, thread, transport or diagnostic store.

A required original-Owner callback persists hints in the existing Q2Attempt
namespace in both Board and SessionDB. Prefix-preserving updates retain them
through stale metadata updates/STOP_UNCERTAIN. A failed hint invokes existing
slot/batch failure handling. Progress+EOF, a missing frame or bad framing never
produces READY, Worker receipt, candidate authorization or RETIRED. Hints remain
untrusted; all physical, serial, thread and accounting evidence is independent.

Offline Ccodec vectors/partial/EINTR/EAGAIN/timeout/handoff tests, real socketpair
and original Owner service tests are not Guest execution. New artifacts and a
new signed Helper must bind this argv contract and be independently frozen.
Only two actual Helper no-VM preflight entries (one per role, plus existing
unrestricted calibrations) may run after independent safety review. QEMU normal
initialization/VM/Guest/Worker remain NOT_RUN. No new execution profile or Native
grant candidate is created. Three old failed grants stay STOP_UNCERTAIN and
nonresumable; old missing evidence and Guest root causes remain UNKNOWN.

## Fourth failure bounded offline review (Main Control 7085033964)

Guest root cause remains UNKNOWN. Preserved stages1/2/3 are untrusted progress
hints, not proof of a failed devtmpfs mount. Exact pinned config/source/newc and
argv support that mount path; stage4 can be missing after mount failure, UART
hint loss, or later unreported progress. No Guest source defect is established;
no Guest artifact or Helper rebuild, new grant/candidate or target run is part
of this offline package. All four historical STOP_UNCERTAIN records are immutable.

The original Host process observer may reconcile an already-verified child's
lookup-disappearance/poll-null window by calling wait on that same Popen only.
The wait is capped at250ms and the remaining caller deadline. Historical birth
identity and Popen PID must match; no signals, argv inference or replacement PID
are used. Timeout/unavailable wait remains UNKNOWN. The contemporaneous poll-null
and lookup classification remain preserved alongside the separate exact-wait
result. Actual exit is not retirement: all pipe, process-group, VM destroy,
Guest readiness, Owner accounting and existing final-proof gates still apply.

Serial observation distinguishes NOT_STARTED, STARTED_NOT_JOINED and
STARTED_AND_JOINED. A never-started pump retains receive_pump_joined=false.
Only a completed and observed original service Future, free synchronous I/O
lock, closed wire/descriptor and actual peer EOF can establish complete serial
transport quiescence without a pump. A local close cannot create peer EOF; a
pending/unbound service cannot create reader completion. A local-shutdown latch
excludes read-zero/EOF caused by our own SHUT_RDWR from peer-EOF evidence.
Started pumps retain
their joined-thread requirement. Existing joined-pump proofs remain compatible;
old missing-pump records gain no inferred facts or migration.

Transport quiescence does not authorize healthy Worker retirement: _valid_proof
still requires an actually joined pump, Guest READY, all original physical proof
and Owner accounting. Pre-READY EOF therefore retains logical UNKNOWN, even if
all transport resources are demonstrably quiescent. The fourth run did not
observe peer EOF, so its historical serial proof remains incomplete.

The bounded recommendation is to stop at these offline findings, not request a
fifth Native run merely to obtain another missing hint. Main Control must assess
whether a finite, evidence-supported product decision can close the remaining
Guest-readiness gap. Real D2/model/engineering delivery needs separate permission;
FIRST_WORKER_OWNED_DELIVERY remains NOT_ACHIEVED.
