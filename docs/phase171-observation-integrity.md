# Phase171：观察证据重派生与部署前置检查

基线：phase170-native-deployment-closure / 5229bdec18d8ebe0637b40ce03caa0251bdc06ae。
交付分支：phase171-observation-evidence-integrity。

## 实验发现与修订范围

用户提供的动态表确认入口具有DF_BIND_NOW/DF_1_NOW，并存在三项COPY重定位：
stderr、__gmp_rands、__gmp_rands_initialized。因此，启动绑定不是调用覆盖；数据
初始化来源与最终存储位置必须分开。GMP DSO自身的绑定时机应按自身标志分析，不能
把入口NOW标志无条件传播到所有库。这些名称和地址只用于说明当前材料，不用于批准。

本轮修复四项实现问题：

1. v2观察报告从原始日志、执行计划和逐命令回执完整重派生。删除绑定、改返回码或
   修改报告中的阶段标志后，仅重算JSON身份不能通过check。保留PID、命名空间、重复
   事件和版本。日志解析与核验使用同一实现，不维护第二套宽松解释器。
2. 正式deploy必须提供新audit-candidate生成的deployment-audit.json，核验计划/
   候选身份、实际审计状态、独立重建、证明/工具/绑定产物和验证代码身份。失败审计、
   不匹配回执、单个成功布尔值不能通过。诊断部署必须显式--diagnostic-only，报告
   保留该模式及缺失前置，不能改成程序级批准。
3. ELF字节自动派生NOW标志、动态重定位和COPY存储/初始化候选。按机器选择重定位
   语义，不匹配stderr或GMP名称。类型/大小/版本候选不等于真实初始化选择或行为证明。
4. 统一结果目录检查，拒绝直接写根目录。加载器版本查询失败作为能力观察保存；
   不按127或错误字符串认定具体发行版，也不把可选版本查询失败算作目标程序失败。

同时修复重放产物目录问题：replay摘要写在重建目录之外，避免后加replay.json使已
封存的清单失效。部署重放新产物位于OUTPUT/rebuild；观察重放新产物位于OUTPUT/run。

虚拟/非文件对象被归为loader-label，语法解析成功与身份未验证分开，不能因名称类似
vdso而放行。真正的内核虚拟对象身份仍需要同次进程的映射/辅助向量等证据。本轮
没有伪造这种证据，也没有把它归入文件摘要验证。

## 证明范围

* check：对已有原始材料和采集回执重新推导报告的一致性，不是重新执行。
* replay-observation：实际再次执行，比较自然运行返回码、预算状态、stdout/stderr摘要。
  不要求含PID/ASLR/LD_DEBUG的原始日志相等，也不借此宣称绑定完备或语义一致。
* 执行回执记录退出码；退出码不能从stdout/stderr反推出。若攻击者同时伪造所有原始
  日志、回执和摘要，普通内容哈希无法证明采集真实性。本轮不宣称对抗被攻陷的采集器。
* 文件对象快照不是同次进程映射身份。自然运行完整绑定、候选指令覆盖、外部类型/
  合法对象/I/O/终止合同及L0–L3仍未完成；对应批准字段保持false。
* 成功的候选审计仅为已有局部证明的前置条件，不扩张成共享库部署ABI或完整函数证明。

原始旧deployment/plan仍可检查和作为重新观察的输入；旧观察v1没有逐命令回执，check会
明确要求重新采集v2，不能通过改schema升级。旧文件不覆盖、不删除。
旧phase170的replay目录若已额外写入replay.json，其封存清单不再一致；不要忽略该文件
放行，应从原始deployment用新replay重新生成。
新API execute默认要求audit_path；单独试验需diagnostic_only=True。CLI参数同理。

## 验证：分步运行，失败停止

### 1. 获取工具和结果目录

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE170_ROOT:?}"
git -C "$REPO" fetch origin phase171-observation-evidence-integrity
export PHASE171_TOOLING="$PREP_ROOT/tooling-phase171"
git -C "$REPO" worktree add --detach "$PHASE171_TOOLING" origin/phase171-observation-evidence-integrity
export PHASE171_ROOT="$(mktemp -d "$PHASE170_ROOT/phase171-XXXXXX")"
: "${PHASE171_ROOT:?Failed to create experiment directory}"
export PYTHONPATH="$PHASE171_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
git -C "$PHASE171_TOOLING" rev-parse HEAD
printf 'PHASE171_ROOT=%s\n' "$PHASE171_ROOT"
```

若工具目录已存在，换用新路径。CLI还会检查输出位置，变量意外为空时拒绝根目录输出。

### 2. 回归及拒绝反例

```bash
python3 -m pytest -q -rs \
  "$PHASE171_TOOLING"/pytools/tests/test_project_*.py \
  "$PHASE171_TOOLING"/pytools/tests/test_native_*.py \
  --junitxml="$PHASE171_ROOT/regression.xml" \
  > "$PHASE171_ROOT/regression.log" 2>&1
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
tail -n 25 "$PHASE171_ROOT/regression.log"
```

必须状态0；skip列原因，不当作实际跨工具链证明。新测试覆盖重新计算身份后的删绑定、
改退出码、改阶段、改动态义务；命令回执不匹配；无审计禁止正式部署；任意名称COPY
数据对象；NOW标志；PID/命名空间/重复/标签分类；可选版本失败；独立再次运行。
审计前置的协议集成使用明确的跨ISA审计边界夹具，本地不冒充真实RV64候选证明。

### 3. 新候选审计回执

沿用已经绑定的/deployment-plan.json。新审计会实际重新运行旧局部候选独立审计，
并生成正式部署需要的新回执；不是给旧audit.json套一个成功标志。

```bash
python3 "$PHASE171_TOOLING/experiment/advance_native_closure.py" audit-candidate \
  --plan /deployment-plan.json \
  --output "$PHASE171_ROOT/candidate-audit" --timeout-seconds 600 \
  > "$PHASE171_ROOT/candidate-audit.log" 2>&1
AUDIT_STATUS=$?
printf 'audit_status=%s\n' "$AUDIT_STATUS"
cat "$PHASE171_ROOT/candidate-audit.log"
```

状态0且nativeCandidateIndependentAuditComplete=true后才继续。新文件：
candidate-audit/deployment-audit.json。失败不会产生可用于正式部署的成功回执。

### 4. 带前置验证的正式重链接

```bash
python3 "$PHASE171_TOOLING/experiment/advance_native_closure.py" deploy \
  --plan /deployment-plan.json \
  --audit "$PHASE171_ROOT/candidate-audit/deployment-audit.json" \
  --output "$PHASE171_ROOT/deployment" --timeout-seconds 600 \
  > "$PHASE171_ROOT/deploy.log" 2>&1
DEPLOY_STATUS=$?
printf 'deploy_status=%s\n' "$DEPLOY_STATUS"
cat "$PHASE171_ROOT/deploy.log"
```

无--audit会被CLI拒绝；不存在或不匹配的回执会在链接前拒绝。不要改用诊断模式绕过
失败的正式验证。诊断模式仅用于明确标注的实现诊断，不能进入正式验收。

```bash
python3 "$PHASE171_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE171_ROOT/deployment/result.json" \
  > "$PHASE171_ROOT/deployment-check.log" 2>&1
CHECK_STATUS=$?
printf 'deployment_check_status=%s\n' "$CHECK_STATUS"
cat "$PHASE171_ROOT/deployment-check.log"
```

### 5. 采集v2观察

```bash
python3 "$PHASE171_TOOLING/experiment/advance_native_closure.py" observe \
  --input "$PHASE171_ROOT/deployment/result.json" \
  --output "$PHASE171_ROOT/observation" --diagnostic --timeout-seconds 600 \
  > "$PHASE171_ROOT/observation.log" 2>&1
OBSERVE_STATUS=$?
printf 'observation_status=%s\n' "$OBSERVE_STATUS"
cat "$PHASE171_ROOT/observation.log"
```

每个阶段都有execution.json、stdout.log、stderr.log，计划位于execution-plan.json。
加载器版本查询可能仍127，但报告必须显示versionQuerySucceeded=false，不声称版本
查询成功。自然/诊断执行的退出码分别检查，退出0仅为指定入口运行结果。

```bash
python3 "$PHASE171_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE171_ROOT/observation/result.json" \
  > "$PHASE171_ROOT/observation-check.log" 2>&1
OBS_CHECK_STATUS=$?
printf 'observation_check_status=%s\n' "$OBS_CHECK_STATUS"
cat "$PHASE171_ROOT/observation-check.log"
```

检查完整result.json：binding events的PID/命名空间/顺序；unparsedBindingLines语法
问题；unverifiedObjectBindings身份问题；dynamicObligations中的NOW/COPY关系。
虚拟对象即使语法解析成功，仍应身份未验证，不能把它的未解决项删除。

### 6. 实际重放

```bash
python3 "$PHASE171_TOOLING/experiment/advance_native_closure.py" replay-observation \
  --input "$PHASE171_ROOT/observation/result.json" \
  --output "$PHASE171_ROOT/observation-replay" --timeout-seconds 600 \
  > "$PHASE171_ROOT/observation-replay.log" 2>&1
OBS_REPLAY_STATUS=$?
printf 'observation_replay_status=%s\n' "$OBS_REPLAY_STATUS"
cat "$PHASE171_ROOT/observation-replay.log"
```

退出0仍需检查naturalObservationReproduced=true。false保留实际差异，不能丢弃输出
后重算为通过。重放报告：observation-replay/replay.json；新观察：
observation-replay/run/result.json，可再次运行check。

```bash
python3 "$PHASE171_TOOLING/experiment/advance_native_closure.py" replay \
  --input "$PHASE171_ROOT/deployment/result.json" \
  --output "$PHASE171_ROOT/deployment-replay" --timeout-seconds 600 \
  > "$PHASE171_ROOT/deployment-replay.log" 2>&1
DEPLOY_REPLAY_STATUS=$?
printf 'deployment_replay_status=%s\n' "$DEPLOY_REPLAY_STATUS"
cat "$PHASE171_ROOT/deployment-replay.log"
```

须independentDeploymentRebuildComplete=true。新部署位于deployment-replay/rebuild/
result.json，replay摘要在外层，不破坏其清单，可再次check。

## 回传与后续阶段

先提供regression.log、candidate-audit.log、deploy.log、observation.log。任何失败
先提供该阶段执行回执/日志，不继续正式后继。成功后提供新observation/result.json和
两个replay摘要。无需再人工逐个导出specs/宏/反汇编。

这些验证完成后，继续推进合法对象/接口/输出/终止合同和候选执行覆盖。
本轮修复观察和部署前置的已知错误，不宣布原五项语义义务或全部L0–L3已经完成。

## 本地验证记录

project/native回归：513 passed、9 skipped（141.29秒）。最终部署/观察专项：
34 passed（75.15秒），包含后续新增CLI和严格字段检查。
9项跳过需要真实Clang、RISC-V GCC、前端或用户主机回执。
本文9个Bash代码块通过bash -n。没有执行用户容器的真实GMP，也没有把协议边界夹具
当作真实跨ISA候选审计或行为证明。
