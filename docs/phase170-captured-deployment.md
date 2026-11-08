# Phase170：捕获链接的精确替换、隔离部署与自动引用诊断

这是phase170历史用法。phase171新增正式部署审计前置及观察v2，使用新代码时请遵循
[phase171验证文档](phase171-observation-integrity.md)，不要混用旧deploy参数。

基线：`phase169-native-validation-evidence`，远端提交
`de6210a744fb8409ffd7de1cde873ff14c8d4ea7`。
交付分支：`phase170-native-deployment-closure`。

## 完成范围和未完成范围

**本轮没有完成整个外部合同方案，不能宣布原有五项阻塞已关闭。**
已实现真实捕获重放、唯一直接对象定位、精确替换、派生DSO与入口重链接、
GNU/bfd定义贡献归因、LOAD输入盘点、完整ELF字节独立重建、自动源端诊断、
加载器选库诊断和分开的自然/诊断执行。

未实现通用机器行为证明器、双端外部类型/对象/可变参数/I/O/终止合同验证器、
目标TU重构及部署上下文重新证明、自然运行完整加载/绑定闭包、候选指令覆盖、
真实GMP的L0–L3整体验收。因此三个总批准字段继续false；这是明确的能力边界，
不是已完成方案的全通过实现。

| 字段 | 具体含义 |
|---|---|
| capturedInputReplacementVerified | 已确认捕获链接输入槽位与唯一生产动作，执行时只替换该直接对象输入 |
| candidateDefinitionAttributionVerified | 从独立对象及GNU/bfd map重派生的链接时贡献归因 |
| capturedBaselineBytesReproduced | 未替换基线与捕获产物完整字节相同 |
| independentDeploymentRebuildComplete | 新目录重新链接，四个ELF全部完整字节相同；不删除build-id或归一化产物差异 |
| loaderListSelectionVerified | 显式解释器--list调用选择了预期派生DSO；不是自然运行观察 |
| testExecutionPerformed | 自然执行请求实际发起且完成采集；退出码另列，不代表测试通过或候选执行覆盖 |
| runtimeLibrarySelectionVerified | 尚未证明自然运行的完整对象身份和绑定，保持false |
| targetDependencyLinkClosureComplete | 尚缺隐式输入/绑定及适用合同闭包，保持false |
| externalContractClosureComplete | 尚缺行为合同验证器，保持false |

退出0仅表示当前证据操作完成。非零程序退出码照实记录，绝不改成测试通过。
只有诊断选库不符、捕获/产物改变、链接失败、未知选项或预算超限才导致相应采集拒绝。
原requirements与provider不会被修改；每个旧义务仍保留。

## 方法与适用范围

`native_captured_deployment.py`：不按GMP、函数或对象文件名批准。先以完整定义签名
定位唯一直接对象，再按路径、摘要、生产动作和时间顺序确定构建变体。PIC/非PIC
即使字节相同，也不会因摘要相同被合并。此选择不是翻译实例语义对应证明；相应字段false。
若有多个库/入口，可用动作ID选择；不得任意取第一个。归档可作为依赖，但归档成员替换
暂不支持，禁止自动抽出成员、前置候选或丢弃选项绕过。

支持已枚举的GNU驱动参数、显式ELF/普通归档输入、分开的-o、soname和绝对rpath。
参数顺序、重复操作数、优化/保护选项和隐式驱动默认均保留。
响应文件、链接脚本、未知选项及其他链接器语义拒绝。已观察的LOAD指令只形成输入盘点，
不宣称已解析链接脚本和所有驱动子程序。没有为使测试通过追加-z defs或关闭保护。

基线和派生操作都写新目录。派生DSO保持SONAME；入口中每个指向原DSO的别名操作数
都在原位置替换。显式记录部署差异：在原搜索路径前加入字面量`$ORIGIN/lib`。
这不是原始链接等价声明；保留旧路径使潜在回退仍可被诊断，实际选错库会拒绝观察。
LD_LIBRARY_PATH不被偷偷清空。普通直接对象定义归因不等于动态抢占/IFUNC/TLS语义证明。

`native_reference_inspection.py`：重放原ledger，再从生产记录读取对象路径，自动采集
配置、反汇编、符号/节、预处理定义。配置/依赖观察包围预处理，对象/工具前后核验。
常量按ELF符号索引、节和受支持的绝对重定位解析，不匹配.LC名称；PC相对重定位不会
被当作无偏移绝对地址。输出的是字节见证，不是格式/指针/类型合法性证明。
根对象没有原生生产动作或存在歧义时保留unresolved。

`native_deployment_observation.py`：先检查部署证据，使用入口的解释器--list；
只有预期SONAME唯一解析到派生库的正确路径与摘要才允许后续执行。自然执行与
LD_DEBUG=files,bindings,versions诊断分开，不设置LD_BIND_NOW，不将两者等同。
支持旧glibc没有--version的情况，将该查询失败保存为能力观察。
输出实际观察的绑定及未解析行；不把未出现的绑定当通过，不进行IFUNC或lazy binding模拟。
未支持的预加载/审计/调试环境明确拒绝。日志预算和超时复用进程组终止逻辑。

`check`是证据一致性重派生；`replay`才实际重新链接。
这些都不是对恶意并发替换、ABA攻击或被攻陷工具链的防护。

## 容器验证：逐步执行，失败时停止

所有步骤使用新目录，不覆盖phase168/169。不要在失败后继续正式后继操作。

### 1. 获取工具并建立新结果目录

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE168_ROOT:?}" "${PHASE169_ROOT:?}"
git -C "$REPO" fetch origin phase170-native-deployment-closure
export PHASE170_TOOLING="$PREP_ROOT/tooling-phase170"
git -C "$REPO" worktree add --detach "$PHASE170_TOOLING" origin/phase170-native-deployment-closure
export PHASE170_ROOT="$(mktemp -d "$PHASE169_ROOT/phase170-XXXXXX")"
export PYTHONPATH="$PHASE170_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
git -C "$PHASE170_TOOLING" rev-parse HEAD
printf 'PHASE170_ROOT=%s\n' "$PHASE170_ROOT"
```

工具树已存在时换用新路径，不删除旧工具树或结果目录。

### 2. 回归测试

```bash
python3 -m pytest -q -rs \
  "$PHASE170_TOOLING"/pytools/tests/test_project_*.py \
  "$PHASE170_TOOLING"/pytools/tests/test_native_*.py \
  --junitxml="$PHASE170_ROOT/regression.xml" \
  > "$PHASE170_ROOT/regression.log" 2>&1
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
tail -n 25 "$PHASE170_ROOT/regression.log"
```

状态0后继续；skip按原因列出，不能算实际跨工具链验证成功。

### 3. 自动准备真实捕获链接计划

```bash
python3 "$PHASE170_TOOLING/experiment/advance_native_closure.py" prepare \
  --requirements "$PHASE168_ROOT/requirements/result.json" \
  --library-records "$PHASE169_ROOT/target-run/target-build/gmp-target/records.json" \
  --test-records "$PHASE169_ROOT/target-run/target-build/gmp-target/test-records.json" \
  --output "$PHASE170_ROOT/deployment-plan.json" \
  > "$PHASE170_ROOT/prepare.log" 2>&1
PREPARE_STATUS=$?
printf 'prepare_status=%s\n' "$PREPARE_STATUS"
cat "$PHASE170_ROOT/prepare.log"
```

candidate从requirements→provider→dependency链定位，验证摘要和身份；不猜实验目录。
自动选择必须唯一。歧义时回传错误，检查实际动作后显式传--library-action/--entry-action，
不能通过改名、按字节相等挑选或删除其他记录消除歧义。

### 4. 独立复核原候选

```bash
python3 "$PHASE170_TOOLING/experiment/advance_native_closure.py" audit-candidate \
  --plan "$PHASE170_ROOT/deployment-plan.json" \
  --output "$PHASE170_ROOT/candidate-audit" --timeout-seconds 600 \
  > "$PHASE170_ROOT/candidate-audit.log" 2>&1
CANDIDATE_AUDIT_STATUS=$?
printf 'candidate_audit_status=%s\n' "$CANDIDATE_AUDIT_STATUS"
cat "$PHASE170_ROOT/candidate-audit.log"
```

须成功且nativeCandidateIndependentAuditComplete=true才正式继续。
复用已有局部整数候选审计，不把它扩张为目标部署上下文、完整函数或程序级批准。

### 5. 执行基线与派生链接

```bash
python3 "$PHASE170_TOOLING/experiment/advance_native_closure.py" deploy \
  --plan "$PHASE170_ROOT/deployment-plan.json" \
  --output "$PHASE170_ROOT/deployment" --timeout-seconds 600 \
  > "$PHASE170_ROOT/deploy.log" 2>&1
DEPLOY_STATUS=$?
printf 'deploy_status=%s\n' "$DEPLOY_STATUS"
cat "$PHASE170_ROOT/deploy.log"
```

失败时看deployment/run-status.json、commands.json及失败阶段stderr.log；后继不执行。
成功时预期精确替换、两个重链接和定义归因通过。基线字节不复现时保留阻塞，不能忽略。
这一步允许诊断性重链接已有candidate target.o，但不会重新编译或认可PIC/完整ABI兼容。
若链接失败，需要继续修订目标TU和候选部署证明，不能临时加-fPIC重编译并沿用旧证明。

### 6. 一致性检查及实际独立重链接

```bash
python3 "$PHASE170_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE170_ROOT/deployment/result.json" \
  > "$PHASE170_ROOT/deployment-check.log" 2>&1
CHECK_STATUS=$?
printf 'deployment_check_status=%s\n' "$CHECK_STATUS"
cat "$PHASE170_ROOT/deployment-check.log"
```

```bash
python3 "$PHASE170_TOOLING/experiment/advance_native_closure.py" replay \
  --input "$PHASE170_ROOT/deployment/result.json" \
  --output "$PHASE170_ROOT/deployment-replay" --timeout-seconds 600 \
  > "$PHASE170_ROOT/replay.log" 2>&1
REPLAY_STATUS=$?
printf 'replay_status=%s\n' "$REPLAY_STATUS"
cat "$PHASE170_ROOT/replay.log"
```

退出0还须检查independentDeploymentRebuildComplete=true；false表示字节不能重现，
需要分析差异，不按任意归一化规则通过。

### 7. 自动源端诊断，代替逐文件人工采集

```bash
python3 "$PHASE170_TOOLING/experiment/advance_native_closure.py" inspect-source \
  --requirements "$PHASE168_ROOT/requirements/result.json" \
  --objdump /usr/bin/riscv64-linux-gnu-objdump \
  --output "$PHASE170_ROOT/source-inspection" --timeout-seconds 300 \
  > "$PHASE170_ROOT/source-inspection.log" 2>&1
INSPECT_STATUS=$?
printf 'source_inspection_status=%s\n' "$INSPECT_STATUS"
cat "$PHASE170_ROOT/source-inspection.log"
```

目录按动作生成，不按sqr_basecase/assert命名。输入仍相同时预期保留5父义务13引用；
这两个数量不写入验证器。检查objects中的配置、常量见证和所有原始日志。
externalContractClosureComplete仍false，机器证明和行为合同不会由采集自动批准。

### 8. 加载诊断与自然/诊断执行

只有前述步骤符合要求才继续。此处运行的是派生入口，不是原始t-powm。

```bash
python3 "$PHASE170_TOOLING/experiment/advance_native_closure.py" observe \
  --input "$PHASE170_ROOT/deployment/result.json" \
  --output "$PHASE170_ROOT/observation" --diagnostic --timeout-seconds 600 \
  > "$PHASE170_ROOT/observation.log" 2>&1
OBSERVE_STATUS=$?
printf 'observation_status=%s\n' "$OBSERVE_STATUS"
cat "$PHASE170_ROOT/observation.log"
```

```bash
python3 "$PHASE170_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE170_ROOT/observation/result.json" \
  > "$PHASE170_ROOT/observation-check.log" 2>&1
OBSERVATION_CHECK_STATUS=$?
printf 'observation_check_status=%s\n' "$OBSERVATION_CHECK_STATUS"
cat "$PHASE170_ROOT/observation-check.log"
```

须分别检查选库诊断、自然执行退出码/输出、诊断绑定和未解析行。不得仅以observe退出0
判断官方测试通过。即使测试退出0，也不能证明候选函数或每个汇编实例已经执行。

## 回传和后续工作

先回传regression.log、prepare.log、candidate-audit.log、deploy.log。
链接失败附run-status.json和对应stderr.log；成功再回传deployment/result.json、
deployment-replay/replay.json、source-inspection/result.json、observation/result.json。
不用再次手工逐个复制原宏、specs和反汇编，自动诊断目录已经保留它们。

后续必须实施：真实部署上下文和target TU重构/重新证明、通用机器行为分析与类型/效果
合同验证、自然运行对象/绑定身份、候选覆盖、程序级L0–L3与独立审计。
本轮不把任何缺失证明改成可信假设，也不加入五个符号的名称白名单。

## 本地验证

新增14项测试使用真实GCC捕获、共享库/入口链接、完整字节重建、GNU加载器和子进程。
覆盖重复库别名、错误槽位、未知选项、原输入变化、重新计算JSON身份后的虚假批准、
错误库覆盖拒绝、失败状态、自动常量解析及配置采集。
源端诊断测试仅对旧跨ISA ledger边界使用夹具，GCC/objdump/预处理实际执行；
不声称本地运行了真实RISC-V GMP。完整project/native回归：494 passed、9 skipped（57.34秒）；
skip需要真实Clang、RISC-V GCC、前端或用户主机回执。专项87 passed、1 skipped。
文档10个Bash代码块通过bash -n。没有执行用户容器的真实GMP实验。
