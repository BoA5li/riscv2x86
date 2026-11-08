# Phase169：真实构建前置条件、候选位置与逐引用证据

基线：`phase168-external-link-contracts` / `6c6ca8bcb13c6c0673fb7fbc3ddbe72ee49b00df`。
分支：`phase169-native-validation-evidence`。

## 交付范围与完成状态

本轮修复原验证命令可以遗漏目标构建、仍继续执行入口/链接操作的问题，提供顺序执行和必需产物检查；增加有显式候选位置的v3链接请求；将原外部义务展开为可独立重放的逐引用账本，并采集实际源TU的编译器specs、宏、有效选项和依赖快照。

**完整外部合同方案尚未实施完成，五项阻塞仍未关闭。** 本轮不包含栈保护/fortify的机器行为证明、外部接口行为合同验证器、实际动态绑定观察、候选运行覆盖或native程序的完整L0–L3接入。源码中没有把这些能力设置为通过；旧requirements/provider清单保持原语义。

| 方案项目 | 本轮实际状态 |
|---|---|
| P0阶段驱动和前置失败传播 | 已实现；有实际子进程、后继停止、日志预算、超时和完整性反例 |
| P1有位置的候选链接 | 已实现显式槽位及独立链接/归因；尚未证明与原捕获链接中对象/归档成员的精确替换关系 |
| P2逐引用义务 | 已实现原始父义务守恒、每个引用字节见证和独立重派生；合同注册/行为验证尚未完成 |
| P3编译器机制 | 已实现实际TU配置采集与重放；没有从配置输出推导机制已经保持 |
| P4–P7运行绑定、行为合同、执行与整体验收 | 尚未完成；不得用本轮测试或acquisitionComplete替代 |

因此，不能将“本轮已提交”表述为“整个修订方案完成”。用户容器的GMP、glibc和原编译器产物不在本地环境；需要以下真实结果确定机制与部署事实。发现实际不相容时仍须失败，证据不足时仍须阻塞。

## 实现说明

`native_experiment_driver.py`：版本化计划；阶段专属新目录；绑定工具、显式输入、输出和日志；检查产物与输入闭合摘要；记录首个失败，后继全部保持not_run。每个子进程使用显式环境、无交互stdin和单独进程组。超时/管道日志预算超限终止整组，避免直接父进程退出后子进程继续占用管道。已有目录拒绝复用。`check-run`核验采集完整性，**不是独立执行重放或语义审计**。日志预算针对驱动捕获的stdout/stderr，既有构建器的内部日志仍由原构建器管理，不声称覆盖整个文件系统用量。

`advance_native_validation.py`：为当前GMP项目适配生成具体计划，顺序执行真实目标库、测试支持库和官方入口构建，再检查捕获记录并列出全部成功链接动作。不会按文件名猜测唯一入口，也不会执行make check或任意选择链接动作。项目名称和make目标仅为构建配置，通用验证器不以它们决定批准。

`native_link_evidence.py`：新增v3 `positionedInputs`，格式为file/group项与唯一 `{"candidate":true}`。请求、执行、独立重建和候选归因均支持v3；v1/v2不变。候选按该槽位参与真实链接，绝不为使链接成功自行移动顺序。该事实只生成 `candidateInputPositionVerified=true`，`capturedInputReplacementVerified=false`。未知选项、原命令转换、归档成员替换、隐式CRT/库选择依然未授权；禁止将任意原生GMP链接argv直接丢参数转换成示例计划。

`native_reference_ledger.py`：先重放原requirements/provider/dependency，再从根对象或原始归档成员字节重新派生引用；每条引用保留原父ID、函数归属、重定位和最多16字节的字节见证。该窗口不是解码后的指令，也不是指令长度。没有引用的父义务仍保留一行pending；没有唯一函数归属增加未解决证据，禁止猜测。禁止按五个名称放行。支持新目录独立replay，修改标志或位置并重算JSON身份仍被重新派生拒绝。

`native_compiler_configuration.py`：先重放真实构建记录、明确选择编译动作、验证现有compile-context，再运行实际代码生成编译器的版本、三元组、specs、sysroot、TU宏以及目标/优化器选项查询；两次原生依赖扫描包围观察，并核验源和编译器身份。未知影响编译语义的选项继续阻塞，不剥离。编译器wrapper/specs/宏的来源仍需结合实际生成指令分析，不能由宏输出代替机器机制证明。采集一致性不等于不可变沙箱或防并发ABA攻击。

## 用户主机验证：按顺序执行

### 1. 更新工具树，创建独立结果目录

保留已成功的phase168结果。以下变量沿用用户现有终端；缺少时停止，不能猜路径或填空值。

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${ARCHIVE_ROOT:?}" "${PHASE168_ROOT:?}"
git -C "$REPO" fetch origin phase169-native-validation-evidence
export PHASE169_TOOLING="$PREP_ROOT/tooling-phase169"
git -C "$REPO" worktree add --detach "$PHASE169_TOOLING" origin/phase169-native-validation-evidence
export PHASE169_ROOT="$(mktemp -d "$PHASE168_ROOT/phase169-XXXXXX")"
: "${PHASE169_ROOT:?创建实验目录失败}"
printf 'PHASE169_ROOT=%s\n' "$PHASE169_ROOT"
git -C "$PHASE169_TOOLING" rev-parse HEAD
```

若工具树已存在，不删除旧证据；使用一个新工具树路径并显式更新变量。

### 2. 回归

```bash
bash -e <<'VERIFY'
: "${PHASE169_TOOLING:?}" "${PHASE169_ROOT:?}"
export PYTHONPATH="$PHASE169_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
python3 -m pytest -q -rs \
  "$PHASE169_TOOLING/pytools/tests/test_project_build_profile.py" \
  "$PHASE169_TOOLING/pytools/tests/test_project_acquisition_driver.py" \
  "$PHASE169_TOOLING/pytools/tests/test_native_test_entry.py" \
  "$PHASE169_TOOLING/pytools/tests/test_native_link_evidence.py" \
  "$PHASE169_TOOLING/pytools/tests/test_native_link_attribution.py" \
  "$PHASE169_TOOLING/pytools/tests/test_native_external_requirements.py" \
  "$PHASE169_TOOLING/pytools/tests/test_native_external_providers.py" \
  "$PHASE169_TOOLING/pytools/tests/test_native_reference_ledger.py" \
  "$PHASE169_TOOLING/pytools/tests/test_native_experiment_driver.py" \
  "$PHASE169_TOOLING/pytools/tests/test_native_compiler_configuration.py" \
  "$PHASE169_TOOLING/pytools/tests/test_native_validation_cli.py" \
  --basetemp="$PHASE169_ROOT/pytest" --junitxml="$PHASE169_ROOT/focused.xml" \
  > "$PHASE169_ROOT/focused.log" 2>&1
VERIFY
VERIFY_STATUS=$?
printf 'phase169_test_status=%s\n' "$VERIFY_STATUS"
cat "$PHASE169_ROOT/focused.log"
```

预期测试全部通过；依赖真实主机回执/跨工具链的跳过项需按原因记录，不将skip当验证通过。phase168中的 `RV2X86_TEST_NATIVE_DEPENDENCIES` / `RV2X86_TEST_RUNTIME_BASIS` 可继续用于真实provider集成。

### 3. 一次执行缺失目标构建及后续证据采集

此步骤使用phase168已成功检查的真实profile和requirements。计划文件不执行构建；第二条run命令才启动。计划中明确包含构建，不再依赖手工记得执行BUILD块。

```bash
bash -e <<'ACQUIRE'
: "${PHASE169_TOOLING:?}" "${PHASE169_ROOT:?}" "${PHASE168_ROOT:?}" "${PREP_ROOT:?}" "${ARCHIVE_ROOT:?}"
export PYTHONPATH="$PHASE169_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
python3 "$PHASE169_TOOLING/experiment/advance_native_validation.py" prepare-target \
  --tooling "$PHASE169_TOOLING" --prep "$PREP_ROOT" --archives "$ARCHIVE_ROOT" \
  --profile "$PHASE168_ROOT/target-profile.json" \
  --requirements "$PHASE168_ROOT/requirements/result.json" \
  --timeout-seconds 3600 --output "$PHASE169_ROOT/target-plan.json" \
  > "$PHASE169_ROOT/prepare.log" 2>&1
python3 "$PHASE169_TOOLING/experiment/advance_native_validation.py" run \
  --plan "$PHASE169_ROOT/target-plan.json" --output "$PHASE169_ROOT/target-run" \
  > "$PHASE169_ROOT/acquisition.log" 2>&1
ACQUIRE
ACQUIRE_STATUS=$?
printf 'phase169_acquisition_status=%s\n' "$ACQUIRE_STATUS"
for name in prepare.log acquisition.log; do
  if test -f "$PHASE169_ROOT/$name"; then cat "$PHASE169_ROOT/$name"; fi
done
```

退出0只表示计划中的采集阶段完成，语义与生产验收字段始终false。退出2时查看首个失败，停止正式后续链接和验收。父目录/初始化失败只可能有stderr，不能要求不存在的子目录日志。

该计划依次执行：target-build → target-readiness → reference-ledger → reference-replay → source-compiler-configurations → source-compiler-replay。

| 文件 | 含义 |
|---|---|
| `target-run/run-status.json` | 外层所有阶段和首个失败，后继not_run |
| `target-run/target-build/stdout.log`、`stderr.log` | 实际构建命令的外层日志 |
| `target-run/target-build/gmp-target/run-status.json` | configure/build/测试构建/import/inspect等内部阶段及首个失败 |
| `target-run/target-build/gmp-target/records.json` | 目标库构建记录 |
| `target-run/target-build/gmp-target/test-records-0.json` | 测试支持库记录 |
| `target-run/target-build/gmp-target/test-records.json` | 官方入口构建记录 |
| `target-run/target-readiness/result.json` | 重放构建记录后取得的全部成功链接动作和入口元数据；仍需明确选择 |
| `target-run/reference-ledger/evidence/result.json` | 原父义务与逐引用证据 |
| `target-run/reference-replay/evidence/result.json` | 独立重派生回执 |
| `target-run/source-compiler-configurations/evidence/result.json` | 实际源编译配置观察；各动作子目录保留原始查询日志 |
| `target-run/source-compiler-replay/evidence/result.json` | 编译配置观察独立重放 |

当前五项清单预期父义务数5、逐引用数13，均仍pending；该数量是对当前输入的核对，不作为验证器硬编码。换输入时按实际义务派生。若记录发生变化应拒绝重放，不更新旧摘要冒充匹配。

```bash
bash -e <<'CHECK'
: "${PHASE169_TOOLING:?}" "${PHASE169_ROOT:?}"
python3 "$PHASE169_TOOLING/experiment/advance_native_validation.py" check-run \
  --input "$PHASE169_ROOT/target-run" > "$PHASE169_ROOT/integrity.log" 2>&1
CHECK
CHECK_STATUS=$?
printf 'phase169_integrity_status=%s\n' "$CHECK_STATUS"
cat "$PHASE169_ROOT/integrity.log"
```

`acquisitionIntegrityChecked=true`不表示独立执行、行为合同或完整程序验收已通过。

### 4. 独立采集源端诊断（目标构建失败时可用）

这两条命令没有目标构建依赖，仅用于诊断既有requirements与源端配置，不授权后续程序验收。使用新目录，已存在目录拒绝重用。

```bash
bash -e <<'SOURCE'
: "${PHASE169_TOOLING:?}" "${PHASE169_ROOT:?}" "${PHASE168_ROOT:?}"
python3 "$PHASE169_TOOLING/experiment/inspect_native_runtime_contracts.py" reference-ledger \
  --input "$PHASE168_ROOT/requirements/result.json" --output "$PHASE169_ROOT/source-reference-ledger" \
  > "$PHASE169_ROOT/source-reference-ledger.log" 2>&1
python3 "$PHASE169_TOOLING/experiment/advance_native_validation.py" compiler-configurations \
  --requirements "$PHASE168_ROOT/requirements/result.json" --output "$PHASE169_ROOT/source-configurations" \
  > "$PHASE169_ROOT/source-configurations.log" 2>&1
SOURCE
SOURCE_STATUS=$?
printf 'source_diagnostic_status=%s\n' "$SOURCE_STATUS"
for name in source-reference-ledger.log source-configurations.log; do
  if test -f "$PHASE169_ROOT/$name"; then cat "$PHASE169_ROOT/$name"; fi
done
```

### 5. v3候选位置链接能力

只有取得真实底层链接动作并确定部署关系之后才能构造计划。格式示例仅说明语法：

```json
[
  {"file":"/actual/test-driver.o"},
  {"group":"start"},
  {"candidate":true},
  {"file":"/actual/support.a"},
  {"group":"end"}
]
```

不能将这些路径当可执行输入，也不能由示例推定GMP只需要这两个依赖。实际原命令含未支持选项、响应文件或脚本时保留阻塞。候选仍在原支持归档中时，必须先形成有来源的派生归档/精确替换证据；本轮没有实现它，不得绕过。

将实际审阅计划保存为JSON文件后，使用 `inspect_native_runtime_contracts.py link-request --positioned-inputs 实际计划.json`；其它参数沿用真实candidate、side和compiler。随后使用已有link、audit-link、attribute-link子命令。旧 `--ordered-inputs` 仍是v2固定前置语义，不能混用两个参数。

## 验收与待返回材料

本轮能力验收：新旧专项通过；实际目标构建的失败/成功有准确回执；13条引用与5个父义务保留；源端配置可重放；v3请求按指定位置执行和归因。上述全部通过也不能将五项行为义务清零。

下一阶段需要：`focused.log`、外层和构建内部run-status、目标readiness/result.json、逐引用result.json、源配置result.json及其specs/macros/target-options/optimizer-options日志。若失败，先提供首个失败状态和对应日志；不要求再次全文搜索或重复无关采集。

五项真正关闭仍要求：有效机器机制合同、双端类型/ABI/对象/I/O/终止合同、实际源/目标链接与运行选择、翻译实例执行、全部适用L0–L3及独立程序审计。没有这些证据时，保留blocked是正确结论，不能通过编辑JSON、放宽要求或桩函数改写来通过。

## 本地验证记录

最终project/native回归：480 passed、9 skipped（43.31秒）。9项跳过需要真实Clang、RISC-V GCC、前端或用户主机依赖/运行库回执。测试覆盖真实native GNU链接及独立重建、候选位置改变归档选择、实际GCC配置观察、逐引用派生、阶段失败/超时/日志预算/完整性拒绝和CLI。本文Bash块全部通过bash -n，git diff --check通过。没有运行用户容器、真实RV64 GMP、实际动态绑定或程序级L0–L3。
