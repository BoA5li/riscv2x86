# Phase186：修复原后端启动阻塞并顺序执行候选链

基线：phase185-original-pipeline-adapter，66c80853d230bea75d73d04d881c72dda62c143d。

## 依据与范围

已提供的实际记录显示：Phase185 的 74 项定向测试通过；真实输入 prepare/check 完成；
随后因 GHIDRA_INSTALL_DIR 为空，translate 收到显式空参数，在寄存器解析器启动时失败，
没有产生翻译结果。后续缺文件是连带错误，不能据此判定原翻译后端已经执行或等价验证失败。
用户实际找到的安装启动器为 /opt/ghidra_11.2_PUBLIC/support/pythonRun。

本轮修订：

| 问题 | 实施 | 验证边界 |
|---|---|---|
| 空配置、相对路径与工作目录混淆 | 统一配置选择：显式选项、环境、既有默认；显式空值拒绝；执行前规范化并检查可执行启动器 | 不猜测其他安装，不自动降级到另一翻译路线 |
| 查询与运行时安装选择分离 | 原 CLI 传播已解析安装；项目启动的运行时和缓存语言拒绝切换安装 | 不声称检测了项目外预先启动的 JVM |
| 缺少真实启动预检 | 执行原公开 CLI 的 --help 导入检查，再执行既有 pythonRun 寄存器查询 | 不代表 p-code lifting、候选生成或程序等价已通过 |
| 查询进程无界、返回数据信任过宽 | 复用有界进程组驱动；保存命令/输出/工具身份；严格解析 RV64 寄存器元数据并重派生 | 超时、非零返回、错误元数据均失败 |
| 上游失败后继续 audit/check | 新 run 按预检、prepare、原 CLI、原回填、独立重跑审计顺序执行 | 非零返回或 unsupported/needs_route/failed 均停止，不回退旧整数路线 |
| 检查失败仍留下貌似完整的 result | 正常检查器通过后原子发布新结果；失败保留状态和日志 | 不覆盖旧实验结果，不修改语义批准条件 |

原生编译上下文保持原记录；Java/HOME/locale 等后端工具环境另行捕获并绑定。
独立审计使用同一记录的后端环境，避免调用者的新 Shell 状态改变配方。

原始宏修改权限、完整机器 ABI、内部对象访问证明、规范实例指令执行覆盖、程序级合同及
完整 L1–L3 证据生产/整体闭合仍未实现。本轮保持这些结论为未知/未完成。
不要求先把整个 GMP 的 466 个 C 上下文全部形式化，再执行原后端候选生成。

## 1. 更新并建立新目录

在原 .venv-l2 环境逐段执行。每段失败后停止依赖它的操作。

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE185_ROOT:?}"
git -C "$REPO" fetch origin phase186-ghidra-preflight
export PHASE186_TOOLING="$PREP_ROOT/tooling-phase186"
git -C "$REPO" worktree add --detach "$PHASE186_TOOLING" origin/phase186-ghidra-preflight
export PHASE186_ROOT="$(mktemp -d "$PHASE185_ROOT/phase186-XXXXXX")"
: "${PHASE186_ROOT:?}"
export PYTHONPATH="$PHASE186_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE186_ORIGINAL="$PHASE186_TOOLING/experiment/run_native_original.py"
git -C "$PHASE186_TOOLING" rev-parse HEAD
printf 'PHASE186_ROOT=%s\n' "$PHASE186_ROOT"
```

旧 prepare 绑定旧验证器源码，不能交给新检查器后强行忽略身份差异。
下面的 run 会从同一真实输入 bundle 重新 prepare；不会修改旧收据。

## 2. 指定已经找到的真实安装并回归

```bash
export GHIDRA_INSTALL_DIR=/opt/ghidra_11.2_PUBLIC
test -x "$GHIDRA_INSTALL_DIR/support/pythonRun"
```

test 非零时先停止并检查该真实路径；不要继续传空参数。

```bash
export RV2X86_REAL_GHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR"
python3 -m pytest -q -rs \
 "$PHASE186_TOOLING/pytools/tests/test_ghidra_configuration.py" \
 "$PHASE186_TOOLING/pytools/tests/test_ghidra_preflight.py" \
 "$PHASE186_TOOLING/pytools/tests/test_ghidra_cli_selection.py" \
 "$PHASE186_TOOLING/pytools/tests/test_checked_result_publication.py" \
 "$PHASE186_TOOLING/pytools/tests/test_native_original_pipeline.py" \
 "$PHASE186_TOOLING/pytools/tests/test_register_read_views.py" \
 "$PHASE186_TOOLING/pytools/tests/test_phase4_privileged_cli_ingress.py" \
 --basetemp="$PHASE186_ROOT/pytest-focused" > "$PHASE186_ROOT/focused.log" 2>&1
PHASE186_STATUS=$?
printf 'focused_status=%s\n' "$PHASE186_STATUS"
cat "$PHASE186_ROOT/focused.log"
```

显式设置 RV2X86_REAL_GHIDRA_INSTALL_DIR 后，真实查询失败会报错，不会自动跳过。
其余合成启动器/前端夹具测试仅验证协议和接线，不能计为 GMP 翻译或真实 Ghidra 实验。
两个旧特权 CLI 测试夹具已补齐现行注册表协议与候选模式，并新增缺字段拒绝测试；生产校验未放宽。

## 3. 顺序执行原候选生成和独立审计

复用上一轮已定位的真实 bundle。变量丢失时，从已有真实 candidate 收据恢复：

```bash
: "${PHASE185_CANDIDATE:?需要上一轮真实候选收据路径}"
export PHASE185_BUNDLE="$(python3 -c 'import json,os; print(json.load(open(os.environ["PHASE185_CANDIDATE"]))["bindingBundlePath"])')"
: "${PHASE185_BUNDLE:?}"
ls -lh -- "$PHASE185_BUNDLE"
```

若 PHASE185_BUNDLE 已有正确值，直接执行下面一段即可，无需重复恢复。

```bash
python3 "$PHASE186_ORIGINAL" run --bundle "$PHASE185_BUNDLE" \
 --ghidra-install-dir "$GHIDRA_INSTALL_DIR" \
 --output "$PHASE186_ROOT/original-run" --timeout-seconds 600 \
 > "$PHASE186_ROOT/original-run.log" 2>&1
PHASE186_STATUS=$?
printf 'original_run_status=%s\n' "$PHASE186_STATUS"
cat "$PHASE186_ROOT/original-run.log"
```

run 只调用原 cli/pipeline、原 candidate_materialization，以及独立重导出前端和重跑原后端的审计。
--skip-verify 仍是原 CLI 的待外部验证候选模式；语义证明门和后续评估准入保持原要求。

返回 0 且存在最终 result.json 后再执行：

```bash
python3 "$PHASE186_ORIGINAL" check --input "$PHASE186_ROOT/original-run/result.json"
cat "$PHASE186_ROOT/original-run/translation/result.json"
```

预期：原候选链和独立重跑全部完成；originalCandidateRouteComplete=true，
programValidationPerformed=false，semanticApproval=false，productionAcceptanceComplete=false。
这不代表程序级 L0–L3 完成，也不证明旧实例的规范指令实际执行。
如果原后端拒绝当前实例，run 返回非零并停止，这是保留真实结果；不能将拒绝改成成功。

## 4. 失败时只获取已经产生的证据

优先提供 focused.log、original-run.log 和 original-run/run-status.json。
按状态中 currentStage/primaryFailure 提供相应文件：

| 失败位置 | 相关路径（相对 $PHASE186_ROOT/original-run） |
|---|---|
| 原 CLI 导入 | preflight/run-status.json、preflight/backend-import/command.json、stdout.log、stderr.log |
| 寄存器查询 | preflight/run-status.json、preflight/query/query.json、stdout.log、stderr.log |
| 输入适配 | input/run-status.json，及其中列明的实际命令日志 |
| 原后端翻译 | translation/run-status.json、translation/original-backend.stdout、translation/original-backend.stderr；存在时补 translation/result.json、translation/translated.json 和尝试归档 |
| 独立审计 | audit 中实际产生的前端/重跑日志及结果，按 original-run/run-status.json 定位 |

配置校验在建目录前失败时，只有 original-run.log 属于预期；不要继续读取不存在的状态文件。
预检可单独运行，但它不消费真实输入合同：

```bash
python3 "$PHASE186_ORIGINAL" preflight --ghidra-install-dir "$GHIDRA_INSTALL_DIR" \
 --output "$PHASE186_ROOT/standalone-preflight" --timeout-seconds 600
```

真实项目仍推荐 run，以确保预检和翻译使用同一记录环境。

## 5. 后续评估

先取得本轮真实原后端尝试归档和独立审计结果，再依据实际首个缺失事实推进。
如候选生成通过，使用原 EvaluationRequest、evaluation_cli 和 translation_validation 继续评估，
参照 phase185-original-pipeline-adapter.md 第 6 节的真实输入、构建与比较合同要求。
不能用空 provider、仅函数入口命中或诊断返回码替代 ABI、对象合法性及实例覆盖。
旧实例 excluded-under-recorded-contracts 的适用性结论仍需保留，不能为了命中修改 GMP 阈值。

## 本地验证记录

54 模块完整回归：689 通过、9 跳过，426.20 秒；退出码 0。
核心组 66 通过、1 跳过；最终预检子集 16 通过、1 跳过。各组重叠，不累加。
暂停前的扩大回归没有最终统计，保留为 interrupted-broad.log；恢复后已完整重跑。
最初缺少已声明的 pypcode 依赖；安装后继续测试。旧特权 CLI 夹具缺失现行协议字段的
诊断及修正记录也保留。完整记录位于 experiment/baselines/phase186/。
本地没有执行真实 Ghidra 查询、GMP 翻译或整程序等价验证；9 项跳过不计通过。
