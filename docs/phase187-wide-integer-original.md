# Phase187：原框架的宽整数语义、物理回填与有限程序证据组件

基线：phase186-ghidra-preflight，8ccbeb8dd5003d22f0506cccbf84addf09684e2f。

## 已确认的真实失败

Phase186 真实主机 68 项测试通过。原后端进程返回 0，但唯一尝试为 unsupported；
外层因候选不完整返回 2。机器码 33b5c502 成功提升为两个 INT_ZEXT、INT_MULT 和 SUBPIECE。
当前缺口是原值语义模型及目标合同，不是继续修 Ghidra 启动，也不是重新采集全部构建上下文。

## 本轮实施与边界

| 项目 | 实施 | 结论边界 |
|---|---|---|
| 源语义 | 原 Phase6A 从类型化 p-code 的封闭定义使用图派生无符号乘法高位 | 不读取源码名称、助记符字符串或 UNIQUE 固定偏移；额外寄存器写入、错误扩展/截取等拒绝 |
| GNU 和类型 | 普通整数类型身份不再依赖原子对象；整条 GNU 输入交换关系进入源模型及合同 | 新合同要求编译器整数宽度见证、可修改输出和适用输入求值事实；不静默剥离 % |
| 原目标链 | Phase6B 登记计划，6C 约束，6D 位向量引理及资源检查，6F 登记渲染 | x86 GNU 汇编显式声明 RAX/RDX/cc；输入在输出写入前消费；没有独立 native 整数回退 |
| 物理编辑 | 保留原编译器导出报告，另生成附加物理绑定投影 | 诊断 fileName 不改；仅允许回填隔离 input.i；不授予原始宏或头文件权限 |
| 审计 | 每个源片段、范围、类型、约束和物理绑定在回填前重核；审计重新导出原始编译器报告并重跑原后端 | 校验器源码变化后必须新 prepare/run，不能给旧收据改身份 |
| 诊断 | 报告实际缺失模型和 Phase6C/6D 明细 | 不改变拒绝条件，不把 unsupported 改成 emitted |
| 验证器来源 | c_module 增加显式包入口 | 模块来源继续严格核查，混合工作树仍拒绝 |
| 机器事实 | 已链接 AMD64 ELF 的完整函数范围及结构化 p-code；有限纯整数叶函数的保存寄存器非写入、栈返回子引理 | 不等于完整声明/调用点 ABI；复杂函数仍有缺失项；静态解码不等于执行覆盖 |
| 对象关系 | 明确假设下的有限仿射对象事件模型，检查边界、对齐、生命周期和已初始化读取；共享 allocation 的 view 显式建模别名 | 尚未自动绑定 C/机器访问或循环；不是 GMP 内部对象合法性证明 |
| 程序计划 | 固定入口、输入域、观察、信任合同和构建单元，生成逐实例/逐单元 L0–L3 义务；区分执行前条件和执行后观察 | 合同文件只冻结身份，不由文件存在推定语义正确；仍由原验证器判定层级 |

原宏来源、完整机器 ABI、内部循环/调用效果、规范实例映射及运行事件、适用 L1–L3 的实际生产和
整程序闭合仍未全部实现。本轮新增组件不能被当作这些整体阶段已完成的证据。

## 1. 更新与环境

沿用已有 .venv-l2。分段执行并检查状态，失败后停止依赖它的命令。

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE186_ROOT:?}"
git -C "$REPO" fetch origin phase187-wide-integer-original
export PHASE187_TOOLING="$PREP_ROOT/tooling-phase187"
git -C "$REPO" worktree add --detach "$PHASE187_TOOLING" origin/phase187-wide-integer-original
export PHASE187_ROOT="$(mktemp -d "$PHASE186_ROOT/phase187-XXXXXX")"
: "${PHASE187_ROOT:?}"
export PYTHONPATH="$PHASE187_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE187_ORIGINAL="$PHASE187_TOOLING/experiment/run_native_original.py"
export PHASE187_EVIDENCE="$PHASE187_TOOLING/experiment/inspect_program_evidence.py"
git -C "$PHASE187_TOOLING" rev-parse HEAD
printf 'PHASE187_ROOT=%s\n' "$PHASE187_ROOT"
```

```bash
export GHIDRA_INSTALL_DIR=/opt/ghidra_11.2_PUBLIC
test -x "$GHIDRA_INSTALL_DIR/support/pythonRun"
python3 -c 'import z3,pypcode; print("Z3",z3.get_version_string(),"pypcode",pypcode.__version__)'
```

z3-solver 已在 requirements-legacy.txt 声明；新合同需要实际执行位向量引理。
如缺失，可在当前虚拟环境执行下列安装后重新检查；不建议为本任务无差别升级已有工具链。

```bash
python3 -m pip install 'z3-solver>=4.12,<5'
```

## 2. 定向回归

```bash
export RV2X86_REAL_GHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR"
python3 -m pytest -q -rs \
 "$PHASE187_TOOLING/pytools/tests/test_wide_integer_original.py" \
 "$PHASE187_TOOLING/pytools/tests/test_native_original_pipeline.py" \
 "$PHASE187_TOOLING/pytools/tests/test_program_proof_components.py" \
 "$PHASE187_TOOLING/pytools/tests/test_native_verifier_manifest.py" \
 "$PHASE187_TOOLING/pytools/tests/test_ghidra_preflight.py" \
 "$PHASE187_TOOLING/pytools/tests/test_candidate_materialization.py" \
 "$PHASE187_TOOLING/pytools/tests/test_evaluation_runner.py" \
 --basetemp="$PHASE187_ROOT/pytest-focused" > "$PHASE187_ROOT/focused.log" 2>&1
PHASE187_STATUS=$?
printf 'focused_status=%s\n' "$PHASE187_STATUS"
cat "$PHASE187_ROOT/focused.log"
```

源汇编器边界在一项完整原 Pipeline 测试中使用显式 fixture；实际 p-code 提升、原模型、约束、
证明、选择、渲染和归档均执行。另有真实主机 GCC 的 32/64 位、O0/O2/O3 编译运行与 Python
任意精度整数参考比较。它们均不能替代真实 GMP 运行。真实 Ghidra 测试显式启用后失败不跳过。

## 3. 在真实输入上重新运行原候选链

使用此前同一真实 bundle，重新生成本轮证据。无需修改或重建 C++ 前端：物理投影使用其已导出的
AST 范围及原生输入绑定；原始前端事实文件保留不变。不能复用 Phase186 prepared/result.json。

```bash
: "${PHASE185_BUNDLE:?需要已有真实binding-bundle.json}"
python3 "$PHASE187_ORIGINAL" run --bundle "$PHASE185_BUNDLE" \
 --ghidra-install-dir "$GHIDRA_INSTALL_DIR" \
 --output "$PHASE187_ROOT/original-run" --timeout-seconds 600 \
 > "$PHASE187_ROOT/original-run.log" 2>&1
PHASE187_STATUS=$?
printf 'original_run_status=%s\n' "$PHASE187_STATUS"
cat "$PHASE187_ROOT/original-run.log"
```

只有返回 0 且产生最终结果后执行：

```bash
python3 "$PHASE187_ORIGINAL" check --input "$PHASE187_ROOT/original-run/result.json"
python3 -c 'import json,os; from pathlib import Path; v=json.loads((Path(os.environ["PHASE187_ROOT"])/"original-run/translation/result.json").read_text()); print({"backendReturnCode":v["command"]["returnCode"],"attemptOutcomes":v["attemptOutcomes"]})'
```

对本次已提供的封闭无符号乘法高位形状，预期进入原登记合同并生成 emitted 候选，完成独立重跑。
实际结果仍由检查器和真实工具决定。若出现新不支持项，保留完整诊断，不切回历史整数路线。

应核对：

- input/frontend-export.json：原始编译器导出，保留诊断路径；
- input/frontend-report.json：原事实加 physicalEditBinding，指向隔离 source/input.i；
- translation/translated.json：sourceModelDiagnostics、选定合同、实际替换文本、验证与发布状态；
- translation/translated.json.attempts.json：对应 emitted 及证明/约束绑定；
- translation/candidate-manifest.json：实际编辑相对路径为 input.i；
- audit/result.json：原前端及后端的独立重跑一致。

semanticApproval 和 productionAcceptanceComplete 仍应为 false；validationOutcome 仍可为 not_verified，
publicationOutcome 为 withheld。原候选链完成不代表 L0–L3 完成。
如果失败，先提供 focused.log、original-run.log、original-run/run-status.json、
translation/original-backend.stdout、stderr，以及存在时的 translated.json、尝试归档和子 result。
不要继续读取不存在的审计或评估结果。

## 4. 接回原评估器

先完成第 3 节，再使用真实原 EvaluationRequest。沿用 phase185-original-pipeline-adapter.md 第 6 节：
prepare-evaluation 绑定本轮 translation/result.json，然后由 riscv2x86_py.evaluation_cli 执行。
原 L0 矩阵、运行器、比较策略和适用 L2/L3 provider 继续决定结果。
本合同不引入额外头文件或运行库；源/目标 .i、编译配置及实际链接替换关系仍须由构建合同确认。

当前实例在记录合同下被排除的旧适用性结论不能删除。候选可生成与规范产物中的实例实际执行
是两个问题，需针对每个配置重新判定。不得通过修改 GMP 阈值或使用不合法参数强行命中。

## 5. 有限程序证据组件（取得对应真实输入后使用）

这些命令返回 0 表示组件记录产生并通过重派生，必须继续查看 facts 中的具体结果。
不会自动接管原 L0–L3，也不会把整体 ABI/对象/覆盖标志升级为 true。

### 5.1 实际机器事实

在原 L0 或实际构建产出本轮已链接目标 ELF 后，明确指定该产物及实际符号。
不要将旧部署 ELF 当作本轮候选产物。PROGRAM_ELF 和 PROGRAM_FUNCTION_SYMBOL 必须来自对应构建记录。

```bash
: "${PROGRAM_ELF:?需要本轮真实已链接ELF}" "${PROGRAM_FUNCTION_SYMBOL:?需要实际函数符号}"
python3 "$PHASE187_EVIDENCE" machine --elf "$PROGRAM_ELF" --symbol "$PROGRAM_FUNCTION_SYMBOL" \
 --output "$PHASE187_ROOT/machine-evidence" > "$PHASE187_ROOT/machine-evidence.log" 2>&1
```

成功后可 check 对应 result.json。当前仅支持 AMD64 已链接 ELF，要求唯一有界函数范围、完整静态解码，
函数范围内有待应用重定位时拒绝。复杂函数可产生事实但不满足受限叶函数子引理。
这不是分析器错误，也不允许忽略栈、内存或调用使它通过。
保存寄存器/返回纪律子引理仍需与声明、调用点、CFG/栈帧和构建关系组合；完整机器 ABI 尚未闭合。

### 5.2 对象关系组件

仅在存在有来源的事件模型时使用，不为当前 GMP 手工伪造一个“可通过”的模型。
模型格式见 program_object_evidence.py 和 test_program_proof_components.py 中的协议测试。

```bash
: "${OBJECT_EVENT_MODEL:?需要有来源的实际对象事件模型}"
python3 "$PHASE187_EVIDENCE" objects --model "$OBJECT_EVENT_MODEL" \
 --output "$PHASE187_ROOT/object-evidence" > "$PHASE187_ROOT/object-evidence.log" 2>&1
```

schemaVersion 为 riscv2x86.affine-object-event-model.v1。variables 声明非空整数区间；allocations
声明数学大小、对齐、生命周期和初始化范围；views 显式共享 allocation；accesses 列出有身份的有限
读写事件。表达式为整数或 {constant,terms} 仿射形式。模型子关系检查包含反例输出，未知不算通过。

该模型是显式假设下的数学关系；尚未证明其事件覆盖全部实际访问，也不证明 C 算术/循环的细化关系。
conditionalObjectRelationsVerified=true 时 legalObjectDomainVerified 仍为 false，不能据此批准程序。

### 5.3 固定范围和证据义务

在入口、输入域、观察及信任边界合同已经明确时，可生成后续工作计划。
不是通过填写几个路径就批准这些合同。scope JSON 的精确字段为：

- schemaVersion: riscv2x86.declared-program-scope.v1；
- entryContract、inputDomainContract、observationContract、trustBoundaryContract：实际合同文件路径；
- requiredLevels：从 L0 开始的连续层级，如 ["L0","L1","L2"]；
- buildCells：非空列表，每项 {cellId,buildContract}，后者为实际构建合同文件路径。

```bash
: "${DECLARED_PROGRAM_SCOPE:?需要已核对的实际范围文件}"
python3 "$PHASE187_EVIDENCE" plan --translation "$PHASE187_ROOT/original-run/translation/result.json" \
 --scope "$DECLARED_PROGRAM_SCOPE" --output "$PHASE187_ROOT/program-plan" \
 > "$PHASE187_ROOT/program-plan.log" 2>&1
```

计划为每个实例/构建单元保留存续/消除、编译器到规范区域映射、运行指令事件、适用效果等义务。
未命中的样本不从分母移除；文件快照及哈希只固定合同内容，不能证明合同内容正确。
L1 执行后比较结论列为 after-L1 义务，避免拿尚待运行产生的完整结论阻止验证器运行。
历史 native 总阶段准入与这些生产者的完整连接仍需后续开发；本计划不替换其门禁。

## 本轮尚未完成的必要能力

1. 适用函数/调用链的完整机器 CFG、帧及声明/调用点 ABI 事实生产与组合；当前机器组件仅有有限叶函数子引理。
2. C/机器访问到对象事件模型的来源绑定、循环不变量及被调用者效果；当前对象组件仅有条件数学关系。
3. 规范实例到优化机器区域的可靠映射，以及与本次真实执行事件的连接；静态解码与入口命中均不能替代。
4. 原评估器的本轮真实构建、源目标运行和适用 L2/L3 证据，以及独立程序级审计和总阶段闭合。
5. 原始宏/头文件修改授权；本轮仍只输出冻结预处理翻译单元。

上述缺口不能靠重复运行组件命令补出；应按计划义务，继续实现所需生产者并用真实产物验证。

## 本地验证记录

58 模块选定扩大回归：761 通过、10 项环境跳过，431.84 秒。
收尾收紧合同后，对直接相关的原链、回填、组件、验证器与评估模块重验：84 通过；
最后加入实际原 Pipeline 到物理回填/独立重跑及 C 输入输出别名检查：30 通过。组间重叠，不累加。

另行运行的旧标量合同模块，在未修改基线和本轮最终代码中均为 18 通过、1 失败；
同一 CSR 测试期望 functional_c，但现行基线返回 needs_route。本轮未改该测试或其生产门禁。
此问题单列为既有问题，不计入新宽整数合同成功，也不宣称全仓库测试全部通过。
完整日志及范围说明位于 experiment/baselines/phase187/。
本地尚未执行真实 Ghidra/GMP 原候选链；第 3 节的主机验证仍是必要步骤。
