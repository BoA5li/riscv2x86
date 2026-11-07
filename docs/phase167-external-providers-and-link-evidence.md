# Phase167：结构化外部提供者及受控链接证据

基线：`8c4d3a5578179305730f3e0c58bd0e644e542672`（Phase166）。
分支：`phase167-structured-external-provider-evidence`。

## 结论与范围

Phase166 主机已经完成归档来源选择：18个所选成员各有一个选中的构建动作，
两个归档选择字段为 true，余下5项均为 external-contract-required。
RISC-V guard 的定义在 loader，另4项在 libc；两端版本名称不同不自动构成不一致。
本轮将候选 ELF 定义与版本解析接入独立证据链，新增受控链接及独立重建接口。
不修改原依赖报告或原来的闭包算法，不按5个名字白名单放行，不改生产编译参数。

**本轮不会宣称5项行为合同已经成立或完整GMP L0–L3已经贯通。** 候选匹配与实际
链接、动态选择、类型/效果合同、运行观察是不同状态；实际目标依赖和测试入口仍须取得。
本轮提供了它们可使用的结构化输入和构建接口，不能从库符号表推导整个库的语义证明。

## 实现及适用边界

1. `native_elf_runtime.py` 是独立、版本化的 ELF64 little-endian 解析器；不修改旧
   ET_REL 解析和历史投影。处理符号的定义/引用、类型、绑定/可见性、GNU版本定义、
   需求、隐藏/默认版本、版本哈希、DT_NEEDED/SONAME/搜索路径、解释器及重定位元数据。
   拒绝不支持的格式、截断/越界、版本链/计数/索引错误、歧义表和无法解释的版本引用。
   重定位元数据不等于已经证明各种重定位或 TLS 机制语义。
2. 候选选择按请求的架构、名字、已知ELF类型及版本约束。UND永不作为定义；未指定版本
   的请求不选择隐藏的非默认定义。弱、GNU unique、TLS/IFUNC等要求额外合同。已链接
   ELF中的COPY类导入存储可能是“有定义但版本来自需求”；不能冒充原始共享库提供者。
   符号大小相同不证明C类型或对象布局相同。
3. `native_external_providers.py` 首先重放父依赖清单，校验runtime basis身份及绑定文件，
   从实际 ELF 字节解析，保留完整版本化请求和定义候选，归档字节再独立解析/重放。
   原5项义务保留在 originalDependencyBlockers，逐项新增pendingReasons。原父清单和
   runtime basis中的其它阻塞也保留。不会把共享PIC构建的版本需求强行移植到静态归档。
4. targetNameCandidates 仅是目标侧同名候选发现，不是跨架构行为映射。没有同名guard
   不能据此添加桩或复制源guard；目标机器机制需单独合同和证据。
5. `native_link_evidence.py` 只链接显式的既有候选对象和用户提供的实际对象/常规归档/
   ELF库。核验架构/适用flags、输入摘要/别名、候选制品、工具身份、GNU bfd、成功退出、
   最终ELF与导出。记录链接映射、跟踪流及隐式CRT/运行库候选。输入缺失、不兼容、重复
   强定义、未定义引用等应失败；不自动修复为另一个实现。
6. 链接驱动明确使用 GNU bfd、-z defs、-t和Map选项。不接受任意链接脚本、响应文件、
   --allow-multiple-definition、--wrap、--defsym或任意源文件；ABI选项仅支持显式
   -march= 和 -mabi=。PIE/static/shared必须由请求明确选择，不能在失败后偷偷改参数。
   对象需要PIC时应由正确编译入口生成，不能假装本驱动已经重编译成PIC。
7. 独立audit-link在新目录重新链接，核验原始工件自身完整性、结构化输出及二进制一致性。
   原始日志/map均保留摘要；只对这次工具生成的输出目录位置做路径投影，其余输入路径
   不被抹除。非确定性产物将保守地重建失败，不放宽为“看起来类似”。
8. candidateObjectExplicitInputVerified/candidateExportsPresent/linkBuildComplete 是构建事实。
   actualLinkSelectionVerified、candidateDefinitionAttributionVerified、运行加载选择、
   类型/效果合同和实际翻译实例执行仍为false。映射和跟踪是后续归因的原始依据，不把
   文本中出现名字自动解释为所有链接与运行义务都已证明。
9. 工具不运行真实GMP测试程序，也不生成伪造入口、关闭栈保护/fortify、删除断言、或
   制造行为合同通过标签。既有L0–L3路线和正确的归档规则保持原样。

## 主机验证

无需重新构建Phase166归档、再次采集库或重跑成功源端基线。保留旧工作树及捕获。

### 1. 更新独立工具树并设置真实集成输入

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE166_ROOT:?}"
git -C "$REPO" fetch origin phase167-structured-external-provider-evidence
export PHASE167_TOOLING="$PREP_ROOT/tooling-phase167"
git -C "$REPO" worktree add --detach "$PHASE167_TOOLING" origin/phase167-structured-external-provider-evidence
export PHASE167_ROOT="$(mktemp -d "$PHASE166_ROOT/phase167-XXXXXX")"
export PYTHONDONTWRITEBYTECODE=1
export RV2X86_TEST_NATIVE_DEPENDENCIES="$PHASE166_ROOT/dependencies/result.json"
export RV2X86_TEST_RUNTIME_BASIS="$PHASE166_ROOT/runtime-provider-basis.json"
test -f "$RV2X86_TEST_NATIVE_DEPENDENCIES"
test -f "$RV2X86_TEST_RUNTIME_BASIS"
printf 'PHASE167_ROOT=%s\n' "$PHASE167_ROOT"
git -C "$PHASE167_TOOLING" rev-parse HEAD
```

若工具树已存在，另取新路径，不要删除旧树。旧捕获绑定了旧实现，不能修改旧模块摘要。

### 2. 专项及真实文件集成回归

```bash
bash -e <<'TESTS'
: "${PHASE167_TOOLING:?}" "${PHASE167_ROOT:?}" "${RV2X86_TEST_NATIVE_DEPENDENCIES:?}" "${RV2X86_TEST_RUNTIME_BASIS:?}"
export PYTHONPATH="$PHASE167_TOOLING/pytools"
python3 -m pytest -q -rs \
  "$PHASE167_TOOLING/pytools/tests/test_native_elf_runtime.py" \
  "$PHASE167_TOOLING/pytools/tests/test_native_external_providers.py" \
  "$PHASE167_TOOLING/pytools/tests/test_native_link_evidence.py" \
  "$PHASE167_TOOLING/pytools/tests/test_native_dependency_inventory.py" \
  "$PHASE167_TOOLING/pytools/tests/test_project_archive_provenance.py" \
  --basetemp="$PHASE167_ROOT/pytest" --junitxml="$PHASE167_ROOT/focused.xml" \
  > "$PHASE167_ROOT/focused.log" 2>&1
TESTS
TEST_STATUS=$?
printf 'phase167_test_status=%s\n' "$TEST_STATUS"
cat "$PHASE167_ROOT/focused.log"
```

`test_actual_host_dependency_and_runtime_receipts`应运行，不能因未设置变量而跳过。
普通native链接测试只证明工具构建机制，不是对真实跨架构GMP语义的验证。

### 3. 正式生成外部候选清单及独立重放

```bash
bash -e <<'PROVIDERS'
: "${PHASE167_TOOLING:?}" "${PHASE167_ROOT:?}" "${RV2X86_TEST_NATIVE_DEPENDENCIES:?}" "${RV2X86_TEST_RUNTIME_BASIS:?}"
python3 "$PHASE167_TOOLING/experiment/inspect_native_runtime_contracts.py" providers \
  --dependencies "$RV2X86_TEST_NATIVE_DEPENDENCIES" \
  --runtime-basis "$RV2X86_TEST_RUNTIME_BASIS" \
  --output "$PHASE167_ROOT/providers" > "$PHASE167_ROOT/providers.log" 2>&1
python3 "$PHASE167_TOOLING/experiment/inspect_native_runtime_contracts.py" replay-providers \
  --input "$PHASE167_ROOT/providers/result.json" \
  --output "$PHASE167_ROOT/provider-replay" > "$PHASE167_ROOT/provider-replay.log" 2>&1
python3 "$PHASE167_TOOLING/experiment/inspect_native_runtime_contracts.py" summary-providers \
  --input "$PHASE167_ROOT/providers/result.json" \
  > "$PHASE167_ROOT/provider-summary.json" 2>&1
PROVIDERS
PROVIDER_STATUS=$?
printf 'provider_status=%s\n' "$PROVIDER_STATUS"
cat "$PHASE167_ROOT/providers.log" "$PHASE167_ROOT/provider-replay.log"
cat "$PHASE167_ROOT/provider-summary.json"
```

预期：原义务仍为5项；对已给资料，源端应各有一个元数据兼容的定义候选，coverage为true；
源guard在loader，另4项在libc；目标同名guard候选可以为空，不是本轮引入的新错误。
pendingReasons仍存在，actualLinkSelectionVerified和typedCallContractVerified必须为false。
初始和重放数量一致。不是要求blocked变为accepted，或要求5项被删除。

summary-providers是展示功能，不替代刚才的独立重放。无需再次上传数千行readelf输出。

### 4. 真实链接前的必要输入，避免伪造测试入口

继续真实链接还需要**实际的、架构正确的测试入口对象和完整目标依赖**。
本轮不会从RISC-V库推造x86对象，不能用只有名字的空函数或手写错误原型替代依赖。
需提供与官方测试来源及捕获动作绑定的入口对象、测试支持库、对应架构GMP依赖，
并核验数据模型及调用对象合同。尤其注意官方 t-powm 的链接不一定只有一个main对象。

已有Phase166记录是源RISC-V构建，不等于目标依赖已构建。相同GMP版本、相同导出名、
两个8字节stderr符号，均不足以证明数据模型/FILE对象/ABI一致。原目标candidate的
_GLOBAL_OFFSET_TABLE_需要目标重定位/链接机制解释，不按名称豁免。

### 5. 输入齐备后使用受控链接接口

以下是接口模板，只有取得实际对象/依赖后才执行。不要给变量填猜测路径或桩文件。
`--input`按实际链接顺序重复；候选source.o或target.o由工具自动作为第一个显式对象，
不要再把该对象重复放入inputs。它们的存在与导出会被检查，但实际执行仍须后续观察。

```bash
: "${PHASE167_TOOLING:?}" "${PHASE167_ROOT:?}" "${PHASE162_ROOT:?}"
: "${TARGET_TEST_ENTRY_OBJECT:?实际x86官方测试入口对象}"
: "${TARGET_TEST_SUPPORT_ARCHIVE:?实际x86测试支持库}"
: "${TARGET_GMP_ARCHIVE:?实际x86GMP依赖归档}"
python3 "$PHASE167_TOOLING/experiment/inspect_native_runtime_contracts.py" link-request \
  --candidate "$PHASE162_ROOT/candidate/candidate.json" --side target \
  --compiler /usr/bin/x86_64-linux-gnu-gcc-7 --mode executable \
  --input "$TARGET_TEST_ENTRY_OBJECT" --input "$TARGET_TEST_SUPPORT_ARCHIVE" \
  --input "$TARGET_GMP_ARCHIVE" --output "$PHASE167_ROOT/target-link-request.json"
```

此模板的三个inputs不是通用完整依赖列表。若实际捕获需要更多对象/库，须全部明确列出；
libtool包装脚本本身不是ELF入口对象。源侧用 --side source、真实RISC-V编译器及源对象，
不可交叉混用。默认保留编译器的PIE选择；只有实际路线要求时显式 --pie yes/no。
需要ABI选项时使用 `--abi-option=-mabi=lp64d`、`--abi-option=-march=rv64gc`。
不要为消除错误而偷偷切换static/shared/PIE或替换源配置。

```bash
bash -e <<'LINK'
: "${PHASE167_TOOLING:?}" "${PHASE167_ROOT:?}"
python3 "$PHASE167_TOOLING/experiment/inspect_native_runtime_contracts.py" link \
  --request "$PHASE167_ROOT/target-link-request.json" \
  --output "$PHASE167_ROOT/target-link" --timeout-seconds 300 \
  > "$PHASE167_ROOT/target-link.log" 2>&1
python3 "$PHASE167_TOOLING/experiment/inspect_native_runtime_contracts.py" audit-link \
  --input "$PHASE167_ROOT/target-link/result.json" \
  --output "$PHASE167_ROOT/target-link-audit" --timeout-seconds 300 \
  > "$PHASE167_ROOT/target-link-audit.log" 2>&1
LINK
LINK_STATUS=$?
printf 'target_link_status=%s\n' "$LINK_STATUS"
cat "$PHASE167_ROOT/target-link.log"
if test -f "$PHASE167_ROOT/target-link-audit.log"; then
  cat "$PHASE167_ROOT/target-link-audit.log"
fi
```

失败保留run-status、commands.json、link.stdout/stderr与map，不把失败改成metadata成功。
独立重建成功只是构建证据；运行时插入/动态符号抢占、实际对象访问及翻译实例执行，
仍需程序观察和独立审计。该接口不会把L0链接事实直接兑换为L1/L2/L3语义验收。

## 下一步返回哪些材料

先返回 focused.log、providers.log、provider-replay.log、provider-summary.json。
若失败，附相应run-status及具体错误。源/目标库的结构化候选和版本检查通过后，继续
实际目标依赖构建与入口绑定、链接归因、类型/可变参数/对象与终止行为合同、实际加载
与执行观察，再接入程序级比较与审计。已有后端失效问题仍需按最终路线校准，不能重哈希放行。

## 本地验证记录

相关native/project、GNU操作数关系、函数类型和调用清单/依赖回归：481 passed，
11 skipped，39.20秒。新增测试使用真实GNU版本化DSO、COPY导入存储、IFUNC、弱/TLS
符号、错误版本/架构/类型、截断与版本哈希/重定位索引损坏，以及实际native链接、
重复定义拒绝、带逗号输出路径、独立重建和重哈希伪造标记的拒绝。

11个跳过项包括新增的真实主机依赖/runtime报告集成，以及原有缺少真实Clang/RISC-V
GCC/前端的集成。主机上应按上述环境变量启用新增真实集成。本地native构建及测试
程序的退出7只验证测试夹具，不是GMP或跨架构语义结论。Python编译、diff检查和本文
全部Bash代码块的bash -n检查通过。本轮未执行真实GMP目标链接或程序级L3。
