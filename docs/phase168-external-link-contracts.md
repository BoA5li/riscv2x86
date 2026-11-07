# Phase168：双端构建、测试入口、有序链接与候选定义归因

基线：Phase167 `03cd42d6cc186861d7db7e58ea20c5d477c39f9a`。
分支：`phase168-external-link-contracts`。

## 实际交付及尚未完成的范围

已实现：

- 明确 source/target/hostcc 角色的 GMP 构建 profile，绑定工具、摘要、编译器三元组、
  CFLAGS 和预期机器架构；独立验证 profile，不将配置选择当成 ABI 证明。
- 构建驱动接受 profile，目标端使用独立配置/构建目录，不继承 RV64 march/mabi；
  原有无 profile 路线保持原语义。目标 inspect 选择 x86_64，不误用 RISC-V。
- 顺序捕获任意受支持的 `[构建子目录:]make目标`，分别导入测试支持库和测试入口的
  records，主 records 继续只对应库 build 阶段，不混入 configure 或测试夹具。
- 测试入口 v2 显式核验 expectedMachine=243/62，仍要求捕获重放、明确动作 ID、
  实际输出摘要和 ELF 元数据；旧 v1 默认 RV64 和历史重放保持原样。
- 链接请求/回执 v2 接受显式 file/group 有序计划，保留重复归档和嵌套链接组；
  保留旧 v1 的输入与重放规则。未知链接选项、响应文件、脚本不猜测、不丢弃。
- v2 链接使用受控 PATH/locale，排除继承 GCC_EXEC_PREFIX/LIBRARY_PATH 等隐式覆盖；
  这只绑定本次链接环境，不证明所有隐式 CRT/库均已正确解析。
- 新 `attribute-link` 独立重建链接，联合检查 GNU bfd 的精确 definition trace、map
  中对应输入段、最终 ELF 定义地址/大小。支持普通分配段中的非零大小 strong FUNC/OBJECT；
  TLS、IFUNC、弱定义、特殊段、歧义、无法解释的优化/松弛继续阻塞。
- 新 `requirements` 从原归档字节定位每项外部义务的重定位和所属函数，携带所选构建
  动作与提供者候选，按 ELF 对象/函数类别列明所需证据；不按五个符号名称白名单放行。
  先独立重放父 provider/dependency/capture；支持新目录独立 replay-requirements。

**尚未完成：五项外部行为合同、双端 ABI/对象/可变参数合同、实际运行绑定及翻译实例
覆盖、程序级 L0–L3 接入。** 本轮并未实现对整个 libc 的语义证明，不能将五项阻塞
自动清零。栈保护机制在不同架构上可以不同；本轮不据同名/无同名自动判定对应。
没有关闭栈保护/fortify、删除断言、添加桩函数、忽略父阻塞或更改既有验收标准。

candidateDefinitionAttributionVerified 仅表示受支持范围内的**链接时定义来源**。
actualLinkSelectionVerified、runtimeLibrarySelectionVerified、typedCallContractVerified、
translatedInstanceExecutionVerified、semanticApproval、productionAcceptanceComplete 仍为 false。
独立重建和候选来源归因不是跨架构语义证明。所有正式结论都必须限定证据范围。

## 1. 更新独立工具树并运行回归

每段代码整段复制；若变量缺失会立即停止。不要在终端提示符前粘贴额外命令。

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE167_ROOT:?}"
git -C "$REPO" fetch origin phase168-external-link-contracts
export PHASE168_TOOLING="$PREP_ROOT/tooling-phase168"
git -C "$REPO" worktree add --detach "$PHASE168_TOOLING" origin/phase168-external-link-contracts
export PHASE168_ROOT="$(mktemp -d "$PHASE167_ROOT/phase168-XXXXXX")"
export PYTHONDONTWRITEBYTECODE=1
printf 'PHASE168_ROOT=%s\n' "$PHASE168_ROOT"
git -C "$PHASE168_TOOLING" rev-parse HEAD
```

```bash
bash -e <<'VERIFY'
: "${PHASE168_TOOLING:?}" "${PHASE168_ROOT:?}"
export PYTHONPATH="$PHASE168_TOOLING/pytools"
python3 -m pytest -q -rs \
  "$PHASE168_TOOLING/pytools/tests/test_project_build_profile.py" \
  "$PHASE168_TOOLING/pytools/tests/test_project_acquisition_driver.py" \
  "$PHASE168_TOOLING/pytools/tests/test_native_test_entry.py" \
  "$PHASE168_TOOLING/pytools/tests/test_native_link_attribution.py" \
  "$PHASE168_TOOLING/pytools/tests/test_native_link_evidence.py" \
  "$PHASE168_TOOLING/pytools/tests/test_native_external_requirements.py" \
  "$PHASE168_TOOLING/pytools/tests/test_native_external_providers.py" \
  --basetemp="$PHASE168_ROOT/pytest" --junitxml="$PHASE168_ROOT/focused.xml" \
  > "$PHASE168_ROOT/focused.log" 2>&1
VERIFY
VERIFY_STATUS=$?
printf 'phase168_test_status=%s\n' "$VERIFY_STATUS"
cat "$PHASE168_ROOT/focused.log"
```

真实文件 provider 集成沿用 `RV2X86_TEST_NATIVE_DEPENDENCIES` 和
`RV2X86_TEST_RUNTIME_BASIS`；只有两者均为真实文件才启用该集成。
普通 native 夹具的运行不等于真实 GMP 跨架构验证。

## 2. 一次定位五项义务的实际引用位置

使用 Phase167 已成功生成的 provider 清单；不重做全目录搜索。

```bash
bash -e <<'REQUIREMENTS'
: "${PHASE168_TOOLING:?}" "${PHASE168_ROOT:?}" "${PHASE167_ROOT:?}"
test -f "$PHASE167_ROOT/providers/result.json"
python3 "$PHASE168_TOOLING/experiment/inspect_native_runtime_contracts.py" requirements \
  --input "$PHASE167_ROOT/providers/result.json" --output "$PHASE168_ROOT/requirements" \
  > "$PHASE168_ROOT/requirements.log" 2>&1
python3 "$PHASE168_TOOLING/experiment/inspect_native_runtime_contracts.py" replay-requirements \
  --input "$PHASE168_ROOT/requirements/result.json" --output "$PHASE168_ROOT/requirements-replay" \
  > "$PHASE168_ROOT/requirements-replay.log" 2>&1
REQUIREMENTS
REQUIREMENTS_STATUS=$?
printf 'requirements_status=%s\n' "$REQUIREMENTS_STATUS"
cat "$PHASE168_ROOT/requirements.log" "$PHASE168_ROOT/requirements-replay.log"
```

预期原五项全部保留，每项列出实际引用的 section/offset/relocation type/所属函数，
原已完成的成员来源保持不变。外部合同仍 blocked 是诚实状态；没有重定位时明确列出
REFERENCE_MECHANISM_NOT_LOCATED，不能忽略该项。请返回 requirements/result.json，
这是后续机器机制和类型合同的定向依据，而非再次要求全文 readelf。

## 3. 构建真实 x86 依赖和官方测试入口

下面显式创建 x86 目标 profile。`-funsigned-char` 对应已捕获源数据模型的 plain-char
选择；它不保证 GMP 全部 ABI 相容。仍需核验 limb/nail/size/结构体和实际调用合同。
两个端各自使用本地 libc/FILE，不复制 RISC-V FILE 布局到 x86。

```bash
bash -e <<'PROFILE'
: "${PHASE168_TOOLING:?}" "${PHASE168_ROOT:?}"
python3 "$PHASE168_TOOLING/experiment/prepare_native_build_profile.py" create \
  --side target --host x86_64-linux-gnu --cflags='-O2 -funsigned-char' \
  --cc /usr/bin/x86_64-linux-gnu-gcc-7 --hostcc /usr/bin/x86_64-linux-gnu-gcc-7 \
  --ar /usr/bin/x86_64-linux-gnu-ar --ranlib /usr/bin/x86_64-linux-gnu-ranlib \
  --ld /usr/bin/x86_64-linux-gnu-ld --output "$PHASE168_ROOT/target-profile.json" \
  > "$PHASE168_ROOT/target-profile.log" 2>&1
python3 "$PHASE168_TOOLING/experiment/prepare_native_build_profile.py" check \
  --input "$PHASE168_ROOT/target-profile.json" > "$PHASE168_ROOT/target-profile-replay.log" 2>&1
PROFILE
PROFILE_STATUS=$?
printf 'profile_status=%s\n' "$PROFILE_STATUS"
cat "$PHASE168_ROOT/target-profile.log" "$PHASE168_ROOT/target-profile-replay.log"
```

如果对应工具不存在，保留报错；不要用 source 工具冒充 target 工具。

```bash
bash -e <<'BUILD'
: "${PHASE168_TOOLING:?}" "${PHASE168_ROOT:?}" "${PREP_ROOT:?}" "${ARCHIVE_ROOT:?}"
bash "$PHASE168_TOOLING/experiment/acquire_real_project_builds.sh" \
  "$PHASE168_TOOLING" "$PREP_ROOT" "$ARCHIVE_ROOT" "$PHASE168_ROOT/gmp-target" gmp \
  --archive-provenance --build-profile "$PHASE168_ROOT/target-profile.json" \
  --test-target tests:libtests.la --test-target tests/mpz:t-powm \
  > "$PHASE168_ROOT/target-build.log" 2>&1
BUILD
BUILD_STATUS=$?
printf 'target_build_status=%s\n' "$BUILD_STATUS"
cat "$PHASE168_ROOT/target-build.log"
```

不会运行 make check，不把交叉构建和执行混淆。输出：

- gmp-target/records.json：库 build 阶段；
- gmp-target/test-records-0.json：tests/libtests.la 构建；
- gmp-target/test-records.json：tests/mpz/t-powm 构建；
- gmp-target/run-status.json：全部阶段与首个失败。

目标原生 GMP 支持库尚不是“翻译后的 GMP”。后续链接必须证明选中的待测定义来自
candidate/target.o；其它原生支持定义应作为明确的依赖/可信基础列入论文和合同。

## 4. 显式选择测试入口链接动作

以下只列出成功的 link 动作，绝不按文件名自动授权。使用上一步 test-records.json。

```bash
bash -e <<'LIST'
: "${PHASE168_TOOLING:?}" "${PHASE168_ROOT:?}"
export PYTHONPATH="$PHASE168_TOOLING/pytools"
python3 - <<'PY'
import json, os
from pathlib import Path
from riscv2x86_py.native_dependency_inventory import checked_records
path = Path(os.environ['PHASE168_ROOT'])/'gmp-target/test-records.json'
value = checked_records(path)
for action in value['actions']:
    if action['kind'] == 'link':
        print(json.dumps({k:action.get(k) for k in ('actionIdentity','directory','arguments',
            'observedReturnCode','observedOutput')}, ensure_ascii=False, indent=2))
PY
LIST
LIST_STATUS=$?
printf 'entry_list_status=%s\n' "$LIST_STATUS"
```

选择确认的实际官方测试 ELF 动作后设置 TARGET_ENTRY_ACTION，执行：

```bash
bash -e <<'ENTRY'
: "${PHASE168_TOOLING:?}" "${PHASE168_ROOT:?}" "${TARGET_ENTRY_ACTION:?明确选择上一步链接动作ID}"
python3 "$PHASE168_TOOLING/experiment/translate_native_project.py" entry-metadata \
  --records "$PHASE168_ROOT/gmp-target/test-records.json" --action-identity "$TARGET_ENTRY_ACTION" \
  --expected-machine 62 --output "$PHASE168_ROOT/target-entry.json" \
  > "$PHASE168_ROOT/target-entry.log" 2>&1
python3 "$PHASE168_TOOLING/experiment/translate_native_project.py" replay-entry-metadata \
  --input "$PHASE168_ROOT/target-entry.json" > "$PHASE168_ROOT/target-entry-replay.log" 2>&1
ENTRY
ENTRY_STATUS=$?
printf 'entry_status=%s\n' "$ENTRY_STATUS"
cat "$PHASE168_ROOT/target-entry.log" "$PHASE168_ROOT/target-entry-replay.log"
```

预期 capturedOutputBindingVerified=true、metadata.elfMachine=62，执行与语义字段仍为false。
原 source 入口可使用 --expected-machine 243；旧不带参数的命令保持 v1。

## 5. 有序目标链接和独立归因

先根据上面的真实链接 argv 确定全部对象/归档顺序。新 plan 是 JSON 数组：
`[{"file":"/实际/main.o"},{"group":"start"},{"file":"/实际/libtests.a"},
{"file":"/实际/libgmp.a"},{"group":"end"}]`。
这里只说明格式；不能把示例路径或三个文件当成通用完整闭包。重复归档按原顺序保留。
候选对象由驱动显式插入，不重复填入。若原命令需要尚不支持的脚本/响应文件/选项，
保留阻塞，不能丢弃参数。本轮不会自动猜测或转换完整 libtool 链接命令。

取得实际计划后设置 TARGET_ORDERED_PLAN 为该 JSON 文件路径：

```bash
bash -e <<'LINK'
: "${PHASE168_TOOLING:?}" "${PHASE168_ROOT:?}" "${PHASE162_ROOT:?}" "${TARGET_ORDERED_PLAN:?实际有序JSON计划}"
python3 "$PHASE168_TOOLING/experiment/inspect_native_runtime_contracts.py" link-request \
  --candidate "$PHASE162_ROOT/candidate/candidate.json" --side target \
  --compiler /usr/bin/x86_64-linux-gnu-gcc-7 --ordered-inputs "$TARGET_ORDERED_PLAN" \
  --output "$PHASE168_ROOT/target-link-request.json"
python3 "$PHASE168_TOOLING/experiment/inspect_native_runtime_contracts.py" link \
  --request "$PHASE168_ROOT/target-link-request.json" --output "$PHASE168_ROOT/target-link" \
  > "$PHASE168_ROOT/target-link.log" 2>&1
python3 "$PHASE168_TOOLING/experiment/inspect_native_runtime_contracts.py" attribute-link \
  --input "$PHASE168_ROOT/target-link/result.json" --output "$PHASE168_ROOT/target-attribution" \
  > "$PHASE168_ROOT/target-attribution.log" 2>&1
LINK
LINK_STATUS=$?
printf 'link_attribution_status=%s\n' "$LINK_STATUS"
cat "$PHASE168_ROOT/target-link.log" "$PHASE168_ROOT/target-attribution.log"
```

只有实际 supported 强定义全部对应时 candidateDefinitionAttributionVerified 才为true。
这不是全部外部符号的提供者选择，也不是运行时绑定。不会设置整体
actualLinkSelectionVerified 或 semanticApproval。

## 后续真实完成条件

返回 focused.log、requirements/result.json、target-build.log、gmp-target/run-status.json、
真实 t-powm 链接动作，以及 target-entry/target-attribution 的结果。
如果某阶段失败，返回其日志与首个失败状态，后续阶段不继续冒充通过。

五项最终关闭还需要：引用机器机制/类型合同、双端对象/输入输出关系、实际 libc/loader
加载及绑定、实例实际执行、L0–L3 与独立程序审计。对未触发的错误处理与保护失败路径，
需要单独合同/验证，不因正常 t-powm 退出0而忽略。源码宏改写、其它 ISA/浮点和一般 ABI
也不能由本轮的链接能力扩展推定完成。

## 本地检查记录

- native/project 回归：452 passed、9 skipped（40.25 秒）；随后修改的测试构建输入绑定
  和新增 requirements 重放反例已在专项复验覆盖。
- 最终专项：46 passed、1 skipped（4.07 秒）。跳过项需要用户主机真实 dependency/runtime
  回执；其余真实 native bfd 链接、重复归档/分组、独立重建和 ELF 来源归因均运行。
- 改动 Python 语法、git diff --check、本文全部 Bash 块 bash -n 通过。
- 没有在本地运行真实 RISC-V GMP 或用户容器；没有执行真实 GMP 目标链接、动态绑定、
  五项行为合同验证或程序级 L3。不得将上述通过项解释为五项义务已经关闭。
