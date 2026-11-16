# Phase193：修复共享库调用测试夹具的重定位合同

基于 Phase192（a9401d6）。用户环境回归为 95 passed / 4 errors；四个错误都发生在
`test_program_machine_inventory.py` 的 `binary` 夹具链接期间，相关测试没有进入解码阶段。

## 原因和修订

手写汇编中的 `call helper` 对工具链默认重定位选择存在依赖。用户工具链实际生成了
R_X86_64_PC32；helper 是默认可见的全局符号，共享库链接器拒绝该形式。
GCC 的 -fPIC 不会自动把手写 .S 的调用改写成 PLT 调用。

本轮显式使用 `call helper@PLT`，保留 helper 的 global/default 可见性，不隐藏符号、
不使用 -Bsymbolic，不关闭链接器检查。将编译对象和链接 DSO 分成两步，保留对象证据。
同时为测试函数调用前后补齐 AMD64 SysV 栈对齐和栈指针恢复。

新增正向检查：

- 实际对象对 helper 使用 PLT32 重定位及相应加数；
- helper 仍为默认可见全局符号；
- 实际 DSO 保留 helper 的 JUMP_SLOT；
- 从 sample 中 p-code 的实际 CALL 目标，经 ELF 可执行段地址关系和 PLT 的间接转移，
  对应到该 JUMP_SLOT 的 GOT 槽；不通过反汇编文本或单看编译参数判断。

新增反例：用显式 .reloc 生成 PC32 调用，以便新汇编器上也重现用户所遇的重定位形式。
先核对对象中实际存在 PC32，再确认共享库链接拒绝它。若链接意外成功，测试失败，
不会将问题静默跳过或忽略错误。反例中的汇编是刻意构造的非法 DSO 输入，不用于执行。

这些名称和指令属于自定义单元测试夹具，不是对 GMP 语料做文本匹配修补。
本轮只修复测试构造和增加合同检查，没有修改生产翻译/评估代码或通过条件。
原 Phase192 双端机器事实、原 Pipeline、18 格 L0 和默认重复参数 10 均保持原样。
完整 ABI、内部对象合法性、规范实例执行覆盖和程序级 L2/L3 依旧未闭合。

## 1. 更新新工作树

直接在当前终端设置变量，再进入子 Shell 执行 git 操作。

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE188_ROOT:?}" "${PHASE185_BUNDLE:?}"
export PHASE193_TOOLING="$PREP_ROOT/tooling-phase193"
export PHASE193_PARENT="$(mktemp -d "$PHASE188_ROOT/phase193-XXXXXX")"
export PYTHONPATH="$PHASE193_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE193_CLI="$PHASE193_TOOLING/experiment/automate_native_project.py"
bash -e <<'SETUP'
: "${REPO:?}" "${PHASE193_TOOLING:?}"
git -C "$REPO" fetch origin phase193-portable-shared-call-fixture
git -C "$REPO" worktree add --detach "$PHASE193_TOOLING" origin/phase193-portable-shared-call-fixture
git -C "$PHASE193_TOOLING" rev-parse HEAD
SETUP
```

## 2. 先针对当前阻塞测试

```bash
bash <<'TARGETED'
: "${PHASE193_TOOLING:?}" "${PHASE193_PARENT:?}"
python3 -m pytest -q -rs \
 "$PHASE193_TOOLING/pytools/tests/test_program_machine_inventory.py" \
 --basetemp="$PHASE193_PARENT/pytest-targeted" > "$PHASE193_PARENT/targeted.log" 2>&1
status=$?
printf 'targeted_status=%s\n' "$status"
cat "$PHASE193_PARENT/targeted.log"
exit "$status"
TARGETED
```

预期为 12 passed。若报错或跳过，先提供 targeted.log；不要先开展耗时的 GMP 实验。
测试目录保留 machine.S、machine.o、machine.so；反例目录还保留 legacy.o、link.stderr。
无需为了当前已明确的原因先收集其他 GMP 证据。

## 3. 回归通过后再推进真实实验

先重跑本轮完整定向回归，预期 101 项通过；本地结果不替代用户旧工具链复核。

```bash
bash <<'REGRESSION'
: "${PHASE193_TOOLING:?}" "${PHASE193_PARENT:?}"
python3 -m pytest -q -rs \
 "$PHASE193_TOOLING/pytools/tests/test_program_machine_inventory.py" \
 "$PHASE193_TOOLING/pytools/tests/test_program_proof_components.py" \
 "$PHASE193_TOOLING/pytools/tests/test_native_project_evaluation.py" \
 "$PHASE193_TOOLING/pytools/tests/test_native_project_campaign.py" \
 "$PHASE193_TOOLING/pytools/tests/test_native_original_evaluation.py" \
 "$PHASE193_TOOLING/pytools/tests/test_original_source_applicability.py" \
 "$PHASE193_TOOLING/pytools/tests/test_project_obligation_assessment.py" \
 "$PHASE193_TOOLING/pytools/tests/test_evaluation_state_separation.py" \
 "$PHASE193_TOOLING/pytools/tests/test_partial_program_evaluation.py" \
 --basetemp="$PHASE193_PARENT/pytest-full" > "$PHASE193_PARENT/focused.log" 2>&1
status=$?
printf 'focused_status=%s\n' "$status"
cat "$PHASE193_PARENT/focused.log"
exit "$status"
REGRESSION
```

全部通过后，执行原指南第三步的真实自动化实验：

```bash
bash <<'RUN'
: "${PHASE193_CLI:?}" "${PHASE193_PARENT:?}" "${PHASE188_ROOT:?}" "${PHASE185_BUNDLE:?}"
python3 "$PHASE193_CLI" run \
 --bundle "$PHASE185_BUNDLE" \
 --target-inputs "$PHASE188_ROOT/evaluation-target-inputs.json" \
 --source-baseline-inputs "$PHASE188_ROOT/evaluation-source-baseline-inputs.json" \
 --source-entry-inputs "$PHASE188_ROOT/evaluation-source-entry-inputs.json" \
 --qemu /usr/local/bin/qemu-riscv64 --runtime-prefix /usr/riscv64-linux-gnu \
 --gmp-seeds 42,43 --repetitions 10 \
 --ghidra-install-dir /opt/ghidra_11.2_PUBLIC --timeout-seconds 600 \
 --output "$PHASE193_PARENT/campaign" > "$PHASE193_PARENT/campaign.log" 2>&1
status=$?
printf 'campaign_status=%s\n' "$status"
cat "$PHASE193_PARENT/campaign.log"
exit "$status"
RUN
```

原请求 verified 返回 0，正常未 verified 返回 1，采集/输入异常返回 2。
L1 仍可能合理返回 inconclusive；修复测试夹具不能替代程序级缺失证明。
GMP 参数 10 仍保留尺寸覆盖条件，不等于严格固定十次，也不保证总体加速 100 倍。

## 4. 有实验记录后再检查与导出计时

```bash
python3 "$PHASE193_CLI" check --input "$PHASE193_PARENT/campaign/progress.json"
python3 "$PHASE193_CLI" timings --input "$PHASE193_PARENT/campaign/progress.json" \
 > "$PHASE193_PARENT/timings.json"
```

check 的成功表示记录一致，不等于语义验证通过。若第三步异常，先保留并提供 campaign.log，
不要检查尚未生成的下游 result.json。完整机器事实收据通过评估摘要的 machineInventory.path 定位。

请先提供 targeted.log 和 focused.log；通过后，再提供 campaign.log、campaign/progress.json、
已有的 evaluation-result.json、machine-inventory.json 和 timings.json。
