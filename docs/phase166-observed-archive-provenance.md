# Phase166：观察归档生成关系，不放宽依赖与语义验收

基线：Phase165，`a351cd64cb25159ec8d7b0da360b95116ceef140`。
分支：`phase166-observed-archive-provenance`。

## 已确认的问题与修订边界

主机使用 GNU ar/ranlib 2.30。Phase152 捕获了最终一次 `ar cq .libs/libgmp.a ...`
及八次 ranlib 调用，全部成功退出，但没有归档输出摘要或归档输入的执行时快照。
最终归档 argv 指向12个非 .libs 输入对象；同字节的 PIC 对象只是其它候选。
argv 是重要选择依据，但不能单独补成历史输入/输出字节证明。

本轮新增通用 GNU 常规归档追加、索引操作证据及来源选择。不会替旧报告补写事实，
不会按 .libs、成员名称、PIC 标记或数组顺序猜测来源；不会改变生产编译参数。
5个外部符号义务、目标 ABI/链接/调用/对象合同及程序级 L0–L3 仍需后续证据和实现。

## 实现

* `project_archive_provenance.py`：显式绑定工具 profile/version/digest，支持已建模的
  GNU ar q（可带 c/D/U/s/S/v）和单归档 GNU ranlib（可带 -D/-U）。其它语法保持
  unsupported，不阻止构建工具按原参数执行，但不能授予来源选择。
* opt-in capture 在工具执行前保存归档存在性、原归档字节、按顺序排列的输入对象；
  执行后保存输出及输入再次观察。字节以内容寻址 blob 独立、排他发布，保留重复名。
* 同一 capture 内按归档 canonical path 对合作的 ar/ranlib 写者加文件锁，覆盖快照、
  工具调用和收尾。不是所有外部进程的锁，也不是反对抗的系统级不可变性保证。
  原项目进程树完整性仍为 false。输入前后相同不证明不存在 ABA 写入。
* 独立读取 blob 重建追加成员序列；ranlib 必须保持全部有效载荷与成员顺序。
  操作链必须从观察到归档不存在开始，每一前驱/后继摘要相接、时间不重叠，最终摘要
  匹配本次指定归档。不会只挑一个字节匹配的尾部动作。
* 为所有 opt-in 构建动作记录调用时间区间；成员输入的路径、解析路径及摘要须匹配
  捕获产物，生产动作须在归档开始前完成。多个历史生产动作仍有歧义时不会任意选一个。
  单调时间绑定 Linux boot identity，新调用不能跨重启混用时间域；已有快照仍可只读重放。
* `archiveActionSelectionVerified` 仅表示归档生成关系闭合；
  `archiveMemberBuildSelectionVerified` 另行检查所选成员的构建身份。
  两者均不授予链接、ABI、动态行为或语义验收。
* 普通旧 capture、依赖 v1 报告继续使用原投影。新 opt-in 依赖报告采用 v2；
  旧17项不会被追溯改写。新 CLI archive-chain / replay-archive 可在无需翻译候选时
  先核验归档证据；阻塞的盘点可成功重放，CLI 不把它解释成验收通过。
* `collect_native_runtime_basis.py` 只读收集源/目标编译器查询、实际 ELF 候选及完整
  readelf 头部、动态符号和版本信息。不解释链接脚本、不运行测试程序、不授予提供者
  或外部行为合同，供下一步分析5项外部义务。工具与文件有摘要和收尾检查。

## 主机验证：保留旧树，使用新目录

不必重复下载、不覆盖原源码、旧候选、归档及成功的原生测试基线。
本轮确实需要一次**新的受控构建**，因为缺失的历史快照无法恢复。仍启用原 assembly、
shared/static，保持原 CFLAGS，不关闭栈保护、fortify 或断言。

### 1. 更新并建立新结果目录

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE163_ROOT:?}" "${ARCHIVE_ROOT:?}"
git -C "$REPO" fetch origin phase166-observed-archive-provenance
export PHASE166_TOOLING="$PREP_ROOT/tooling-phase166"
git -C "$REPO" worktree add --detach "$PHASE166_TOOLING" origin/phase166-observed-archive-provenance
export PHASE166_ROOT="$(mktemp -d "$PHASE163_ROOT/phase166-XXXXXX")"
export PYTHONDONTWRITEBYTECODE=1
printf 'PHASE166_ROOT=%s\n' "$PHASE166_ROOT"
git -C "$PHASE166_TOOLING" rev-parse HEAD
```

如果工具树已存在，另取新路径，不要删除历史工作树。保留原 Clang、RISC-V GCC 和
已构建前端环境变量；新数据不代表该前端已更新或完成程序验收。

### 2. 先运行专项及既有回归

```bash
bash -e <<'TESTS'
: "${PHASE166_TOOLING:?}" "${PHASE166_ROOT:?}"
export PYTHONPATH="$PHASE166_TOOLING/pytools"
python3 -m pytest -q -rs \
  "$PHASE166_TOOLING/pytools/tests/test_project_archive_provenance.py" \
  "$PHASE166_TOOLING/pytools/tests/test_native_dependency_inventory.py" \
  "$PHASE166_TOOLING/pytools/tests/test_project_build_capture.py" \
  "$PHASE166_TOOLING/pytools/tests/test_project_acquisition_driver.py" \
  "$PHASE166_TOOLING/pytools/tests/test_native_runtime_basis.py" \
  --basetemp="$PHASE166_ROOT/pytest" --junitxml="$PHASE166_ROOT/focused.xml" \
  > "$PHASE166_ROOT/focused.log" 2>&1
TESTS
TEST_STATUS=$?
printf 'phase166_test_status=%s\n' "$TEST_STATUS"
cat "$PHASE166_ROOT/focused.log"
```

非零时先停止后续构建，提供该日志。本地跨架构协议测试明确使用人工修改 ELF header
验证拒绝逻辑，不等同于真实 RISC-V 翻译测试。

### 3. 用新捕获配置执行一次新的官方构建

```bash
bash -e <<'BUILD'
: "${PHASE166_TOOLING:?}" "${PHASE166_ROOT:?}" "${PREP_ROOT:?}" "${ARCHIVE_ROOT:?}"
test -f "$ARCHIVE_ROOT/gmp-6.3.0.tar.xz"
bash "$PHASE166_TOOLING/experiment/acquire_real_project_builds.sh" \
  "$PHASE166_TOOLING" "$PREP_ROOT" "$ARCHIVE_ROOT" \
  "$PHASE166_ROOT/gmp-native" gmp --archive-provenance \
  > "$PHASE166_ROOT/gmp-driver.log" 2>&1
BUILD
BUILD_STATUS=$?
printf 'phase166_build_status=%s\n' "$BUILD_STATUS"
tail -n 80 "$PHASE166_ROOT/gmp-driver.log"
if test -f "$PHASE166_ROOT/gmp-native/run-status.json"; then
  cat "$PHASE166_ROOT/gmp-native/run-status.json"
fi
```

该入口仍会执行源码核验、configure、build、捕获导入及编译上下文检查。若构建成功但
后续 inspect 失败，先提供 run-status 和相应阶段日志，不要将整个目录删掉重跑。
配置中 archiveCapture 应显式存在，且 tools 含 ar=gnu-ar、ranlib=gnu-ranlib。
不要把旧 capture 的 moduleDigest 改成新值来伪造迁移。

### 4. 先核验归档链及独立重放

```bash
bash -e <<'CHAIN'
: "${PHASE166_TOOLING:?}" "${PHASE166_ROOT:?}"
python3 "$PHASE166_TOOLING/experiment/inspect_native_dependencies.py" archive-chain \
  --records "$PHASE166_ROOT/gmp-native/records.json" \
  --archive "$PHASE166_ROOT/gmp-native/build/.libs/libgmp.a" \
  --output "$PHASE166_ROOT/archive-chain" > "$PHASE166_ROOT/archive-chain.log" 2>&1
python3 "$PHASE166_TOOLING/experiment/inspect_native_dependencies.py" replay-archive \
  --input "$PHASE166_ROOT/archive-chain/result.json" \
  --output "$PHASE166_ROOT/archive-replay" > "$PHASE166_ROOT/archive-replay.log" 2>&1
CHAIN
CHAIN_STATUS=$?
printf 'archive_chain_status=%s\n' "$CHAIN_STATUS"
cat "$PHASE166_ROOT/archive-chain.log" "$PHASE166_ROOT/archive-replay.log"
```

检查 chain/result.json 的 selection.complete 与 archiveActionSelectionVerified，不能只看
退出0。unsupported、既有归档无来源、链中断、成员变化、最终摘要不匹配都必须保留。
若尚阻塞，提供该报告，不要手工改状态或成员来源。

### 5. 用新归档分析已有候选的依赖，保持候选不变

```bash
bash -e <<'DEPENDENCIES'
: "${PHASE166_TOOLING:?}" "${PHASE166_ROOT:?}" "${PHASE162_ROOT:?}"
python3 "$PHASE166_TOOLING/experiment/inspect_native_dependencies.py" inventory \
  --candidate "$PHASE162_ROOT/candidate/candidate.json" \
  --records "$PHASE166_ROOT/gmp-native/records.json" \
  --archive "$PHASE166_ROOT/gmp-native/build/.libs/libgmp.a" \
  --output "$PHASE166_ROOT/dependencies" > "$PHASE166_ROOT/dependencies.log" 2>&1
python3 "$PHASE166_TOOLING/experiment/inspect_native_dependencies.py" replay \
  --input "$PHASE166_ROOT/dependencies/result.json" \
  --output "$PHASE166_ROOT/dependency-replay" > "$PHASE166_ROOT/dependency-replay.log" 2>&1
DEPENDENCIES
DEPENDENCY_STATUS=$?
printf 'dependency_status=%s\n' "$DEPENDENCY_STATUS"
cat "$PHASE166_ROOT/dependencies.log" "$PHASE166_ROOT/dependency-replay.log"
```

该步骤是新依赖证据对既有候选的**诊断分析**，不是证明新配置可无条件替换候选原配置。
检查12项多身份是否由明确 archiveInput + selectedBuildActions 关闭；其它来源未闭合时
继续报告。预计外部符号义务仍在，但不硬编码总数为5。初始/重放数量必须相同。
源、目标导出名称相同不证明 ABI 或依赖相容，所有语义和生产验收标记保持 false。

### 6. 收集下一步外部提供者分析依据

```bash
bash -e <<'RUNTIME'
: "${PHASE166_TOOLING:?}" "${PHASE166_ROOT:?}" "${RV2X86_TEST_RISCV_CC:?}"
export SOURCE_LOADER="$("$RV2X86_TEST_RISCV_CC" -print-file-name=ld-linux-riscv64-lp64d.so.1)"
test -f "$SOURCE_LOADER"
python3 "$PHASE166_TOOLING/experiment/collect_native_runtime_basis.py" \
  --compiler "$RV2X86_TEST_RISCV_CC" \
  --compiler /usr/bin/x86_64-linux-gnu-gcc-7 \
  --library libc.so.6 --library libgcc_s.so.1 \
  --file "$SOURCE_LOADER" \
  --file "$PHASE166_ROOT/gmp-native/build/.libs/libgmp.so.10" \
  --output "$PHASE166_ROOT/runtime-provider-basis.json" \
  > "$PHASE166_ROOT/runtime-provider-basis.log" 2>&1
RUNTIME
RUNTIME_STATUS=$?
printf 'runtime_basis_status=%s\n' "$RUNTIME_STATUS"
cat "$PHASE166_ROOT/runtime-provider-basis.log"
```

库名和路径仅是此次收集请求，不是代码白名单。查询结果不是实际链接/加载选择；
libc/loader 中找到符号也不等于外部行为合同成立。后续需链接映射、符号版本、目标
调用/数据对象合同以及实际运行加载证据。不要用成功源端基线替代目标端证明。

## 应返回的材料与后续边界

返回 focused.log、gmp-native/run-status.json、archive-chain/result.json、
dependencies/result.json、两类 replay 日志及 runtime-provider-basis.json。
失败则附对应阶段日志，不必再次上传完整全部构建动作。

新的归档链通过后，继续独立建立源/目标外部提供者、目标依赖构建及授权链接、调用与
对象合同、实际实例观察和程序级 L0–L3。历史69项后端诊断未由本轮“修复”，应按最终
路线在新目录准备和校准必要后端；不能为了静态清零重哈希历史后端。

## 本地验证记录

最终相关回归：455 passed，10 skipped，36.85 秒。范围包括 native/project 全部测试、
GNU 操作数关系、函数类型及调用清单/依赖。跳过项依赖本环境没有的真实 Clang、RISC-V
GCC 或已构建前端，不应解释为这些集成已通过。真实 GNU ar/ranlib、重复成员名、长文件名、
多次追加、并发合作写者、同字节不同产物、时间域与生成顺序、索引不改变有效载荷、证据
缺失/篡改、旧捕获不追溯批准及新 v2 依赖报告重放均有回归。Python 编译检查、diff 检查
及本文全部 Bash 代码块的 bash -n 检查通过。主机 Binutils 2.30 和完整 GMP 构建仍需按上文验证。
