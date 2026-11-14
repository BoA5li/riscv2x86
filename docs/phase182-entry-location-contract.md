# Phase182：入口代码位置连续性与原 L0 序列化修复

父远端提交：4bf77c2c2aae792adfddfa6ea5303abe05c931f1。

## 本次证据和确定根因

收到的 capture.json 记录一个候选函数入口，armedEpoch=2、hitEpoch=15，
armedStopOrdinal=145、hitStopOrdinal=326、returnCode=0、failureReason=null。
入口地址140688597168544，命中RIP=140688597168545。
补充附件为 epoch15；其原始JSON（不含末尾换行）的摘要与capture中epoch15摘要一致。
结合贴出的epoch2，入口所在VMA的end由140688599400448缩短为140688597295104。
其余端点映射字段及capturedFileStat相同；入口的文件偏移保持369056。
这是旧derive整条mapping相等规则的确定反例。尚未取得全部中间快照和镜像blob，
因此没有声称本机已经重派生通过用户的完整原始捕获。

native_entry_probe.location_relation比较入口地址、原字节、摘要、完整file stat、
设备/inode/路径/权限及地址到文件偏移的关系。设置断点快照仍要求mapping完全相等。
后续快照允许不影响此关系的VMA边界变化。
transition_preserves_entry逐一检查受支持映射系统调用的影响区间，拒绝任何触及
入口页内代码位置的mmap、mprotect、munmap、mremap；即使重新映射同一文件也不接受。
采集端和重派生端复用这些规则。未知变化拒绝。后端明确限Linux x86-64 4KiB页面；
不宣称防止任意进程内存写入、未观察系统机制或无ptrace运行等价。
错误现在按address、original-byte、file-stat、mapping-identity、file-offset等分类。

native_framework_admission.artifacts显式将ignored_source_state输出为公开JSON数组。
原translation_artifact_from_dict保持严格。新增直接内存解析/JSON往返/identity一致性测试。
没有删除矩阵单元或接受部分构建，也没有修改原L0的摘要或通过规则。

## 必须区分的剩余工作

当前实现尚不能完成全部五阶段接受；以下是实现计划，不是已经实现的能力。

| 工作 | 证据生产与检查要求 | 当前边界 |
|---|---|---|
| 原生依赖来源 | configure/build阶段冻结响应文件及归档操作，按产物与操作身份重建；未知生产链拒绝 | 历史缺失字节不能恢复；需新构建，不拼接新旧状态 |
| C/汇编调用范围 | 按上下文身份续采C回执；汇编接口、间接目标集合、实际链接选择单独建合同 | 13/466消费不是完整闭包；静态符号唯一不是实际调用证明 |
| 运行绑定 | 明确诊断运行和自然运行的身份范围，完整请求方/提供者/版本及适用重定位效果 | 602个诊断端点不能替代自然运行语义 |
| 机器ABI | 声明/编译上下文/实际符号一致性，参数与返回槽位、栈对齐、保存寄存器及适用异常约束；每项绑定实际机器码与可核验见证 | 当前类型断言和槽位模型不是完整机器ABI证明 |
| 合法对象域 | 明确调用前条件；构造初始化、生命期、容量/对齐/别名；另外检查被调用路径实际访问范围与外部效果 | 当前驱动仅保证受限输入构造；内部访问仍需模型或可核验分析 |
| 输出与终止 | 源目标相同输入、明确观察策略；正常/错误/保护失败路径分别检查；环境效果和未覆盖分支列义务 | 单个API输出一致不能消除其他路径义务 |
| 规范实例覆盖 | 编译器源码位置/机器码区间映射，绑定规范产物、实际装载镜像及运行事件；计入所有未命中实例 | 插桩替换语句完成计数不等于规范指令覆盖 |
| 原L0–L3与汇总 | 复用原运行器；适用层真实执行；阶段检查器消费足够且同源的证据再推导状态；缺失/不支持保持未知 | 目前完整阶段检查器和所有证据生产者尚未齐备 |

不得通过把固定false改true、直接移除准入或把局部子目标当整体阶段来实现闭合。
通用性来自编译器/ELF/调用接口/映射关系与身份绑定，不来自GMP函数名或地址常量。
有限支持范围必须声明；不支持的汇编效果、间接调用或对象关系仍报告inconclusive。
这也意味着不能承诺仅执行已有命令即可验证任意真实项目。

## 1. 新建工具与实验目录

保留旧失败目录。请逐块执行；首个失败后停止依赖步骤，先返回该日志。

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE181_ROOT:?}"
export PHASE182_PREVIOUS_ROOT="$PHASE181_ROOT"
git -C "$REPO" fetch origin phase182-entry-location-contract
export PHASE182_TOOLING="$PREP_ROOT/tooling-phase182"
git -C "$REPO" worktree add --detach "$PHASE182_TOOLING" origin/phase182-entry-location-contract
export PHASE182_ROOT="$(mktemp -d "$PHASE182_PREVIOUS_ROOT/phase182-XXXXXX")"
: "${PHASE182_ROOT:?}"
export PYTHONPATH="$PHASE182_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE182_CLI="$PHASE182_TOOLING/experiment/advance_native_closure.py"
git -C "$PHASE182_TOOLING" rev-parse HEAD
printf 'PHASE182_ROOT=%s\n' "$PHASE182_ROOT"
```

## 2. 先复验两个直接阻塞

```bash
python3 -m pytest -q -rs \
 "$PHASE182_TOOLING/pytools/tests/test_native_entry_probe.py" \
 "$PHASE182_TOOLING/pytools/tests/test_native_framework_admission.py" \
 "$PHASE182_TOOLING/pytools/tests/test_native_l0_materialization.py" \
 --basetemp="$PHASE182_ROOT/pytest-focused" \
 > "$PHASE182_ROOT/focused.log" 2>&1
PHASE182_STATUS=$?
printf 'phase182_focused_status=%s\n' "$PHASE182_STATUS"
cat "$PHASE182_ROOT/focused.log"
```

非零则停止，回传focused.log。真实ptrace和真实RV64矩阵在本地受限环境不可用，
你的实验容器应实际执行这些测试，不能以跳过替代成功。

## 3. 用新验证器重新建立审计和部署证据

新源码改变验证器清单，不能直接将新工具套在旧审计上。
为复用phase181逐步指令，以下显式将PHASE181工具/输出变量指向本轮新目录；
旧值已保存在PHASE182_PREVIOUS_ROOT中，旧结果不会被覆盖。

```bash
: "${PHASE179_ROOT:?}"
export PHASE181_TOOLING="$PHASE182_TOOLING"
export PHASE181_ROOT="$PHASE182_ROOT"
export PHASE181_CLI="$PHASE182_CLI"
export PHASE181_PLAN="$PHASE179_ROOT/deployment/plan.json"
export PHASE181_CLANG="$(command -v clang-10)"
: "${PHASE181_CLANG:?}"
```

继续执行[phase181指南](phase181-native-api-admission.md)第2步联合回归、
第3–15步重新审计/部署/采集/入口检查。不要再次执行其第1步创建旧工具目录。
每个命令检查退出码；上游失败后，不再对未生成的result.json运行check/refine。
本轮已定位的入口问题还必须通过真实GMP捕获和check，不能只靠合成测试。
若失败，返回新的function-entry.log及trace/capture.json，不编辑原始证据。

## 4. 继续API与原L0实验

入口检查成功后执行phase181指南第16–20步。先导出api-plan.json，
再依据实际函数声明/实现/文档明确前置条件和有限输入域；不得猜测库函数可用参数。
第19步真实原L0矩阵可在输入域尚未审定时独立进行，其输入是基础合同和实际候选，
不是API成功状态；准备接口时使用同一基础合同身份。

若L0真实构建失败，先检查对应单元日志；不删优化级别、Clang或消毒器单元。
若完整语义层被entry-abi/legal-objects-inputs等准入阻挡，说明对应检查器/合同仍缺，
不属于本次入口或序列化修复再次失败。

首批回传：focused.log、联合回归focused.log（注意路径）、function-entry.log、
function-entry/result.json和phase181-entry-summary.json。进入L0后再提供其首个失败日志
或framework/result.json。修复两个直接阻塞不代表最终语义接受。

## 本地验证结果

定向回归41通过、2跳过；同一21模块联合回归314通过、5跳过，353.12秒。
跳过2项ptrace路径和3项真实跨架构路径，均未计为通过。
日志和摘要位于experiment/baselines/phase182/。尚未在本机完成用户GMP原始捕获
重派生或真实RV64矩阵；也没有实现全部整体合同闭合检查器。
