# Phase184：修复ABI检查器基础，不冒充完整native证明链

父远端提交：1670b898759b58fd209f637b19c9e1f546b51f35。

## 本轮完成与尚未完成

本轮核查复用ABI组件时发现并修复了会导致不收敛及错误接受的底层问题。
没有把native_contract_evidence中的缺失机器事实替换成猜测数据，没有把整体阶段改为通过。
**完整机器事实生产者、函数内部对象访问分析、规范实例指令覆盖及完整native L1–L3
证据接入仍未实现；本提交不是用户所要求完整工作链已经完成的证明。**

## 1. 定位与修复

### function_frame_analysis

旧实现共用一个sp字典存放块入口和出口：传播出口后，下一轮又用前驱的入口覆盖。
两块 -16/+16 的简单平衡帧也可能不断交替更新，旧正例测试无法结束。
旧实现还把退出块的入口SP当最终SP，并通过“RA有读有写”推断返回地址恢复。
寄存器恢复只检查出口附近是否有RESTORED标签，没有逐路径验证原值保存关系。

新实现分离incoming/outgoing，用有限格工作队列传播：不可达、精确偏移、未知偏移。
回边产生不同偏移时合并为未知，不枚举无穷偏移；寄存器状态按路径集合合并。
保存发生在值已被修改之后、只在另一条分支保存、未保存直接恢复等均不能证明保留。
退出摘要使用退出块转移后的状态；SP、FP、RA和各保存寄存器分别检查。
调用点必须提供相对块入口的SP偏移及对齐保证；SysV入口余数8与RV64余数0明确区分。
RA必须提供独立ra_updates；仅reads_ra/writes_ra不能证明保存恢复。

这是消费权威转移事实的抽象检查器，不是机器码解码器。SAVED/RESTORED必须由生产者
证明指向同一个保存的入口值；栈槽覆盖、别名及非回绕等事实未被证明时不能标complete。
本轮不允许将任意手填转移事实直接作为GMP机器证明输入。

### function_cfg_analysis

旧实现将asm节点追加到C节点列表，却没有要求替换真实C CFG占位节点，可能批准断开的区域。
新AsmRegionCfgFacts必须给出frontend_node_id，指向相同fragment身份的asm_placeholder。
构建器重定向进入边；区域退出必须提供显式编译器绑定的continuation边，不能猜测fallthrough。
检查节点、边、退出、占位成员、区域可达性及未登记终点。缺失/歧义保持不完整。
旧的无占位、无连接正例已改为显式连接模型，并保留原断开形状作为拒绝反例。

### function_abi_machine_join / function_abi_sidecar

加入声明参数/返回值位置和机器位置事实的显式对应；机器complete标记不能替代这些事实。
FunctionMachineAbiFacts新增entry_arguments、return_values及entry_sp_residue_bytes。
None表示未取得证据，不等同于无参数的空tuple。机器和栈帧入口余数须匹配实际ABI。
逐一核对退出摘要、恢复状态、对齐、已知trap/unwind属性及缺失原因。
启用unwind能力不等同于实际会unwind；真实异常路径仍要求独立路线，不能按普通返回批准。
Sidecar增加固定标量SysV AMD64配置并核对编译器triple；拒绝字符串伪布尔及类型宽度不匹配。

当前连接器的值位置完成范围明确限制为64位整数/指针及void返回。声明盘点可以保留窄类型，
但其寄存器扩展和读取视图证明尚缺时，机器ABI连接不能通过。FP、变参、聚合、异常展开和
其他不支持路线继续拒绝。这个范围限制没有降低旧证明要求。

## 2. 完整工作链的剩余代码工作

| 项目 | 可复用组件 | 仍需真正实现的生产/检查 |
|---|---|---|
| 机器ABI | 本轮CFG/帧/ABI连接器、compiler声明及ELF归属 | 绑定实际机器码和编译上下文的整函数解码；完备CFG；SP/FP/RA/栈槽/寄存器转移；调用链接选择和实际值位置；窄类型读取/扩展；独立重派生 |
| 内部对象访问 | native_api_contract、object_layout_contract、l2_memory_object | 参数到对象及地址表达式；循环/分支范围；生存期/初始化；所有适用调用的读写、逃逸、别名及前置条件；不支持语义不能省略 |
| 规范实例覆盖 | instance binding、native_entry_probe、原L3区域/轨迹组件 | 优化后的实例到规范机器码区域映射；删除/复制/合并的明确分类；实际装载身份与运行事件；插桩和自然运行范围分别声明 |
| L1–L3接入 | 原registry/运行器、l2_materialization及authority、L3分类与闭合 | 与本次部署一致的真实输入/观察适配；缺失provider；分开执行前合同和执行后比较，避免output-termination与L1循环依赖；适用层分类及程序级独立审计 |

native_contract_evidence.ast_graph仍以None调用ABI连接器；native_experiment_evidence主要消费
有限子目标。这是尚未打通的生产者—消费者连接，不能靠把complete/verified字段改真解决。
原L3组件的存在也不代表任意GMP函数已经满足其纯整数、对象、调用或后端支持范围。

## 3. 实验验证：无需先运行phase183，可直接使用本分支

已包含phase183的runtime.none/v1和C上下文续采修订。保留旧目录。

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE182_ROOT:?}"
git -C "$REPO" fetch origin phase184-machine-proof-foundations
export PHASE184_TOOLING="$PREP_ROOT/tooling-phase184"
git -C "$REPO" worktree add --detach "$PHASE184_TOOLING" origin/phase184-machine-proof-foundations
export PHASE184_ROOT="$(mktemp -d "$PHASE182_ROOT/phase184-XXXXXX")"
: "${PHASE184_ROOT:?}"
export PYTHONPATH="$PHASE184_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE184_CLI="$PHASE184_TOOLING/experiment/advance_native_closure.py"
git -C "$PHASE184_TOOLING" rev-parse HEAD
printf 'PHASE184_ROOT=%s\n' "$PHASE184_ROOT"
```

```bash
python3 -m pytest -q -rs \
 "$PHASE184_TOOLING/pytools/tests/test_function_frame_analysis.py" \
 "$PHASE184_TOOLING/pytools/tests/test_function_cfg_analysis.py" \
 "$PHASE184_TOOLING/pytools/tests/test_function_abi_machine_join.py" \
 "$PHASE184_TOOLING/pytools/tests/test_function_abi_sidecar.py" \
 "$PHASE184_TOOLING/pytools/tests/test_phase8_function_abi_validation.py" \
 "$PHASE184_TOOLING/pytools/tests/test_native_l0_contract.py" \
 "$PHASE184_TOOLING/pytools/tests/test_native_l0_materialization.py" \
 "$PHASE184_TOOLING/pytools/tests/test_native_entry_probe.py" \
 --basetemp="$PHASE184_ROOT/pytest-focused" > "$PHASE184_ROOT/focused.log" 2>&1
PHASE184_STATUS=$?
printf 'phase184_focused_status=%s\n' "$PHASE184_STATUS"
cat "$PHASE184_ROOT/focused.log"
```

真实机器测试失败后停止依赖步骤，不对不存在的result运行check/refine。
原测试正例的输入事实被加强，不是将失败期望改成通过；未知/不一致输入有独立反例。

接下来映射phase183指南变量到本轮目录，跳过其创建旧工具的第一段：

```bash
export PHASE183_TOOLING="$PHASE184_TOOLING"
export PHASE183_ROOT="$PHASE184_ROOT"
export PHASE183_CLI="$PHASE184_CLI"
```

执行[phase183指南](phase183-native-runtime-contract.md)第二节：重新审计部署、建立基础合同，
优先生成api-plan.json和真实L0矩阵。新源码改变验证器清单，不复用旧审计冒充新版本。
完成后再按其第三节续采C上下文；取得回执不等于ABI或对象证明通过。

## 4. 下一份必要的真实输入

先返回focused.log；其后只返回实际已经生成的文件：

- 本轮api-plan.json：实际函数、三端接口、输入域模板和编译器绑定的函数正文。
- l0-inputs/result.json和framework/result.json：实际规范构建/执行身份，或首个失败日志。
- context-resolution-complete/result.json：当前调用义务；未执行续采则先不提供。

函数前置条件须引用实际实现/项目文档或可信接口合同，不能从函数名推断。
仅补充数据仍不会自动生成尚不存在的机器事实及对象访问生产者；这两类实现必须继续开发。
本轮修复这些消费者的错误，为后续复用提供可靠基础，但尚未完成完整工作链请求。

## 本地回归

38模块联合回归499通过、5环境跳过（353.58秒）。最终出口清单强化后，
底层/整函数10模块72通过，native合同盘点/重派生2通过；组间重叠，不相加。
跳过包括2个ptrace和3个真实跨架构测试，未计为通过。日志与模块列表位于
experiment/baselines/phase184/。本地没有完成真实GMP整程序接受或全机器事实生产。
