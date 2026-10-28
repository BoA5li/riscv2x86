# L3 完整工作链与覆盖扩展修订实施方案

## 0. 基线、结论与适用范围

基线是已验收分支 `phase121-memory-access-width-proof`，远端提交
`9f9b0ac403804048a394470185a83a6d0e4bc274`，代码树
`2271eb6a3116583a148fd7e6a784805bb2823858`。本方案依据对该树的代码核查，
以及用户提供的 Phase121 验收日志。它描述待实施设计，不代表下列新能力已经实现。

已确认验收：208 项针对性测试、双端共 8 项存储宽度校准、原始 narrow-store 的
L0–L3 与独立审计、17 项真实 typed-store 生产测试均通过。普通 8/16/32/64 位
store、非零常量偏移、较宽 unsigned 输入及既有返回形式已补齐，不再列为未实现。
共享严格 JSON 检查也已接入主要路线，后续任务是统一剩余边界并保持版本兼容。

目标范围：对具有完整源语义、已批准翻译关系、可证明前提和可提供观察证据的程序，
完整执行翻译、L0–L3 与独立审计；对仍缺少证据的程序精确定位缺失层。
现有 gate 不能被当成天然支持范围的最终定义；具有可补足证明/观察能力的输入，
应通过实现能力解除阻塞，而不是改写为无需 L3。无前提的任意 C/汇编支持、
物理缓存时延、预测/推测行为、无界并发进展等不能由本路线的通过结论推出。

所有新增路线必须保持：

1. 义务由源语义和批准关系产生，不能由当前 observer 支持情况删减。
2. 类型、ABI、参数、对象、表达式及区域来自编译器和规范化 IR，不解析源码名字猜测。
3. 访问宽度、载体宽度、寄存器宽度、扩展/截断语义分别建模。
4. 动态事件必须来自实际执行。静态 fence 锚点、理论访问或预期结果不得伪装成观察。
5. 证明、捕获、比较、独立审计分层；同一套错误比较逻辑的重复调用不足以构成独立依据。
6. 新增能力使用明确版本与校准；保留已验收旧路线及其严格检查。
7. 对每个被执行的语义区域核对必需效应和性质，不能仅比较最终函数结果。

## 1. 具体定位及修改边界

下列路径均相对 `pytools/riscv2x86_py/`，runtime 路径另行标出。

| 项目 | 已核查位置及实际限制 | 需要联动的层 |
|---|---|---|
| 联合机制 | `l3_mechanism_selection.plan` 要求 `len(mechanisms)==1`；`produce/build_route` 单分派 | planning、intent、部署、联合 observer、比较、审计 |
| 计划完整性 | `l3_execution_plan.build` 按成员机制是否在 capabilities 中置 ready；fence/atomic 仅在单 finding 时尝试 spec | 将类型/调用/源证明/部署/观察/审计就绪分开，不能把存在 backend 等同于完整可执行 |
| 编译器区域 | `compiler_program_regions.export` 仅直接语句、纯叶表达式和结尾 return，2–16 个 asm | 源 AST/CFG、表达式与内存效应、控制/调用闭包 |
| L2 跨区域关系 | `l2_fragment_execution.materialize_fragment_execution_authority` 构建值依赖图；当前图拒绝 cycle，部分 operand observation 要求唯一 producer/consumer/sink | 版本化内存依赖、控制边、fan-out/merge、循环迭代关系 |
| 程序 spec | `l3_program_spec.spec` 单函数、纯标量，逐成员调用 `scalar_spec` | 通用成员契约与整体效应闭包 |
| 程序部署 | `l3_program_deployment.bound/build_side/prepare` 单函数、scalar call/vector harness，精确函数代码/执行镜像检查 | 通用调用、目标区域映射、可达函数、重定位证明 |
| 程序捕获 | `l3_program_backend.parse_capture` 按固定区域顺序各执行一次；`runtime/l3_qemu_program_trace.c` 固定 16 区域且不读取寄存器值 | 版本化执行实例/边/迭代协议；能力校准及预算 |
| 程序比较 | `l3_program_route.comparison` 将任何区域数据访存视为错误，主要比较函数结果；`fragment_result` 仅允许 access-pattern 单性质 | 按效应/性质的组合比较和跨区域比较 |
| 调用类型 | `compiler_memory_signature.type_fact/export` 支持有限 LP64 整数/指针/void 类型事实；`l3_scalar_call` 1–4 个 integer64 参数、integer64 返回 | 统一编译器类型及 ABI 契约，逐个 ABI 类型族启用 |
| 普通访存 | `memory_access_semantics.decoded_access` 恰好一个 LOAD/STORE；`l3_memory_intent.memory_spec` 一个对象、效应和关系 | 有序 access 集合、对象集合、别名与作用域证明 |
| 窄 load | `candidate_plans._memory_renderer_semantic_contract_id`、`c_module/phase6c_x86_memory_inline_asm` 的 load ID 为 32/64；`decoded_access` 不接受待证明的载入后扩展 | Phase6A–F、L2 值/对象观察、L3 类型化 harness |
| store 调用 | `l3_memory_call.bind` 两参数、unsigned、pointee 宽度等于访问宽度；`compiler_continuation_sites.memory_store_function_scope` 独立 asm/受限 indexed return | 通用值/地址表达式、外壳、输出与副作用闭包 |
| 控制 | `l3_control_spec.spec` 寄存器域、单 control-flow authority；`signature` integer64 | 多性质区域、逻辑控制边、条件对象状态和多出口 |
| fence | `l3_fence_spec.spec` 无参数 void、独立 rw/rw、mfence 合同；不能带 memory objects | 动态前后事件与批准 ordering relation；其它已证明 fence |
| 原子地址 | `memory_address_projection.project_memory_address` 仅精确 `*decl`，直接导出 offsetBytes=0；`l3_atomic_spec.spec` 又要求 offset=0 | 编译器地址表达式闭包、一次求值、对象范围、harness 地址、机器归因 |
| 原子调用 | `l3_atomic_spec.spec` 单函数、两参数、单对象、受限返回、四种 ordering | 通用调用/观察输出，按已批准顺序关系扩展 |
| 操作族与序列输出 | `l3_atomic_semantics.OPERATIONS` 五类 RMW；`lrsc_sequence` 当前四类算术/位运算；`l2_lrsc_authority.require_observable_scope` 要求 next/status dead/discarded | 源证明、目标实现、真实输出、归因与比较同时扩展 |
| 审计 | `l3_production_acceptance.audit_evaluation` 按 deployment 分支提前分派，control/fence/atomic/LRSC 各要求一个片段 | 通用 program acceptance，精确覆盖全部义务和捕获 |
| 环境 | `l3_sync_obligations.build` 保留 visibility/environment required；manager backend 集合无对应项 | 接入现有 instruction visibility、controlled-system 契约与独立 L3 观察 |

重要补充：`test_controlled_system_production.py` 当前明确要求 L3 not_run、
L3Equivalent false。其 L0–L2 生产验收成功不能被升级描述为已完成环境 L3。
仓库已有 `l3_concurrency_campaign`、`l3_statistical_experiment`、
`l3_specialized_experiment`；应核查和复用其合同边界，不能假设这些模块的存在
就为自动单线程路线提供了真实并发或物理属性证据。

## 2. 依赖优先顺序与可交付阶段

| 阶段 | 主要成果 | 阶段退出条件 |
|---|---|---|
| P0 | 独立能力目录、阶段化诊断、统一数据模型/义务与覆盖分母 | 旧域不退化；所有新域明确指出缺失的证明/执行/观察/审计前提 |
| P1 | 类型化调用/对象/输出契约；普通窄 load 与扩展证明 | 调用和 load 的完整 L0–L3 正例、边界与反例通过 |
| P2 | 无环、多区域普通访存与标量联合执行，继而静态多对象 | 同一次调用完成 load→scalar→store；跨区域值/对象依赖和整体审计闭合 |
| P3 | fence→真实访存序列，atomic/LRSC 与地址/输出泛化 | 动态事件与同步合同联合闭合；next/status 活跃时可真实观察 |
| P4 | 含内存的控制流、多出口、多区域及有证明界限的循环 | 可达边、路径、迭代、区域执行实例及所有效应完整 |
| P5 | 可达函数闭包、更多原子操作/ordering、指令可见性与受控环境 | 按能力子项独立完成真实观察与中央审计，不靠空结果通过 |

P5 的入口/可达函数身份设计应在 P0/P1 完成；先交付单入口无调用实例，之后启用
有完整摘要的可达 callee。操作族可在底座成熟后并行于某一阶段的独立工作项实施，
但不能先增加白名单再等待证明与 observer 补齐。

第一条联合正例建议：一个有效整数对象、同一函数、无环、三个独立已证明 asm 区域，
完成 load→标量变换→store，并观察函数返回及对象最终状态。它能够暴露真正的
跨区域接口问题。初始切片通过不意味着多对象/分支/同步缺口已全部关闭。

## 3. P0：能力前提、义务和覆盖目录

### 3.1 修改现有 planning

修改 `l3_execution_plan.build` 和 `l3_mechanism_selection.plan`：

* 保留源义务生成；planning 消费义务和能力契约，不从测试 ID/文件名选择路线。
* 每成员保留 semantic profile、source model/proof、effect relation、function/region ID。
* 分别检查 type binding、call closure、L0–L2 approval、object closure、deployment、
  machine observation、comparison、audit；输出每一缺失项的阶段、性质和前提身份。
* 将组合限制表示为缺少联合执行能力，而不是改选一个成员机制或删掉其它性质。
* 静态成员可用状态、整体执行计划完整性、实际执行完成性使用不同字段。
  这些内部状态不得直接扩充/混淆现有 `ValidationStatus` 或 approval 枚举。
* 预算不足属于明确的 resource/budget disposition；不能误报为语义不支持，更不能
  将已捕获的前缀当成完整执行。

新增“能力契约目录”是拟议实现，可按现有模块风格落地，例如
`l3_capability_contract.py`；该名字不代表当前已存在。目录描述类型/区域/操作/观察
前提，支持域必须独立定义并可审计，不能由散落的当前 gate 自我定义。

### 3.2 义务补充

扩展 `l3_property_obligations`、`l3_sync_obligations`、requirements/profile schema：
在 fragment 性质之外，引入经批准的 program/region-edge/object 性质，如跨区域
内存效应顺序、逻辑路径、输入输出流、同步关系、完整成员闭包。新性质需要版本化
policy、unit、证据契约和结果结构，不能偷偷添加字符串后让旧消费者忽略。
“无此性质”必须有源事实依据；无观察器不能成为 not_applicable 的依据。

### 3.3 覆盖分母

复用 `l3_coverage` 与 `experiment/inspect_l3_workflow.py` 的报告统计基础，但增加
独立 compiler corpus inventory：分别统计文件/入口、可达函数、源 asm、逻辑区域、
义务和独立验收。缺报告、缺 attempt、漏提取 asm 必须仍在分母中。暂不从现有
report count 推断整个测试集覆盖率，也不将尚未被识别的片段从分母删除。

## 4. P1：统一类型、调用、对象与输出

### 4.1 编译器类型和调用事实

扩展/复用 `compiler_operand_type`、`compiler_memory_signature`、
`compiler_value_flow`、`compiler_expression` 和 `automatic_batch_cli.inspect_entry_points`。
建议增加版本化通用调用 DTO，至少包含：

* root function ID、source digest、ABI/profile、参数 declaration/type identity；
* integer 的有符号性、位宽、转换与表示前提；pointer 的宽度、pointee、qualifiers；
* 参数/结果求值图、一次/多次求值规则和副作用；
* result/void、自然活跃输出、被证明 dead 的输出及观察 sink；
* root 与可达 callee、外部 runtime 合同及禁止的未摘要副作用。

类型事实可以复用，但 memory/atomic/control 的调用许可不能互相冒充。
保留各路线专有前提，统一底层类型及表达式身份，不把所有 spec 简单合并成宽松字典。
逐个启用 ABI 类型族；aggregate/浮点/可变参数不应在无 ABI 证明时顺带启用。
纯整数 8/16/32/64 位及 void 是较小的首批域。signed 样本通过有定义的构造/转换产生，
避免把超范围 unsigned→signed 的实现相关结果当作跨平台通用语义。

### 4.2 对象与地址

将单 fragment 的 `object:0` 坐标视图提升为 invocation 内稳定对象模型，复用
`l2_memory_object`、compiler boundary 和现有 object authority，至少保存：

* 稳定对象 ID、分配/声明来源、lifetime、有效 extent、初始化区域和对齐依据；
* pointer 参数/局部值到对象的 view，字节偏移、求值身份、范围证明；
* must-alias/may-alias/disjoint 关系及其证明/输入域约束；
* 每个效应的读写范围、访问宽度、目标 value 节点和顺序关系。

不能因为两个参数声明不同就假定不别名，不能以某一次运行的地址不同证明整个域
不别名。别名场景使用同一 backing object 的多个合法 view，而不是两个伪造对象。
不兼容 effective type、越界、生命周期和不对齐不能通过扩大 buffer 掩盖。
地址检查必须使用真实对象 extent；偏移非负不等于 bounds proof。

### 4.3 运行调用与输出

统一产生 sample plan、typed harness 和输出协议，逐步替换各路线受限生成器。
保留 Phase121 的真实 typed backing object 和逐字节边界检查。
按确定类型观察 return、out-parameter、对象和自然活跃结果；不得读取未初始化局部、
padding 或已证明不可观察的中间状态。aggregate 若后续启用，应序列化字段而非比较
不确定 padding 字节。整个调用序列与输入域约束须写入计划身份。

### 4.4 普通 load 扩展

修改 `memory_access_semantics`、`source_model`、`candidate_plans`、
`c_module/phase6c_x86_memory_inline_asm`、`phase6d_x86_memory_asm`、
`phase6f_contract_registry` 及目标 catalog，沿实际 IR def-use 跟踪 LOAD 后的
COPY/SUBPIECE/INT_SEXT/INT_ZEXT，而非看到类型或助记符就选 movsx/movzx。

每次访问显式保存 memoryAccessWidth、architecturalResultWidth、carrierWidth、
extensionKind、truncation/projection、最终可见输出绑定。按位向量证明源到目标等价，
分别注册准确指令合同；32 位目标写引起的高位行为也需纳入证明。
L2/L3 同步消费该关系，不能仅增加 `_LOAD_IDS` 后沿用等宽校验。
正例覆盖符号位两侧；反例包括错误扩展、错误高位、错误访问宽度和输出被后续覆盖。

## 5. P2：区域、效应图与联合执行

### 5.1 编译器程序图

以新版本扩展 `compiler_program_regions.export`，保留 v1 旧路线：

* 节点包括 asm region、具有效应的 C shell、entry/exit、调用与条件/合流；
* 边包括执行先后、值流、memory RAW/WAR/WAW、控制依赖和批准的 ordering；
* 每条边绑定 declaration/value/object/statement identity 与来源；
* 多区域顺序由 CFG/编译器身份确认，不能仅用源码偏移排序代替 CFG；
* 无效应 C 外壳可由静态证明排除；有访存/调用的 C 外壳必须建模或明确拒绝。

`l2_fragment_execution` 现有 DAG、值边和观察 sink 能复用，但不能作为完整内存依赖图。
增加对象版本和跨区域 use/def；支持值 fan-out、条件 merge 时必须保留每条边。
旧 DAG cycle rejection 保留；循环使用独立有循环语义的新版本，不能直接删检查。

### 5.2 单片段多访问

将 `decoded_access` 的单记录接口扩展为有序访问集合的新模型，保留单访问兼容入口。
每个 access 有独立 ID、宽度/地址/值表达式、volatile/atomic 属性、控制条件及证明。
Phase6B–F 对整个效应图建立目标 refinement，允许变化仅来自批准关系；不能通过
原样输出未翻译 RISC-V 或任意模板拼接扩大支持。先覆盖有限直线访问和已证明算术，
再扩展复杂地址/分支。多片段各一个访问与单片段多个访问应作为两个独立覆盖维度验收。

### 5.3 联合执行契约

新增通用 program spec/deployment/capture 版本。可采用新模块承载；旧
`l3_program_spec` 的纯标量 v1 继续可用。联合 spec 至少绑定：

```
program/source/policy identity
root + reachable functions
compiler region/effect graph identity
call + object + sample-plan identities
members: fragment/region/proof/effect-relation/required-properties
source/target machine-region maps
observer capabilities and calibration identities
execution closure + comparator/audit contract versions
```

以上是字段语义草案，不是可绕过既有 parser 的现成 JSON。
规划先验证整体联合契约，再选择能够覆盖全部必需事件的 backend。
`l3_mechanism_selection` 对完整联合域分派新联合 route；旧单机制仍走已验收路线。

### 5.4 部署与编译一致性

复用 `l3_program_deployment.instrument/label_assembly` 的 zero-byte metadata、
原始 APP 边界与 exact-code/ELF image 检查。标签必须绑定真实编译器区域；
不能把参数计算、spill、harness 或其它函数随意计为 asm 区域访问。
若一个目标替换对应多个基本块/区域，必须由 renderer 提供批准映射。

当前 exact function bytes 对既有域继续强制。未来存在 callee/链接重定位时，
设计单独的重定位感知证明：比较代码及重定位记录、符号解析与实际调用目标，
固定并验证 link inputs/flags。不能把现有“代码相等”检查直接删掉以支持新域。
日志或输出观察若改变编译/寄存器分配，必须验证语义及代码关系，不能默认无干扰。

### 5.5 观察与比较

`runtime/l3_qemu_program_trace.c` 与 `l3_program_backend` 需要新协议和校准。
P2 首批保留无环固定执行序列，但支持各区域实际 R/W 和对象归一化；跨调用共享同一
sample/invocation/token、对象布局和执行产物。对 raw absolute address 的归一化只
使用该次调用绑定的实际 object base/view，不在两 ISA 间比较原始地址。

联合事件模型为不同事件族定义独立字段，包含 occurrence、region、call、线程上下文、
PC、对象偏移/宽度、逻辑控制边和证据来源；没有读到的值不能填理论值。
现有 callback 只提供部分信息，访问值和内部寄存器值必须分别标注观察来源。
若验证性质需要内部值而现有观察手段不能无干扰取得，需新增并校准 observer，
或使用真正完整的批准抽象关系；不能声称已有原生寄存器观察能力。

比较器按批准 effect relation 消费动态事件，检查缺失/额外/顺序错误/错对象/错宽度。
不得对未获重排许可的 trace 排序后比较，也不能以最终对象相等容忍中间额外写。
标量片段可继续观察“无数据访问”这一 L3 性质；中间标量值若由 L2 完整覆盖，
应准确标注证据层，不能宣称 L3 直接观察到了它。

## 6. P3：fence、atomic 和 LR/SC

### 6.1 fence 联合上下文

保留 `l3_fence_spec` 独立 rw/rw 路线，新增复合区域 spec，复用 machine attribution。
把真实前后访问的动态实例链接到 fence occurrence 和批准 ordering relation。
目前 proof-context anchors 仍是静态事实，不能改名后当作真实前后 memory events。

其它 fence 形式按 source/target ordering、memory domain 和环境前提分别证明。
不能将所有 fence 都翻译或归类为 mfence；I/O、instruction visibility 与普通 coherent
memory 不能互相代替。动态顺序只证明执行了相应指令/事件，ordering 保证仍由批准合同
及机器归因提供；不能宣称单线程 trace 测量了物理乱序或跨线程可见性。

### 6.2 原子非零地址与调用

`memory_address_projection.project_memory_address` 先扩展为编译器确认的有限
pointer+constant/index 表达式；保留完整 type identity、C 元素尺度、求值次数、
边界/溢出/对齐/副作用约束。后续启用动态索引必须拥有可重放的范围证明。
同步修改 `l2_atomic_authority`、源地址绑定、`l3_atomic_spec`、harness、
`l3_atomic_machine/compare`、deployment 与 audit。不能仅删除 `offset!=0`。
样本初始化、执行地址、观察位置和邻接字节检查都围绕该实际偏移生成。

### 6.3 操作与 ordering 扩展

增加 min/max、compare-exchange 等前先确认源 decoder/模型、Phase6C/D、renderer、
L2 authority、L3 机器归因和 reference semantics 均完整。五项 OPERATIONS 字典不是
唯一支持开关。compare-exchange 必须建模 expected 的更新、成功/失败结果和不同
路径；若出现弱操作、允许的伪失败或不同失败 ordering，也须有独立批准关系。
seq_cst 等新增顺序同样需要对应证明，不能由“目标用了 lock”自动推出全部性质。

### 6.4 LR/SC 可见输出与重试

当前 `require_observable_scope` 对 next/status 的拒绝保留，直至新输出契约成立。
枚举每个活跃 GNU 输出及其 downstream use；将可见结果绑定到真正的 C 输出 sink、
对象或已校准 observer。只观察 return/object 的旧 harness 不能承担新义务。
目标内部寄存器与 source next/status 不要求逐寄存器相等，必须通过批准的逻辑输出
关系比较。若目标值并不存在，不得由预期公式生成一个“观察值”。

LR/SC 与目标 CAS 的失败/重试次数通常不是同一抽象观测量。通过已批准的重试
抽象和最终状态关系比较；检查实际完成路径和允许的失败行为。达到预算、截断 trace、
未完成操作均不算通过。成功样本不构成所有执行都会终止或并发进展的证明。

## 7. P4：控制流、循环和动态区域实例

扩展编译器 CFG/continuation facts、`l3_control_spec`、control machine/deployment、
program capture，以及联合 property comparator。

* 条件消费有类型位宽/有符号性的表达式，不将所有条件转成 unsigned64。
* 逻辑边以批准的 continuation ID 连接；两 ISA 的分支方向/跳转数量可不同，
  但实际机器路径必须映射到同一允许的逻辑路径/批准 refinement。
* memory/control/order 义务可同时存在；不能因 profile 选了 branch 就丢掉访存义务。
* 源 CFG 给出可达边和多出口，动态记录给出实际 occurrence。未走到但静态可达的边
  在覆盖统计中保持 uncovered，而不是视作不存在。
* 受限循环需要循环头、回边、归纳/不变量、迭代 bound 及退出条件证明；区分语义
  上界和执行资源预算。不能以 timeout 充当循环上界证明。
* 静态 regionId 与动态 occurrenceId/iteration/call 分开；更新当前一次一个区域的
  parser 和固定顺序状态机，检测 skip、duplicate、非法进入、非法退出及 trace 丢失。
* 使用有界反例和边界样本覆盖条件两侧、0/1/多次迭代、各可达出口与访存路径。
  按合同报告实际覆盖；既有静态证明负责的全输入结论不得由有限样本替代。

## 8. P5：函数闭包与环境路线

### 8.1 入口与 callee

用 compiler function identity 和可达调用闭包替代无条件 `len(functions)==1`。
无关函数不应阻塞入口；可达函数必须有完整效应/ABI/区域/退出摘要。
调用目标不能按函数名猜测；重载身份、函数指针、外部调用和递归分别处理。
首次支持有确定目标的无环调用图；间接调用若无法证明目标集合，保留明确缺口。
每次调用有 call instance，递归或重入不得复用错误的全局 region/object 状态。

### 8.2 指令可见性

复用 `instruction_stream_sync_contracts`、`instruction_stream_domain`、
`prepare_instruction_visibility*`、`instruction_visibility_harness` 与
`l2_instruction_visibility_runner`，先核查其实际承诺和实验产物，再接入 L3。
新义务需要真实代码/数据版本、同步操作、观察结果和环境身份；源目标机制可不同，
但可见性 refinement 必须有证明。普通 data-memory callback 不能证明取指可见性。

### 8.3 受控环境

复用 `controlled_system_contract/backend/runner/scope` 与现有环境 authority。
新增环境专用 L3 observer/contract、属性比较和中央审计，并接入 mechanism selection。
明确运行 privilege、模拟器/内核版本、初始状态、trap/完成语义及允许效应。
受控环境通过不能被表述为原 Linux user 程序等价。现有 L0–L2 受控验收继续保留。

若研究目标另外要求并发 outcome 或统计/平台属性，使用现有 campaign/statistical/
specialized contract 作为独立路线基础，确认真实 executor 与证据闭包，再接入统一
聚合。样本概率、实验轮次独立性、调度和置信区间不能伪装成 ISA 普遍等价证明。

## 9. 整体独立审计：贯穿 P0–P5

修改 `l3_production_acceptance.audit_evaluation` 与 program audit：先按明确的
schema/contract 收集执行单元，再对所有义务进行闭合，不因看到 atomicDeployment
等某个键就提前结束其它成员的检查。

1. 从源/compiler inventory 和 requirements 取得预期入口/成员/效应/性质集合。
2. 验证 evaluation/attempt/层次前提；缺层不能触发伪造的完整审计。
3. 重放编译器图、类型/对象/调用契约、proof/effect relation 及 deployment。
4. 校验实际工具/插件/实现依赖/机器映像与 calibration；前后复核防止执行期间替换。
5. 从 raw capture、命令 stdout、退出状态和 footer 独立重建事件及实际输出。
6. 检查每成员、性质和跨区域关系精确覆盖；多次动态执行按 occurrence 分组，不能
   把合法循环误作重复 fragment，也不能漏掉非法额外 occurrence。
7. 检查 shared execution identity、样本计划、对象初始/最终状态、正常退出及上下文。
8. 依据已批准 relation 和独立 reference semantics 重算比较，核对报告结果及聚合。
9. 任意必需项 failed/inconclusive/缺失都会阻止 production acceptance。

允许 source/target 按明确 strengthening、stuttering 或其它批准关系存在差异；
“所有字段都必须一样”和“只要最终值一样”都不能替代关系证明。
独立审计可以共享严格 parser，但关键输入事实应来自重新验证/重建，不能相信缓存
的 comparison/status。为重要语义增加独立小型 oracle 和反例，不只自调用相同函数。

## 10. 持久化、实现依赖和故障诊断

* 新 DTO 只使用 JSON-native 类型；写前/读后/重建后都进行严格类型校验。
  bool/int、tuple/list、整数/字符串 key、缺字段/多字段均不得隐式等同。
* 为新增 schema 使用明确版本和迁移/适配器；旧 v2 memory facts 不获得 v3 的
  projection 权限，旧 standalone spec 不获得新联合义务。
* 审计剩余原生 `==/!=` 的位置，确认是否已有完整类型校验覆盖，再逐步统一；
  发现原生比较并不自动意味着已存在可绕过错误，需以反例验证。
* 复用 `l3_implementation_dependencies` 的全包依赖绑定和
  `BackendValidationSession` 的操作内复用/结束时 uncached validation。
  扩展/新 backend 显式绑定其 runtime C、header、编译命令、插件二进制和探针。
* 多区域预算按编译/捕获/比较/审计分项记录；使用有界事件数/调用数/迭代数。
  预算耗尽给出精确阶段，不通过无限增大 timeout 掩盖实现错误。
* 使用原子 checkpoint 更新可变状态；immutable artifacts 仍独占创建。
  新输出路径避免覆盖旧证据。保留原始异常及其因果链，诊断写失败不能覆盖主异常。
* Phase121 `translation_backend_failure` 和 pipeline traceback 继续保留；联合
  比较增加 occurrence/object/property 的首个差异，不仅输出泛化 mismatch。

## 11. 校准、测试矩阵与防止只覆盖当前种子

### 11.1 测试维度

| 类别 | 必须覆盖的变化 |
|---|---|
| 类型/调用 | 8/16/32/64 位、signed/unsigned、参数换序/额外参数、void/自然输出、typedef、类型不匹配 |
| load/store | 符号位边界、低位截断/扩展、0/正负偏移、对象边界、重叠访问、周边字节、同/异对象 |
| 区域 | 1/2/多个区域、读→标量→写、多访问单区域、跨区域值复用、fan-out、C shell 效应 |
| 别名 | 明确 disjoint、同一合法对象 view、may-alias、非法 alignment/lifetime/extent |
| 同步 | 真实 R/W-fence 序列、wrong fence/missing fence、atomic 偏移和返回、LRSC 活跃 next/status |
| 控制 | 条件两侧、多出口、跳过区域、非法回边、0/1/最大迭代、预算截断 |
| 输出 | 返回值正确但内存错、内存最终相同但额外写、额外/缺失输出、错误输出投影 |
| 证据 | 缺 header/footer、token 混淆、片段/调用串用、PC 错属、对象误归一化、重复/删改事件 |
| 部署 | 插件/编译器/语义 binary 替换、instrument 改代码、错误重定位、陈旧 calibration/source snapshot |
| 持久化 | JSON 往返、重算 hash 后类型错误、版本降级、未知字段、共享缓存结果被篡改 |
| 泛化 | 函数/变量/路径/标签改名、合法参数换序、不同偏移/常量、独立于生产实现的预期 oracle |

源码例子只是参数化维度的实例；代码不允许根据其名字或模板选择能力。
对每个新支持子域要求至少：真实编译/执行正例、错误翻译或错误证据反例、中央独立
审计、旧路线兼容。有限运行覆盖声明与全输入语义证明分别呈现。

### 11.2 backend 校准

P2 需要双端多区域 R/W 宽度和区域交错校准；P3 增加 fence/atomic/LRSC 的归因
及失败/重试协议；P4 增加分支、skip/duplicate、多出口和迭代控制；P5 增加环境
专用探针。每个新捕获协议必须有负探针，不能以 v1 的 empty/read/skip 三种探针
宣称所有新事件族均已校准。固定容量 16 是当前实现/预算边界，不是程序语义边界；
新实现可用有界动态容量，但耗尽不能得到 complete footer。

### 11.3 高效验证节奏

每个相互关联的修订包完成后跑相关单元/契约/原生执行测试；完成阶段纵向工作链后，
先一个独立命名真实正例和反例，再阶段生产矩阵；跨阶段里程碑再跑跨路线回归。
无需每个小修改后跑所有耗时生产实验。涉及实现 pin 的修改须重新准备相关 wrapper，
不能修改旧 manifest 的身份来复用旧校准。

pytest 生产反例可能在成功审计后故意篡改 capture；保留其测试结果作为反例证据，
不要再将整个 pytest 输出树当作全正例重审。另建未篡改生产验收目录。

## 12. 首轮实施包的具体范围与交付

建议首轮实施 P0、P1 通用 DTO 基础和 P2 的最小完整纵向切片，而不是一次性启用
所有高级控制/原子形式。交付应包含：

1. 新 capability assessment 与 compiler-backed program/call/object contract；
2. 无环单入口单对象的 load→scalar→store 联合部署/实际捕获/比较；
3. 当前 pure scalar 和 standalone memory/control/fence/atomic/LRSC 的兼容适配；
4. 完整 members+program obligations 的中央审计；
5. 缺成员、错顺序、错对象、额外写和真实错误翻译的反例；
6. 后续子域的明确缺口记录，而非删除 requirements 或假定通过。

此切片内如果上游 source model/proof/operand authority 不足，应补齐相应上游模型；
不能仅改 L3 让一个没有证明的 translation 获得 approval。窄 load 的 Phase6A–F
变更宜作为清楚的前置子包验收，避免通用调用与机器语义同时失败而难以定位。

## 13. 仍需哪些执行信息

上述代码级方案不依赖新增长时间实验，足以作为实施依据。当前 Phase121 通过的
目录可作为旧域基线保留，无需再重复约 57 分钟矩阵。

以下信息只用于缩小下一轮首批输入和分析实际组合，不是本方案成立的前提：

* 此前 `seed-and-call-basis.json` 的实际内容，而非“32 个函数导出成功”日志；
* 拟支持组合的原始 C 输入及其 compiler-candidates/fragment joins、完整 source
  proof/approval、L2 authority/依赖图；不能只给最后一条 reasonCode；
* 现有后端 capabilities、工具版本及插件 header。只有新观察协议确实需要额外
  callback 能力时才提取实际声明；不预设原 backend 能读内部寄存器值。

可对已经保存的真实正例报告做轻量库存，避免重跑生产过程：

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PHASE121_ROOT="$REPO/experiment/results/phase121-uJpaRh"
export NEXT_PLAN_ROOT="$(mktemp -d "$REPO/experiment/results/l3-composite-basis-XXXXXX")"
printf 'NEXT_PLAN_ROOT=%s\n' "$NEXT_PLAN_ROOT"
git rev-parse HEAD > "$NEXT_PLAN_ROOT/git-head.txt"
python3 experiment/inspect_l3_workflow.py \
  --root "$PHASE121_ROOT/narrow-store" \
  --output "$NEXT_PLAN_ROOT/phase121-original-inventory.json" \
  > "$NEXT_PLAN_ROOT/collect.log" 2>&1
COLLECT_STATUS=$?
printf 'collect_status=%s\n' "$COLLECT_STATUS"
cat "$NEXT_PLAN_ROOT/collect.log"
```

这里刻意不加 `--audit`：本次只是读取已存报告，不重复声明独立验收。库存输出的
semanticApproval false 是正确的。后续针对新组合收集具体 compiler/proof 产物时，
应先增加与新接口相符的提取器，不凭空给出当前尚不存在的 CLI 参数。

## 14. 整体完成判据

只有以下条件同时满足，才能宣称某个明确支持域完成覆盖：

* 独立声明的域前提成立，源语义与所有 asm/调用/对象/控制效应完整；
* Phase6/其它批准路线给出正确翻译关系，L0–L2 与各观察接口闭合；
* 新旧数据版本、类型转换、对象边界、外壳及 machine mapping 正确；
* 一次实际执行覆盖被声称的 execution unit，所有必需义务都有真实证据或明确批准
  的静态证明依据，且没有观察遗漏被误称为无效应；
* 整体独立审计重放通过，缺失/额外/错序/错归因/错误语义均有可检出的反例；
* 泛化样本、真实双端生产、既有路线回归均完成；未实现的其它子域仍准确报告。

关闭某一阶段的缺口必须依据这个判据逐项登记，不能以“测试返回 0”或“没有报告
错误”单独替代。最终结论仍限于写入合同的语义和观察范围。
