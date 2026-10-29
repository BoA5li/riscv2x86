# L3 完整覆盖缺口修订实施方案（Phase124 验收基线）

## 0. 基线、目标与交付边界

代码基线：远端 `phase124-typed-load-return-binding`，提交
`99b5f2fe80551828ddd3a3369b8d730ea1437d97`。本地相同代码树已核查。
主机验收目录：`experiment/results/phase124-jhDhHP`。已见日志：构建0、261定向通过、
16项后端校准完成、2个原失败用例通过、18项load生产通过、17项store兼容通过。
当前文档是下一阶段的实施依据，不表示下面建议的模块或路线已经实现。

修订目标：对属于既定证明、调用和观察域且满足前提的合法程序，完成L0–L3及独立审计。
原本应处于该域中的种子被阻塞时，必须定位并补齐实现，不得通过缩小声明范围、删除种子、
标记not-applicable或降低义务逃避。无证明/观察能力的程序保留准确缺口和原始证据，不能批准。
不把有限动态样本称作全输入证明；不把TCG观察称作物理缓存、时序、并发原子性实测。

整体方案覆盖本轮列出的全部12类缺口；落地以完整纵向里程碑分步交付。每个里程碑必须包含
生产、反例和独立审计，不把只增加schema或放开gate称作能力已完成。

## 1. 逐项代码定位与修订边界

| 缺口 | 当前实现锚点 | 必须修改的完整链条 |
| --- | --- | --- |
| 混合机制 | `l3_mechanism_selection.plan/produce/build_route`仅选一种；`l3_execution_plan.build`按pattern/dimensions选route，fence/atomic还要求单成员 | 从源义务生成联合计划，构造一个调用内的执行组，联合capture与比较，生成成员投影和组结果，整体审计 |
| 多区域 | `compiler_program_regions.export`直接纯外壳；`l3_program_spec.spec`纯标量2–16成员；program parser固定顺序 | 编译器区域图和动态实例，跨区域值/对象关系，完整函数执行闭包，容量与预算合同 |
| 调用 | `l3_scalar_call`主要integer64；`l3_memory_call.bind`两个unsigned参数；load bind一个指针；atomic专用签名 | 共用编译器类型/表达式/对象驱动调用合同、合法输入生成、输出覆盖，不改变C原函数ABI |
| 多访问/对象 | `memory_access_semantics.decoded_access`恰好一个访问；`l3_memory_intent.memory_spec`一个对象/效应/关系 | 上游逐效应语义、地址和别名证明→目标效应关系→L2→多事件L3，不能只放宽L3列表长度 |
| load | `memory_contracts.LOAD_ROLES`与Phase124返回合同已通 | 保留已验收能力，复用于多区域、多输出；更一般返回表达式须独立证明，禁止无条件剥离cast |
| store | `l3_memory_call.bind`unsigned且pointee匹配；受限return shell | signed对象及载体、值表达式、更多输入和可观察返回；对应C转换和实际字节写入同时验证 |
| 控制/访存 | `l3_control_spec`拒绝memory objects/ordering，一个transfer，主要64位参数 | CFG边、路径、动态访问、区域出口、循环实例与预算，包含外壳效应 |
| fence上下文 | `l3_fence_spec`零参数void、普通rw/rw、无对象 | 访存/屏障统一事件与证明的序关系，按pred/succ及域逐项扩展；不强制数值编码相等 |
| atomic地址/调用 | `l3_atomic_spec`arity2、单对象、offset0、受限return；`memory_address_projection`只支持直接解引用 | 编译器地址表达式/对象/边界合同、所有调用输出、机器地址归因、值/机制/ordering比较 |
| atomic族/LRSC输出 | `l3_atomic_semantics`五类；`l2_lrsc_authority.require_observable_scope`只容许dead/discarded next/status | 按上游证明增加操作族；活跃输出需要实际观察/状态关系，失败重试由路径和真实数据共同归因 |
| 总体审计 | `l3_production_acceptance.audit_evaluation`按路线早分派；program已有组审计，其他特殊路线单片段 | 统一执行组分区与义务闭包审计，逐组逐成员检查，拒绝提前返回漏掉其他成员 |
| visibility/environment | `l3_sync_obligations`有义务；selection没有相应机制；controlled-system生产测试L3明确not_run | 新环境合同和真实observer/比较/审计接入，不能把已有L0–L2成功升级为L3 |

无关函数共存的入口身份选择已改善，不需恢复“整个TU必须恰好一个函数”。可达callee、
递归、间接调用、共享全局状态仍未获证明闭包，必须另外处理。

## 2. 统一正确性原则

1. 源义务独立于观察器，复用`l3_property_obligations.analyze`及`l3_sync_obligations`。
   选了什么backend不能决定忽略哪些源效应。新程序级义务只能明确增加/映射，不能覆盖丢失。
2. 声明身份、值身份、转换表达式身份和对象身份分别保留。Phase124的返回关系与严格
   `_decl_identity`是基础；不能把一般表达式伪装成一个变量来复用旧接口。
3. 证明逻辑关系与真实观察分别记录。静态证明可承担明确的性质，不可被命名为实际测量；
   实际数据不足时不能从“源码应当如此”补造观测值。
4. 同一执行单元共享真实对象与中间状态，源端一次、目标端一次，均使用相同逻辑输入。
   分开运行孤立片段，或在片段之间重置对象后汇总，不是联合程序执行。
5. 比较对象相对地址、逻辑效应及获批关系，不要求跨ISA虚拟地址、指令数、微事件数相等。
   部署仍须分别绑定源/目标原始机器码和准确区间，不能用比较归一化绕过代码校验。
6. `verified`表示已声明性质在其证明/实验域内满足；`failed`用于有效且完整证据中的反例；
   `inconclusive`用于截断、未完成、归因不明、缺能力。非法源/构建失败/不支持分别报告。
7. 禁止名称/路径/case编号决定批准；所有identity/范围/类型从编译器和真实产物得到。
8. 子性质不适用必须有源事实依据，不是因为观察器没有输出。可选能力缺失不得吞掉required义务。

## 3. 公共合同：先建立足够支撑后续路线的基础

以下均为建议新增的语义合同，最终命名可沿用现有模块风格。schema版本由具体字段变化决定。

### 3.1 Supported-domain与覆盖账本

新增机器可读域描述与覆盖账本（建议`l3_supported_domain`、`l3_coverage_inventory`）。
每项记录：语义族/宽度/表达式语法、调用形状、对象/别名域、控制图约束、proof requirement、
observer requirement、claim scope、前提及拒绝原因。记录来源不能是运行后“哪些恰好通过”。

阶段状态分为源合法性、翻译证明、L2材料化、调用、程序闭包、backend校准、部署、实际执行、
比较、独立审计。修订`l3_execution_plan`中ready含义：现有机制可用只代表选路候选可用，
不能代表执行闭包/生产已完成。`l3_capability_assessment`继续只读，不授予执行批准。

生成语义组合的expectation matrix，而非case白名单；所有已承诺域内种子必须完成。
对最初32个generated种子保留逐项账本，其中环境类种子必须声明其环境前提，不承诺统一使用
普通memory后端就全通过。基线变化应记录原因，不隐藏原失败记录。

### 3.2 Typed Invocation与输出合同

复用`compiler_memory_signature`、`compiler_integer_signature`、`compiler_expression`、
`compiler_expression_evaluation`、`compiler_return_binding`及`l3_entry_binding`，统一导出：

* entry/function/source/ABI身份；参数序号与声明身份；整数宽度/符号性/限定符；指针pointee；
  可达callee集合及其闭包身份（后续阶段），无关函数不进入该集合。
* 标量输入、对象绑定、指针基址/偏移、alias partition、初始化及调用前提。
* 返回表达式、output对象/区间及所有活跃输出。每个输出绑定实际观测来源和精确转换链。
* 所有参数按真实C签名传递；不把函数统一强转为uint64函数指针，不依赖未证明ABI巧合。

首期普通整数8/16/32/64和普通整数指针；额外参数由事实驱动，不固化为“恰好两参数”。
ABI寄存器/栈参数都必须被harness和机器归因覆盖，不能仅放宽arity数字。后续聚合/浮点/可变
参数不自动获得许可，未证明时明确缺口。signed初始化使用可表示的C值或有证明的字节构造，
避免实现定义转换、未初始化值、严格别名和对齐UB。L1/L2/L3的typed对象生成应共享语义。

### 3.3 对象、地址及别名图

对象记录：逻辑identity、大小、生命周期、类型/有效类型、对齐、可读/写区间、地址空间、
volatile/atomic属性、初始化与可观测输出区间、别名关系、对应证明。
指针是(objectId, offsetExpression)而不是孤立整数。动态地址表达式来自编译器AST和IR，
初期支持直接对象、常量偏移、获证明界限的数组索引/仿射表达式，再扩展语法。

逐访问验证范围、溢出、对齐、pointer provenance与求值次数。多参数指向同一对象应分配同一
存储并记录偏移，不得错误分配成两个独立数组。覆盖disjoint/same-base/disjoint-slices/
proved-overlap几类，未证明关系保留unknown，不能运行样本地址不等就宣称全域不别名。

### 3.4 程序区域与外壳图

扩展`compiler_program_regions`：region/function/candidate/proof/source range身份；CFG入口、
正常/异常出口（若支持）、值定义/使用、对象读写、控制/地址/数据依赖；显式C外壳效应。
成员既包括原asm，也包括翻译后C表达式/builtin/helper的获批对应区间，不能要求一一#APP块。

先支持直接无环区域，再加分支/循环/callee。程序图与当前L2依赖图可以共享事实，但需按新
程序合同重建并交叉验证，不能直接把一份完整L2图当作动态执行完成证据。

外壳C访存、运算和调用：要么由静态非干扰/精确效应证明覆盖，要么纳入真实观察。原policy
排除outside-fragment-effects，联合路线应新增明确的policy/性质，不能悄悄扩大旧policy解释。

### 3.5 执行实例与证据合同

每次capture固定source/target artifact、部署、backend、工具链、输入/对象布局、sample plan、
执行预算、要求集合及环境identity。每个动态实例记录(invocationId, functionId, regionId,
visitIndex)，循环重访不能与初次执行合并；必要时增加thread/hart身份，不伪造多线程支持。

事件类型至少包含调用与区域边界、内存访问、控制转移、屏障、原子尝试/结果及退出。
数据字段根据已校准observer能力提供，不承诺QEMU插件当前就能读取寄存器或内存值。
每项值记录区分实际callback/寄存器快照/调用输出与独立语义重放；缺少必需真实值须补observer。

原始流必须有token/序号/开始/结束/footer、溢出/丢失计数、调用与实例计数。容量改为声明并
验证的预算；不能仅删掉16上限而保留固定数组。超时/预算耗尽/未闭合流均未完成。

### 3.6 C语义、编译器外壳与运行资源

所有新增表达式都检查C整数提升、转换、signed溢出、移位范围、求值顺序、一次求值、
对象生命周期/有效类型、未初始化读取及pointer provenance。测试输入规避UB不等于已证明
一般输入安全；应有静态条件或声明并验证的输入域。volatile访问、GNU memory/cc clobber、
early-clobber、tied operand与ABI状态继续作为Phase6D/L2义务，联合执行不能将其合并忽略。
多线程/信号/外部设备会改变对象状态，若未建立专用域与观察合同，不冒充private对象执行。

运行缓存若用于减少反复capture，其key必须绑定整个执行组、所有要求、输入与环境、源/目标
产物、backend和实现身份；仅按fragmentId复用会错误混合不同调用。不得在验证期间修改源、
backend或证据；捕获与重放两端都检查一致性。未知机器指令/效应不能默认为无操作。

## 4. 混合执行的完整纵向实现

### 4.1 先独立设计联合路线，不破坏旧路线

建议新增`l3_joint_spec/deployment/backend/route/compare`，让旧专用路线继续运行。
`l3_mechanism_selection`仅在联合合同、校准与部署都可用时选择joint；未支持组合保留拒绝。
不能循环调用现有producer得到多个profile后就宣称一次执行。联合需求合同明确绑定组identity，
成员profile与程序级性质都指向同一个capture。

重构`l3_execution_plan`：先收集所有成员/外壳义务，再构造执行组和组间依赖；机制选择是
满足义务集合的约束求解/确定性规则，而非pattern种类的计数。并发/控制/同步义务不被普通
memory能力替代。单成员也可能是多种机制，不应仅按finding数量判断组合。

### 4.2 首个生产域：load→scalar→store

入口采用真实typed签名；一个普通有界对象或已证明不相交的输入/输出对象，直接无环外壳，
至少两个asm区域。共享初始化，实际load结果流经原始C/asm计算，再实际store；不在区域间
独立构造预期输入。标量区域的无访存性质来自源证明与机器观察共同检查，不凭pattern名认定。

部署扩展program机制：编译器范围→源/目标binary region映射；获批替换产物逐一验证；
zero-byte标记删除后机器码必须与语义产物一致。空机器区间或纯C替换必须有专用边界/证明，
不能因找不到#APP就漏成员。插入会改变代码/屏障的C日志不能当无扰动区域标签。

backend复用可复用组件，但必须重新校准完整联合域：源/目标各宽度读写、跨区域连续性、
多个调用、token、错序/缺失区域、额外访问、缓冲溢出与截断。当前program仅empty/read/skip
校准，不足以宣称多宽度写事件、分支、fence和atomic均可观察。

### 4.3 比较规则

1. 由source effects和approved relations定义逻辑事件及允许的refinement。
2. 地址映射到同一调用的逻辑对象和偏移；对象找不到、归属不唯一则未完成。
3. 有依赖顺序必须满足；对有证明允许重排的独立效应比较偏序，不要求盲目逐条同序。
4. 最终返回、所有输出区间、完整守卫/未修改对象区间均检查，不能最终数值相同就忽略
   中间缺失/额外访存或错误控制路径。
5. 中间值按性质要求：需真实观测的补observer；已由L2与静态闭包承担的明确标注证明方法，
   不能把参考执行推导的值写成实测。联合数据流的实际执行完整性独立验证。
6. 程序成员结果是组证据的有身份投影，不是重复执行成员取得的孤立证据。

## 5. 多访问、多对象与一般load/store

替代`decoded_access`单项返回，以稳定(effectId, blockId, operationIndex, pathCondition)
导出访问集合。逐项绑定地址表达式、access/carrier宽度、projection、volatile/atomic性质、
内存状态输入/输出与别名条件。保留旧单访问adapter，不将额外访问截掉。

同步扩展source_model/source_memory事实、候选、约束、Phase6D、渲染器、effect proof、
L2 sidecar和材料化。目标一条源指令可合法对应多条机器指令，但每个目标效应必须在批准关系
中解释；未知调用和隐式访存不能漏掉。多访问片段的path condition与顺序属于证明输入。

L2按区间/值/序关系核验，多对象harness维持真实别名拓扑；L3记录全部事件。
load沿用已验收扩展/返回关系。store新增signed对象/载体时，分别证明C值到存储位模式、
截断/转换与对象字节；不能把所有store统一转换成unsigned而无语义依据。一般值表达式必须
保留一次求值及求值顺序，不得重复带副作用表达式。

## 6. 控制流、循环与程序闭包

扩展`l3_control_spec`、control machine、程序CFG和backend；单独引入memory+control合同。
真实路径以PC/分支目标和完整边界记录为依据，数据访问必须映射到该路径允许的效应。
样本应覆盖可行分支、出口、边界值与路径上对象状态，不能要求不可行路径被执行。
未覆盖可行路径不等于已证明全路径；保留输入域/覆盖统计。

循环需CFG回边、归纳关系/不变量或明确有界域证明；记录每次region访问，验证迭代数、
状态转移和退出。预算是资源限制，不是终止证明；运行到上限不代表合法终止。
多出口分别绑定返回/对象输出和continuation。间接控制、递归/间接调用需新目标集合与闭包
证明，不能因观测一次目标就静态批准所有目标。

可达callee阶段用编译器/链接符号确认调用图及所有效应，处理全局对象/别名/ABI/clobbers/
外部函数合同；每个实际调用实例与返回都闭合。未建立callee合同就准确拒绝，不只检查入口。

## 7. fence、atomic及LR/SC

### 7.1 fence真实上下文

扩展`l3_fence_spec`并接joint事件：实际R/W—fence—R/W及对象关系。源pred/succ、memory域、
目标屏障合同和机器事件都绑定；不能要求源/目标barrier opcode相同。首先rw/rw普通一致性
内存，再按静态证明扩展子集；I/O域、特殊地址空间不自动包含。不要放宽单次观测来声称实测
物理重排序或多核内存模型。并发性质需要独立的并发执行/结果集合合同。

### 7.2 atomic地址和调用

扩展`memory_address_projection.project_memory_address`，基于compiler expression支持p+k、
数组元素、有界仿射索引。类型、元素尺寸、求值次数、范围、对齐、对象身份及算术溢出全部
证明；offset与harness、样本对象布局和机器实际地址一致。原offset0路线保留。

调用合同沿用typed invocation，不再由“两个参数”推断地址和值；每个活跃结果可映射到返回、
输出对象或已证明可见端点。静态approved ordering、真实机器机制归因和实际结果分别验证。
扩展`l3_atomic_machine`、backend、retry归因和compare时，不把两条普通回调判作原子性。

### 7.3 操作族与LR/SC活跃输出

每增加一个操作族，必须同时具备源IR/typed operation、输入/结果宽度与signedness、源/目标
effect relation、Phase6D、目标代码/循环不变量、实际事件识别、harness及审计。
候选如signed/unsigned min/max或其它RMW，按上游证明能力接入；CAS有成功/失败及双ordering，
不能套用无条件RMW。真实SC失败和重试须能观测，不能人为伪造成功/失败状态。

`require_observable_scope`不得直接删除。先增可见next/status的证明/输出合同和观察，再按
覆盖情况解除对应限制。活跃SC状态可能只有“0成功、非0失败”的约束，是否要求精确值由
源语义/批准关系决定；若C程序观察具体非零值，不能擅自折叠成布尔。失败时next、中间old、
最终status的对应关系都需要源/目标关系证明，不能只比较最终对象。

## 8. 指令可见性与受控环境

环境路线单独建立版本化scope、initial state、允许操作、executor/firmware/ISA权限、可观察
环境转移和复位合同。复用`instruction_stream_sync_contracts`、`compiler_instruction_sync_scope`、
`local_sync_environment/mechanism`及`controlled_system_*`中已批准事实，不把其存在等同于L3接入。

visibility：必须有可执行且有语义的代码发布/指令可见性实验，绑定写入、同步、取指/结果。
QEMU若自动失效翻译块，不能据此证明fence.i必要性或目标真实硬件缓存行为；需证明执行器
忠实实现所声明环境，或使用适合的后端。删除同步的负例若环境掩盖缺陷，不可记作有效负例。

controlled environment：ecall/wfi等需对应环境中的真实trap、返回或等待/唤醒观察，包含异常、
超时和外部状态。静态映射成功、空stub或未执行不能验收。接入selection、producer、route、
义务比较和audit，同时维护原L0–L2合同。

环境前提未知时，只对相关路线索取QEMU/硬件/特权/执行域信息，不阻塞普通访存联合路线。

## 9. 整体独立审计与基础设施

统一audit入口先枚举全部要求、attempt、execution groups，验证完整分区后再分派组审计。
不能遇到一个atomic或program分支就early return而漏掉其他要求。一个capture可满足多个
成员，但组身份、成员投影与性质映射必须明确；不能把同一证据错误拼接为不同调用。

逐组检查：源/目标产物与构建、source/target mapping、backend及校准域、调用与对象合同、
程序图与proof身份、运行原始证据、完整性/异常、每个要求的比较重算及最终聚合。
防止missing/duplicate/unrelated/member mismatch、混合版本、stale digest、文件改动、
跨sample拼接、unknown事件、错误不适用、只有终值没有必要中间证据。

共用严格JSON-native DTO，区分bool/int、数组顺序和集合规范化；hash仅证明内容身份，不能
替代来源、对象范围和语义验证。新schema需producer/parser/deployment/provider/compare/audit
端对称接入，旧版本不获得新权限；状态文件原子更新与证据文件不可变写入分开。
继续使用`l3_backend_validation`验证会话及完整实现pinning，不降低重建检查来改善耗时。

进度/预算清楚区分编译、校准、capture、重放、audit。产物写入失败保留原始错误，不用
二次checkpoint错误覆盖根因。超时不自动重试后挑选成功样本，重试策略和所有尝试归档。

## 10. 实施里程碑、依赖和验收

| 阶段 | 纵向交付 | 主要依赖 | 必须通过的验收 |
| --- | --- | --- | --- |
| M0 | 域/覆盖账本、阶段化plan与现有能力冻结 | Phase124 | 不批准运行、缺口分类正确、域内种子不被隐藏；既有路线定向回归 |
| M1 | typed invocation/object/output/region合同，首个load–scalar–store联合路线及程序审计 | M0 | 同一真实调用，单对象有界无环，源/目标完整事件与结果，所有成员独立审计与反例 |
| M2 | 多访问片段、多对象/别名/重叠域、signed store与一般地址 | M1；上游源事实与Phase6D同步 | 每个源/目标效应有关系，每个对象和输出被覆盖；合法别名与不合法条件区分 |
| M3 | 访存与fence上下文 | M1/M2相关对象能力 | 全事件序关系、机器屏障、批准ordering合同、审计；不声称物理重排实测 |
| M4 | atomic非零偏移/typed调用、LRSC活跃输出及可证明新操作族 | M1/M2；对应源/目标proof | 结果/状态/机制/ordering全部闭合，失败重试反例；旧AMO/LRSC矩阵不回归 |
| M5 | memory+control、多出口、有界循环 | M1/M2，CFG与终止/有界证明 | 真实路径、动态区域实例、可行路径与迭代状态，缺失/截断必拒绝 |
| M6 | 可达callee与更广程序外壳 | M5与ABI/调用图效应合同 | 所有可达函数/外壳效应闭合，无关函数不误拒绝 |
| M7 | visibility/environment真实L3 | 专用环境合同，可与M3–M6独立推进 | 实际环境执行、有效观察与负例、独立审计；旧L0–L2保持 |
| M8 | 全域覆盖清算与复现归档 | M0–M7 | 12项映射、所有域内组合无未解释阻塞；未支持域明确且不冒充已完成 |

M1不能只发布“合同准备”，须包含首个真实联合闭环；M2上游证明不足不能靠L3兜底放行。
M3/M4可在共用基础稳定后分别实现；M5需要动态实例而非固定顺序列表，不通过提高数组上限
替代。阶段之间不反复全量长矩阵，小修改跑受影响单元/集成与负例，完整纵向包完成后跑
真实生产矩阵和受影响旧路线兼容，最终M8再统一验收。

## 11. 测试设计与证据要求

正例按维度组合生成而非名称匹配：8/16/32/64位、signedness、投影、返回转换、参数位置、
对象数量/大小/偏移/对齐、别名拓扑、片段数、路径/迭代、fence域、atomic操作/ordering、
活跃输出。用边界值加确定性随机值；seed与样本计划identity归档。类型合法性先检查，不能
靠关闭-Werror或-fno-strict-aliasing掩盖错误harness。

负例包括：漏/多一次访问、偏移/宽度/方向错误、高位错误、对象别名被分离、依赖断裂、
区域跳过/重复/错序、不可行路径伪造、非终止/截断、丢事件/溢出、错误原子机制或ordering、
可见status被忽略、错误环境、所有身份/版本/成员关系篡改。重算hash后的无效语义也须拒绝。
改变源/目标代码作真实负例时必须保持其余证据合法并说明故障注入位置，不能把单纯checksum
失败称作语义反例；两类负例分别统计。

每个里程碑分五级：schema/parser→真实编译器事实→proof/materialization→真实双端生产→
独立审计及反例。mock/native/collected/skipped不能计作双端生产通过；fixture不能冒充编译器
批准。保留未篡改正例归档，测试故意篡改的capture单独保存，便于复审。

验收记录：HEAD/dirty source diff、工具及backendidentity、环境合同、源清单/摘要、命令/预算、
JUnit、要求/plan、源/目标产物、部署、raw captures、比较和audit JSON。源/目标ISA相关
宣称始终与环境/claimScope绑定，不把有限观察升级为物理微架构等价。

## 12. 尚需信息与下一次信息采集

现有代码与Phase124产物足以开始M0/M1实现，无需再重复本轮load/store长矩阵。
下一阶段在代码中加入通用精简检查器，按源元数据收集：

* 当前HEAD、源diff、sourceDigest、函数签名、返回绑定、region/CFG事实；
* 所有片段的outcome、proof/materialization、逐效应地址/值关系；
* 程序依赖图、义务、stage disposition及原因；
* 若运行失败，原始command stderr、关键合同与捕获完整性，不递归倾倒整个目录。

应先在仓库中建立可复现的M1种子族（同对象常量偏移load→算术→store、不同参数位置、
unsigned/signed返回、变更变量/函数名称），通过真实前端提取事实。若上游证明不支持，
按具体缺口补齐，不预先写“应该verified”但与真实证明无关的报告。

仅当推进visibility/environment或并发性质时，才需要用户补充对应执行器/特权/内存域/
代码发布方式/线程hart等环境前提。这些信息不能从普通load成功中推断。

最终完成判据：12项缺口逐项有代码、前提、真实正例、有效负例及整体独立审计；已承诺域内
合法种子的任何不完整工作链都进入待修复账本。仍缺任一必要纵向环节时，阶段不得标记完成。
