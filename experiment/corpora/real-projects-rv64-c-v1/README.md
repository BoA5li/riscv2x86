# GNU C / RV64 测评候选视图

本版从不可变的 `real-projects-v2` 派生，面向当前自动入口的 GNU C、
RV64GC/LP64D → x86 翻译评估范围。原始来源归档 v1/v2 不删除、不改写。
本版是有排除依据的候选视图，**不是已经获得编译器确认的正式可运行测试集**。

## 筛选结果

| 项目 | 原始语法位置 | candidate | review | supporting | excluded |
|---|---:|---:|---:|---:|---:|
| GMP 6.3.0 | 264 | 0 | 142 | 4 | 118 |
| musl 1.2.5 | 1,070 | 6 | 76 | 33 | 955 |
| Linux 6.6 | 12,523 | 1,257 | 1,778 | 360 | 9,128 |
| 合计 | 13,857 | 1,263 | 1,996 | 397 | 10,201 |

- `candidate`：尚未发现明确排除依据的 C extended-asm 语法位置；仍须确认
  原始构建配置、AST、源 ISA、宏实例、依赖、函数与执行条件。
- `review`：条件未知、宏/模板/头文件待确认、basic asm 与符号别名待 AST
  区分、非目标架构路径提示尚待确认、或语法尚未解析。**没有排除，不能作为失败或通过统计。**
- `supporting`：寄存器绑定、精确空模板 asm；不作为独立指令翻译样本。
  它们作为编译器接口/屏障语义材料保留，组合程序中也不能忽略。
- `excluded`：在本版已声明的语言、目标架构源目录或条件约束下，不进入主候选
  集。全部记录原 siteIdentity、路径、摘要、字节区间、理由与策略身份。

GMP 的 candidate=0 **不代表没有 RISC-V 汇编**。例如 longlong.h 中的
RISC-V 宏仍在 review：头文件包含条件、类型宽度、扩展宏及原始宏实例未由
实际构建确认。review 必须继续清算，不能只运行 candidate 后声称覆盖完整。

以上均为语法位置数，不能作为函数数、程序数、宏展开实例数或正式成功率分母。
所有 compilerActivationComplete/semanticApproval/productionAcceptanceComplete
保持 false，compilerConfirmedTestInstances=0 表示尚未进行编译器资格确认。

## 具体排除依据与保留规则

1. 按明确的项目源目录命名空间选择目标架构：Linux 的 arch/<arch>、tools/arch
   及架构自测目录（含 KVM 的 lib/include 架构子目录）、perf/objtool/power
   工具目录，musl 的 arch/<arch> 与 src/<模块>/<arch>，GMP 的已知
   mpn/<架构> 目录。保留 RISC-V、generic 及无法确定的共享目录；不按路径中
   任意出现 arm/x86 等字符串匹配。RV32 专用目录不进入本轮 RV64 主候选集。
   这是源范围选择，**不是编译器证明文件已激活**；域外文件仍可作为依赖从原库恢复。
2. C++ 独立翻译单元扩展名 .cc/.cpp/.cxx/.C/.c++ 不作为本轮 GNU C 主输入。
   .hpp/.hh/.hxx/.H/.h++/.ipp/.tcc 等头文件/模板不直接按语言删除，保留 review，
   等待其是否由真实 C 翻译单元包含的证据。普通 .h 同样不能直接作为独立程序运行。
3. 仅对明确的目标事实和可解析表达式做三值条件分析。策略约束 __riscv=1、
   __riscv_xlen=64，并列明其它架构的 GNU 宏不成立。它们是**声明的输入范围
   约束，不是宿主宏探测结果，也不是完整构建配置**。
4. 未知宏（包括 CONFIG_*、HAVE_HOST_CPU_*、__GNUC__）不默认为 0 或未定义。
   不受支持的表达式、未配对条件指令、源内目标宏重定义等保留未知。实现仅对
   可安全判断为 false 的分支排除；未知条件进入 review。若实际构建不满足
   已声明的目标事实，必须换用适当策略重新筛选，不能套用本视图。
5. 没有指令白名单，也不调用翻译成功/失败结果作筛选依据。浮点、特权、复杂
   原子和当前未实现语义均保留，只要其来源没有明确的域外或不激活依据。
6. 文档、脚本、Makefile、许可证、独立汇编等不作为独立 C inline-asm 测试
   输入，仍在 file-decisions 的 supporting_context 中保留来源/构建用途。
   无字面 asm 的宏调用方通过原版宏引用索引保留 review_source；不能静默丢弃。

10,201 个 excluded 包括 9,977 个域外目标架构目录位置，以及 224 个在
声明目标约束下不激活的位置。C++ 文件级排除也在 file-decisions 中记录；
它们的数量不等于 asm 位置数量。

## 文件与审计

`manifest.json` 绑定原版 catalogIdentity、策略和所有分片。策略绑定筛选器、
依赖采集器及当前自动入口代码摘要。每项目资产如下：

| 资产 | 内容 |
|---|---|
| candidate-sites.jsonl.gz | 静态候选的原始 site 记录，未授予可运行资格 |
| review-sites.jsonl.gz | 未确认位置的原始记录 |
| supporting-sites.jsonl.gz | 编译器接口等辅助语义位置 |
| site-decisions.jsonl.gz | 全部原始语法位置的互斥、完备分类和理由 |
| file-decisions.jsonl.gz | 原版全部 86,619 个非目录条目的用途分类 |
| sources.tar.gz | 保留位置所在的完整原始文件及许可证 |

源文件不裁剪：共享头文件内即使有排除的其它架构条件分支，其原字节仍保持
不变。**筛选的是位置索引及测评用途，不是对源码做删除分支的改写。**
不要递归执行 sources 快照内所有 .c 文件来替代本视图；其中还包含 review
和 supporting 上下文。原始完整构建依赖应通过 v2 锁定的上游发布包恢复。

## 本地更新与核验

```bash
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase146-rv64-c-corpus-filter
git switch --track origin/phase146-rv64-c-corpus-filter
python3 experiment/filter_rv64_c_corpus.py verify
```

已创建本地分支时，先切换到该分支，再执行
`git merge --ff-only origin/phase146-rv64-c-corpus-filter`。

verify 重新从 v2 推导全部决定、候选与原始文件并逐项比较，不仅读取已有状态。
预期 status=verified-rv64-c-candidate-partition；语义批准等 false 是正确边界。

```bash
export VIEW_WORK="$(mktemp -d "$PWD/experiment/results/rv64-c-view-XXXXXX")"
python3 experiment/filter_rv64_c_corpus.py materialize --output "$VIEW_WORK/materialized"
python3 experiment/filter_rv64_c_corpus.py build --output "$VIEW_WORK/rebuilt-view"
python3 -m pytest -q -rs pytools/tests/test_filter_rv64_c_corpus.py pytools/tests/test_whole_project_corpus.py pytools/tests/test_real_project_corpus.py
```

本轮 90 项回归通过，覆盖三值求值、与真实 C 预处理器的已知结果交叉检查、
多行注释、重定义、否定/嵌套条件、未知宏、路径误匹配、C++/共享头文件区分、
浮点/特权保留、宏调用方、原始字节、篡改拒绝及已发布全集分区重放。
该预处理器交叉检查使用宿主 C 预处理器验证表达式规则，**不是 RISC-V 编译实验**。

后续正式入集仍需原始工程的编译命令、生成头文件、宏展开/包含映射和 AST。
按这些事实清算 review，并记录无法构建的原因；研究范围内尚不支持的语义应
报告为覆盖缺口，不得为了提升通过率从正式分母中移除。
