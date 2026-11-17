# Phase196 本地验证记录

基线提交：98b6cdf719917db7bce17f26356327fff29add36。

已检查的代码及指南树：c7109ccb3058368ece98a3f46f45620896cb1ff1。
发布树在此基础上只增加本验证记录；包源代码与被测试内容相同。

## 最后一轮回归

结果：**319 passed, 4 skipped in 192.05s**。退出码 0。
执行范围为 PHASE196_VERIFICATION.md 第一节列出的 24 个测试文件，包含本轮新增的只读所有权、
原编译器上下文衔接、GNU 分区冲突、main 所属实例、证据前提规则和 Python 路径规范化测试，
以及原翻译、回填、独立重跑、检查点、机器盘点、L2 授权和表达式回归。

git diff --check 无错误。GitHub 待发布代码树与本地 git write-tree 相同。

环境：Python 3.12.14、pytest 9.2.0、Z3 4.16.0、pypcode 3.3.3、GCC 14.2.0。
此环境不同于用户 Ubuntu 18.04 / Python 3.10 / GCC 7 / Clang 10 环境，必须继续在用户环境验证。

跳过项：
- test_phase196_original_context.py 的真实 Clang 冻结输入函数导出集成；
- test_project_native_input.py 的真实 Clang 原生输入独立重放；
- test_project_native_input.py 的真实 RISC-V GCC + Clang 独立重放；
- test_ghidra_preflight.py 的真实 Ghidra 安装集成。

这些缺少的实际工具集成未由模拟测试替代。没有在这里重跑用户的真实 GMP 实验，
没有取得规范实例指令覆盖或完整程序语义批准。

## 合成数据微基准

同一含 20,000 个节点的 JSON 派生结构，先预热，再运行 12 次相同键命中：
- 原隔离副本模式：2.00414 秒；
- 内部只读共享模式：0.00839 秒。

这是解释复制成本的本地合成数据微基准，执行时存在其他测试负载。
它不表示真实 GMP 的端到端加速，也不用于论文稳定性能结论。
真实性能应按指南对同一新版产物运行缓存开/关的相同 check 操作，
结合 wallSeconds、调用次数、pure.copy / freeze / key / derive 计时核对。

## 保留的验证边界

原 CLI / Pipeline、源语义、约束、证明、渲染、候选回填及独立重跑继续使用。
十项完整义务中尚缺的 ABI、对象访问、输入关系、调用效果、运行映像、规范覆盖、
L2 实际授权和独立程序审计等事实，继续列为缺失。
有限子结论的消费不授权完整程序通过；L3 仍需明确适用合同。
当前源条件排除的 GMP 实例仍须如实保留，不通过修改项目阈值强迫覆盖。
