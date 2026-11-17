# Phase197 验证记录

基线：62e6944347dd1a0f8b0f05ec0a957ef3d8f32b93。
最终代码、测试和指南树（不含本记录）：89ccdd7ea26606405866198a5ff2d84236e936fd。

## 执行结果

1. PHASE196_VERIFICATION.md 的 24 个文件，加 Phase197 新增文件：
   **336 passed, 4 skipped in 404.18s**，退出 0。
   此轮收集到新增文件的前 17 项测试。
2. 随后补强物理报告检查，在复用本次已检查上下文时仍即时核查前端报告快照，
   并增加源码及前端报告变化的两项拒绝测试。最终代码重新执行五个相关文件：
   test_phase197_typed_closure、test_native_original_pipeline、
   test_phase196_original_context、test_candidate_materialization、
   test_wide_integer_original。
   **64 passed, 1 skipped in 50.51s**，退出 0；其中 Phase197 新增测试 19 项全部通过。
3. git diff --check 无错误。

两组结果有重叠，不能相加作为独立测试数量。第二组针对最终补强后的代码执行。
四个较广回归跳过项分别需要真实 Clang、真实 Ghidra、真实 Clang 原生输入重放、
以及真实 RISC-V GCC + Clang。最终相关回归跳过真实 Clang 冻结输入导出。
本环境为 Python 3.12.14、pytest 9.2.0、Z3 4.16.0、pypcode 3.3.3、GCC 14.2.0，
与用户 Ubuntu 18.04 / Python 3.10 / GCC 7 环境不同。

## 实际上传报告的局部重放

直接消费用户提供的 Phase196 报告中的 compilerExpressionFacts 和 Clang Tooling 操作数：
- 三个操作数表达式绑定成功；规范类型均为 unsigned long；
- 原约束仍为 =r、%r、r；
- 整组关系仍含 [0,1,2] 和 [0,2,1] 两个允许排列；
- semanticRouteApproved 仍为 false。

这仅验证真实报告上的表达式绑定修复。上传内容不含完整函数 AST，
没有把局部重放声称为完整载体生产、原后端重跑、真实 GMP 或完整 L2 验证。
载体生产使用任意重命名 typedef 链、编译器 desugaredQualType、32/64 位和符号属性的结构测试验证。

## 正确性及剩余边界

保留原 Pipeline、源语义、目标约束、证明门、渲染器、回填器和独立重跑路径。
没有移除 %、按 GMP 类型名猜测宽度、放宽八参数测试桩、修改 GMP 阈值或设置全局通过标志。
新缓存键从本次实际读取的不可变字节计算，不接受收据摘要替代实际内容；
不同调用重新读取；正常修改、重新初始化、同尺寸同 mtime 的变化均有拒绝/失效测试。
新物理报告内部接口仅供刚完成 check_input 的同步检查使用；公开回填入口仍独立检查。

完整机器 ABI、内部对象访问及调用效果、三端上下文关系、实际输入关系、自然运行映像、
规范实例覆盖、程序级 L2 和 L3 等仍需继续生产及检查证据。整组关系的结构绑定
不替代交换语义证明消费；原标量 L2 对此保留明确未完成原因。
当前源条件排除实例继续保留，不产生规范实例执行覆盖结论。原始宏编辑权限未提升。

没有在本环境执行真实 GMP；不报告端到端加速比。无缓存只读冻结和其余递归复核
仍有成本，需按新版指南对同一产物、同一 check 范围比较，而非比较 resume 与 check。
