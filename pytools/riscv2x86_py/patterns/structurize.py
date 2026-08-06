from dataclasses import dataclass
from typing import List, Dict, Optional


@dataclass
class Line:
    text: str
    is_branch: bool = False
    is_jump: bool = False
    # 约定：
    #   cond 表示“branch taken 条件”
    #   target_pos 表示“branch taken 时跳去的前向位置”
    #
    # 也就是说，这里建模的是典型 RISC-V 前向条件跳转：
    #   if (cond) goto target;
    #   ... fallthrough block ...
    # target:
    #
    # 结构化时，fallthrough 区域会被翻成：
    #   if (!(cond)) { ... fallthrough block ... }
    #
    # 若 fallthrough block 的末尾还有一个无条件前跳，
    # 并且它跳到比 target 更远的位置，则识别为：
    #   if (!(cond)) { ...fallthrough... } else { ...taken... }
    cond: Optional[str] = None
    target_pos: Optional[int] = None


def structurize(
    lines: List[Line],
    ins_pos: List[int],
    label_for_pos: Dict[int, str],
    end_pos: int,
) -> Optional[List[str]]:
    """
    把“只包含前向 branch/jump 的线性控制流”结构化成 C 代码。

    关键语义约定：
    - Line.is_branch:
        cond 表示 branch taken 条件；
        target_pos 表示 taken 时跳往的前向位置。
      因此 branch 后、target_pos 前的线性区域是 fallthrough block，
      输出时翻译成：
          if (!(cond)) {
              ...fallthrough block...
          }

    - if/else 识别：
        若 fallthrough block 的最后一条是无条件 jump，
        且该 jump 跳到比 branch.target_pos 更远的位置，
        则视为标准 if/else 形态：

            if (cond) goto L_else;
            ... fallthrough ...
            goto L_end;
        L_else:
            ... taken ...
        L_end:

        对应输出：
            if (!(cond)) {
                ... fallthrough ...
            } else {
                ... taken ...
            }

    - Line.is_jump:
        这里只接受“跳到当前区域末尾或更远”的收尾 jump。
        其它 jump 仍视为当前结构化器不支持的形态。
    """
    # 当前实现不依赖 label_for_pos，但保留签名以兼容调用方。
    _ = label_for_pos

    out: List[str] = []
    i = 0

    while i < len(lines):
        ln = lines[i]
        cur_pos = ins_pos[i]

        if ln.is_branch:
            target = ln.target_pos
            if ln.cond is None:
                return None
            if target is None or target <= cur_pos:
                # 仅支持前向 branch
                return None

            # fallthrough block: branch 后直到 target 之前的线性区域
            j = i + 1
            fallthrough_block: List[Line] = []
            fallthrough_pos: List[int] = []
            while j < len(lines) and ins_pos[j] < target:
                fallthrough_block.append(lines[j])
                fallthrough_pos.append(ins_pos[j])
                j += 1

            has_else = False
            taken_block: List[Line] = []
            taken_pos: List[int] = []
            region_end = target

            # 识别 if/else：
            # fallthrough block 末尾若是一个跳到更远位置的无条件 jump，
            # 则该 jump 充当 if/else 分隔符：
            #   fallthrough ... ; goto region_end;
            #   target: taken ...
            if fallthrough_block and fallthrough_block[-1].is_jump:
                jump_to = fallthrough_block[-1].target_pos
                if jump_to is not None and jump_to > target:
                    has_else = True
                    region_end = jump_to

                    # 去掉 fallthrough 尾部的“else 分隔 jump”
                    fallthrough_block.pop()
                    fallthrough_pos.pop()

                    # [target, jump_to) 这一段视为 taken block
                    k = j
                    while k < len(lines) and ins_pos[k] < jump_to:
                        taken_block.append(lines[k])
                        taken_pos.append(ins_pos[k])
                        k += 1
                    j = k

            fallthrough_c = structurize(
                fallthrough_block,
                fallthrough_pos,
                label_for_pos,
                region_end,
            )
            if fallthrough_c is None:
                return None

            taken_c = None
            if has_else:
                taken_c = structurize(
                    taken_block,
                    taken_pos,
                    label_for_pos,
                    region_end,
                )
                if taken_c is None:
                    return None

            # cond 是“taken 条件”，因此 C 中要包住 fallthrough：
            #   if (!(cond)) { ... }
            neg = f"!({ln.cond})"
            out.append(f"if ({neg}) {{")
            for s in fallthrough_c:
                out.append("  " + s)

            if has_else:
                out.append("} else {")
                for s in taken_c or []:
                    out.append("  " + s)

            out.append("}")

            i = j
            continue

        if ln.is_jump:
            # 只允许“跳到当前区域末尾”的收尾 jump。
            # 注意这里用 >= end_pos，是为了容忍调用方把 jump
            # 归一到当前区域末尾或更远的哨兵位置。
            if ln.target_pos is not None and ln.target_pos >= end_pos:
                i += 1
                continue
            return None

        # 普通语句允许为空；空语句不会输出任何文本，但不会破坏结构化。
        if ln.text:
            out.append(ln.text)
        i += 1

    return out