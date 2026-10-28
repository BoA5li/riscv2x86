"""Single-access value semantics from typed canonical IR, never assembly text.

Only identity/low-bit transparent definitions are admitted. Arithmetic, merges,
multiple writes and unknown register provenance cannot authorize this route.
"""
from .pcode_ir import VarKind
from .runtime_facts import canonicalize_riscv_register_name


def decoded_access(blocks, runtime_facts):
    ops = [op for block in blocks for ins in block.instructions for op in ins.ops]
    accesses = [op for op in ops if op.opcode in {"LOAD", "STORE"}]
    if len(accesses) != 1 or runtime_facts is None:
        return None
    access = accesses[0]
    store = access.opcode == "STORE"
    if len(access.inputs) != (3 if store else 2):
        return None
    value = access.inputs[2] if store else access.output
    if value is None or type(value.size) is not int or value.size not in {1, 2, 4, 8}:
        return None
    width = value.size * 8
    bindings = getattr(runtime_facts, "rv_to_operand_index", {})
    widths = getattr(runtime_facts, "operand_width_bits", {})
    names = {canonicalize_riscv_register_name(k): v for k, v in bindings.items()}
    # Definitions are ordered: a register read must resolve its preceding
    # definition rather than being mistaken for its original input operand.
    before = next(i for i, op in enumerate(ops) if op is access)
    def resolve(node, limit, seen):
        if type(node.size) is not int or node.size * 8 < width:
            return None
        if (node, limit) in seen:
            return None
        seen = seen | {(node, limit)}
        producers = [(i, op) for i, op in enumerate(ops[:limit]) if op.output == node]
        if producers:
            i, op = producers[-1]
            if op.opcode == "COPY" and len(op.inputs) == 1 and op.inputs[0].size >= node.size:
                return resolve(op.inputs[0], i, seen)
            if (op.opcode == "SUBPIECE" and len(op.inputs) == 2
                    and op.inputs[1].kind is VarKind.CONST and op.inputs[1].offset == 0
                    and op.inputs[0].size >= node.size):
                return resolve(op.inputs[0], i, seen)
            return None
        if node.kind is VarKind.REG:
            view = node.register_read_view
            name = node.name
            if view is not None:
                if (view.offset != node.offset or view.size != node.size
                        or (name and canonicalize_riscv_register_name(name) !=
                            canonicalize_riscv_register_name(view.parent_name))):
                    return None
                name = view.parent_name
            canonical = canonicalize_riscv_register_name(name)
            # A preceding overlapping register definition invalidates input
            # provenance even when its varnode has a different size/view.
            if any(op.output is not None and op.output.kind is VarKind.REG
                   and op.output.space == node.space
                   and op.output.offset < node.offset + node.size
                   and node.offset < op.output.offset + op.output.size
                   for op in ops[:limit]):
                return None
            return names.get(canonical)
        return None
    if store:
        index = resolve(value, before, set())
    else:
        # Loads with post-load extension need a separate proven contract.
        if any(value in op.inputs or
               (op.output is not None and op.output.kind is VarKind.REG
                and value.kind is VarKind.REG and op.output.space == value.space
                and op.output.offset < value.offset + value.size
                and value.offset < op.output.offset + op.output.size)
               for op in ops[before + 1:]):
            return None
        index = names.get(canonicalize_riscv_register_name(value.name)) if value.kind is VarKind.REG else None
    carrier = widths.get(index)
    if type(index) is not int or type(carrier) is not int or carrier not in {8,16,32,64}:
        return None
    if carrier < width or (not store and carrier != width):
        return None
    return width, index, ("low_bits" if store and carrier > width else "identity")


def value_matches(memory, value, width, kind):
    return (type(width) is int and width in {8,16,32,64}
            and type(memory.access_width_bits) is int
            and type(memory.value_operand_index) is int
            and memory.access_width_bits == width
            and memory.value_operand_index == value.source_operand_index
            and type(value.width_bits) is int
            and ((memory.value_projection == "identity" and value.width_bits == width)
                 or (kind == "store" and memory.value_projection == "low_bits"
                     and value.width_bits > width and value.width_bits in {16,32,64})))
