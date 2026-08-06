import inspect

_RC_WEAKMEM_UNPROVEN = globals().get("RC_WEAK_MEMORY_UNPROVEN", "weak_memory_unproven")
_RC_MICROARCH_UNPROVEN = globals().get("RC_MICROARCH_VALIDATOR_UNAVAILABLE", "microarch_validator_unavailable")

_ATOMIC_ORDER_TOKEN_RE = re.compile(r"__ATOMIC_[A-Z_]+")
_AMO_SRC_RE = re.compile(
    r"\b(amo(?:add|or|and|xor|swap))\.(w|d)(?:\.(aqrl|aq|rl))?\b",
    re.IGNORECASE,
)
_LR_SRC_RE = re.compile(r"\blr\.(w|d)(?:\.(aqrl|aq|rl))?\b", re.IGNORECASE)
_SC_SRC_RE = re.compile(r"\bsc\.(w|d)(?:\.(aqrl|aq|rl))?\b", re.IGNORECASE)
_ORDER_NOTE_RE = re.compile(
    r"(?:source\.)?(?:order|success_order|failure_order)\s*=\s*([A-Za-z0-9_]+)",
    re.IGNORECASE,
)

def _extract_atomic_orders(replacement: str) -> list[str]:
    out: list[str] = []
    for m in _ATOMIC_ORDER_TOKEN_RE.finditer(replacement or ""):
        x = _normalize_atomic_order_token(m.group(0))
        if x != "unknown":
            out.append(x)
    return out

def _extract_atomic_order(replacement: str) -> str:
    orders = _extract_atomic_orders(replacement)
    return orders[0] if orders else "unknown-order"

def _normalize_atomic_order_token(tok: str) -> str:
    s = str(tok or "").strip().lower()
    s = s.replace("__atomic_", "")
    table = {
        "relaxed": "relaxed",
        "consume": "acquire",   # 保守近似
        "acquire": "acquire",
        "release": "release",
        "acq_rel": "acq_rel",
        "acqrel": "acq_rel",
        "seq_cst": "seq_cst",
        "seqcst": "seq_cst",
    }
    return table.get(s, "unknown")

def _aqrl_tag_to_order(tag: str) -> str:
    t = str(tag or "").strip().lower()
    if t == "aq":
        return "acquire"
    if t == "rl":
        return "release"
    if t == "aqrl":
        return "acq_rel"
    return "relaxed"

def _order_covers(actual: str, required: str) -> bool:
    actual = _normalize_atomic_order_token(actual)
    required = _normalize_atomic_order_token(required)

    if required == "unknown" or actual == "unknown":
        return False
    if required == "relaxed":
        return actual in {"relaxed", "acquire", "release", "acq_rel", "seq_cst"}
    if required == "acquire":
        return actual in {"acquire", "acq_rel", "seq_cst"}
    if required == "release":
        return actual in {"release", "acq_rel", "seq_cst"}
    if required == "acq_rel":
        return actual in {"acq_rel", "seq_cst"}
    if required == "seq_cst":
        return actual == "seq_cst"
    return False

def _source_order_from_notes(tr) -> str:
    for n in _tr_notes(tr):
        m = _ORDER_NOTE_RE.search(str(n))
        if m:
            v = _normalize_atomic_order_token(m.group(1))
            if v != "unknown":
                return v
    return "unknown"

def _source_order_from_amo(frag, lift, tr) -> str:
    note_v = _source_order_from_notes(tr)
    if note_v != "unknown":
        return note_v

    texts: list[str] = []
    for insn in list(getattr(lift, "insns", []) or []):
        texts.append(str(getattr(insn, "asm_mnem", "") or ""))
    if frag is not None:
        texts.append(str(getattr(frag, "rawAsmText", "") or ""))

    for t in texts:
        m = _AMO_SRC_RE.search(t)
        if m:
            return _aqrl_tag_to_order(m.group(3) or "")
    return "unknown"

def _infer_lrsc_width(frag, lift, tr, default: int = 32) -> int:
    notes = " ".join(_tr_notes(tr)).lower()
    if "width=64" in notes:
        return 64
    if "width=32" in notes:
        return 32

    texts: list[str] = []
    for insn in list(getattr(lift, "insns", []) or []):
        texts.append(str(getattr(insn, "asm_mnem", "") or ""))
    if frag is not None:
        texts.append(str(getattr(frag, "rawAsmText", "") or ""))

    blob = " | ".join(texts).lower()
    if "lr.d" in blob or "sc.d" in blob:
        return 64
    if "lr.w" in blob or "sc.w" in blob:
        return 32
    return default

def _source_order_from_lrsc(frag, lift, tr) -> str:
    note_v = _source_order_from_notes(tr)
    if note_v != "unknown":
        return note_v

    texts: list[str] = []
    for insn in list(getattr(lift, "insns", []) or []):
        texts.append(str(getattr(insn, "asm_mnem", "") or ""))
    if frag is not None:
        texts.append(str(getattr(frag, "rawAsmText", "") or ""))

    aq = False
    rl = False
    for t in texts:
        for m in _LR_SRC_RE.finditer(t):
            tag = (m.group(2) or "").lower()
            aq = aq or ("aq" in tag)
            rl = rl or ("rl" in tag)
        for m in _SC_SRC_RE.finditer(t):
            tag = (m.group(2) or "").lower()
            aq = aq or ("aq" in tag)
            rl = rl or ("rl" in tag)

    if aq and rl:
        return "acq_rel"
    if aq:
        return "acquire"
    if rl:
        return "release"
    return "relaxed"

def _check_atomic_order(required: str, emitted_orders: list[str], *, what: str) -> VerifyResult:
    emitted = emitted_orders[0] if emitted_orders else "unknown"

    if required == "unknown" or emitted == "unknown":
        return _vr_build_only(
            _RC_WEAKMEM_UNPROVEN,
            f"{what}: atomic order compatibility not fully proven (required={required}, emitted={emitted})",
        )

    if not _order_covers(emitted, required):
        return _vr_failed(
            _RC_WEAKMEM_UNPROVEN,
            f"{what}: emitted atomic order '{emitted}' is weaker than required '{required}'",
        )

    return _vr_verified(
        f"{what}: atomic order lattice compatible (required={required}, emitted={emitted})"
    )

def _check_cas_orders(required: str, emitted_orders: list[str]) -> VerifyResult:
    base = _check_atomic_order(required, emitted_orders, what="LR/SC CAS")
    if base.status == "failed":
        return base

    succ = emitted_orders[0] if len(emitted_orders) >= 1 else "unknown"
    fail = emitted_orders[1] if len(emitted_orders) >= 2 else succ

    if fail in {"release", "acq_rel"}:
        return _vr_failed(
            _RC_WEAKMEM_UNPROVEN,
            f"LR/SC CAS: compare_exchange failure order must not be {fail}",
        )

    if succ != "unknown" and fail != "unknown" and not _order_covers(succ, fail):
        return _vr_failed(
            _RC_WEAKMEM_UNPROVEN,
            f"LR/SC CAS: failure order '{fail}' must not be stronger than success order '{succ}'",
        )

    return base

def _invoke_checker_flexibly(
    checker,
    *,
    frag=None,
    out=None,
    lift=None,
    ir_summary=None,
    contract=None,
    kind=None,
    meta=None,
):
    alias = {
        "frag": frag,
        "out": out,
        "tr": out,
        "translation": out,
        "lift": lift,
        "summary": ir_summary,
        "ir_summary": ir_summary,
        "contract": contract,
        "kind": kind,
        "meta": meta,
    }

    try:
        sig = inspect.signature(checker)
    except Exception:
        # 最后兜底，按常见新接口调用
        return checker(frag=frag, out=out, lift=lift, ir_summary=ir_summary, contract=contract, kind=kind, meta=meta)

    kwargs = {}
    for name, p in sig.parameters.items():
        if p.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue
        if name in alias:
            kwargs[name] = alias[name]

    return checker(**kwargs)

def _run_weak_memory_validator(kind: str, frag, lift, tr, *, meta=None) -> VerifyResult:
    checker = (
        globals().get("_verify_atomic_weak_memory")
        or globals().get("_verify_weak_memory_model")
        or globals().get("_verify_memory_order_equivalence")
    )
    if checker is None:
        return _vr_build_only(
            _RC_WEAKMEM_UNPROVEN,
            f"no weak-memory validator installed for {kind}",
        )

    try:
        raw = _invoke_checker_flexibly(
            checker,
            frag=frag,
            out=tr,
            lift=lift,
            ir_summary=None,
            contract=None,
            kind=kind,
            meta=meta,
        )
        return _coerce_legacy_semantic_result(
            raw,
            unavailable_reason=_RC_WEAKMEM_UNPROVEN,
        )
    except Exception as e:
        return _vr_build_only(
            _RC_WEAKMEM_UNPROVEN,
            f"{kind} weak-memory validator raised: {e}",
        )

def _merge_semantic_layers(func_vr: VerifyResult, order_vr: VerifyResult, weak_vr: VerifyResult) -> VerifyResult:
    detail = _merge_details(
        getattr(func_vr, "detail", ""),
        f"order: {getattr(order_vr, 'detail', '')}",
        f"weak-memory: {getattr(weak_vr, 'detail', '')}",
    )

    if func_vr.status == "failed" or order_vr.status == "failed" or weak_vr.status == "failed":
        rc = (
            getattr(func_vr, "reason_code", None)
            or getattr(order_vr, "reason_code", None)
            or getattr(weak_vr, "reason_code", None)
            or RC_SEMANTIC_PROOF_FAILED
        )
        return _vr_failed(rc, detail)

    # 真正 verified 的前提：功能证明通过 + 弱内存验证器也通过。
    # order_vr 允许是 build_only（例如 replacement 里没有直观 order token），
    # 因为弱内存验证器可能已经覆盖了这部分。
    if func_vr.status == "verified" and weak_vr.status == "verified":
        return _vr_verified(detail)

    return _vr_build_only(_RC_WEAKMEM_UNPROVEN, detail)

def _run_microarch_validator(frag, tr, lift=None, ir_summary=None, contract=None) -> VerifyResult:
    checker = (
        globals().get("_verify_microarch_e2e")
        or globals().get("_verify_microarchitectural_preservation")
        or globals().get("_run_phase8_microarch_validator")
    )
    if checker is None:
        return _vr_build_only(
            _RC_MICROARCH_UNPROVEN,
            "no phase8 microarchitectural validator installed",
        )

    try:
        raw = _invoke_checker_flexibly(
            checker,
            frag=frag,
            out=tr,
            lift=lift,
            ir_summary=ir_summary,
            contract=contract,
            kind="microarch",
            meta=None,
        )
        return _coerce_legacy_semantic_result(
            raw,
            unavailable_reason=_RC_MICROARCH_UNPROVEN,
        )
    except Exception as e:
        return _vr_build_only(
            _RC_MICROARCH_UNPROVEN,
            f"microarchitectural validator raised: {e}",
        )

def _with_microarch_plan(
    vr: VerifyResult,
    tr: TranslationOutput,
    frag: Optional[AsmFragment] = None,
    lift=None,
    ir_summary: Optional[IRSummary] = None,
    contract: Optional[TranslationContract] = None,
) -> VerifyResult:
    if vr.status in {"failed", "unsupported"}:
        return vr

    if not _needs_microarch_e2e(tr, frag):
        return vr

    micro_vr = _run_microarch_validator(
        frag=frag,
        tr=tr,
        lift=lift,
        ir_summary=ir_summary,
        contract=contract,
    )
    detail = _merge_details(
        getattr(vr, "detail", ""),
        f"microarch: {getattr(micro_vr, 'detail', '')}",
    )

    if micro_vr.status == "failed":
        return _vr_failed(
            getattr(micro_vr, "reason_code", None) or _RC_MICROARCH_UNPROVEN,
            detail,
        )

    if vr.status == "verified" and micro_vr.status == "verified":
        return _vr_verified(detail)

    return _vr_build_only(
        getattr(micro_vr, "reason_code", None) or _RC_MICROARCH_UNPROVEN,
        detail,
    )