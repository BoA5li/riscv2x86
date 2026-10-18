"""Production ingress for content-bound atomic object authority."""
from __future__ import annotations

from collections.abc import Mapping
from hashlib import sha256
import json
from dataclasses import replace

from .runtime_facts import AtomicMemoryObjectRuntimeFact
from .semantic_authority import (
    AtomicOperationFacts, AuthorityProducerRegistry, RegisteredAuthorityProducer,
    SemanticAuthorityError, semantic_authority_bundle_from_dict,
)
from .compiler_fragment_closure import (
    validate_closed_compiler_fragment_candidate,
)
from .route_authority import AtomicAuthorityError
from .compiler_operand_type import compiler_operand_type_from_dict


ATOMIC_AUTHORITY_PRODUCER_REGISTRY = AuthorityProducerRegistry((
    RegisteredAuthorityProducer(
        "frontend-compiler-sidecar", ("v1",), ("atomic_operation",),
    ),
))


COMPILER_FRAGMENT_AUTHORITY_SCHEMA = (
    "riscv2x86.compiler-fragment-authority.v1"
)


def _identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def atomic_runtime_object_from_compiler_authority(
    raw_authority: Mapping[str, object], *, fragment_id: str,
    source_digest: str, begin_offset: int, end_offset: int,
    runtime_facts: object, atomic_operation: object, frontend_fragment: Mapping | None = None,
) -> dict[int, AtomicMemoryObjectRuntimeFact]:
    """Join compiler object authority with decoder-owned AMO semantics.

    The compiler payload never claims that an instruction is atomic.  It only
    identifies GNU operands and their source objects.  Operation kind,
    ordering, width and register roles come exclusively from the canonical
    decoder fact supplied here.
    """
    required = {
        "schemaVersion", "sourceDigest", "fragmentId", "targetTriple",
        "functionIdentity", "fragmentBindingKey", "candidate",
        "memoryObjectBindings", "authorityIdentity",
    }
    from .fragment_source_range import AUTHORITY_SCHEMA, validate_fragment_source_range
    ranged = raw_authority.get("schemaVersion") == AUTHORITY_SCHEMA
    typed = ranged or raw_authority.get("schemaVersion") == "riscv2x86.compiler-fragment-authority.v2"
    if ranged:
        required.add("sourceRangeBinding")
    if typed:
        required.add("compilerTypeBindings")
    if set(raw_authority) != required:
        raise AtomicAuthorityError("ATOMIC_COMPILER_AUTHORITY_FIELDS_INVALID", "compiler fragment authority fields are invalid")
    unsigned = {key: value for key, value in raw_authority.items()
                if key != "authorityIdentity"}
    if (raw_authority.get("schemaVersion") not in {COMPILER_FRAGMENT_AUTHORITY_SCHEMA,
                "riscv2x86.compiler-fragment-authority.v2", AUTHORITY_SCHEMA}
            or raw_authority.get("sourceDigest") != source_digest
            or raw_authority.get("fragmentId") != fragment_id
            or raw_authority.get("targetTriple") != "riscv64-linux-gnu"
            or raw_authority.get("authorityIdentity") != _identity(unsigned)):
        raise AtomicAuthorityError("ATOMIC_COMPILER_AUTHORITY_IDENTITY_MISMATCH", "compiler fragment authority is stale or malformed")
    key = raw_authority.get("fragmentBindingKey")
    candidate = raw_authority.get("candidate")
    objects = raw_authority.get("memoryObjectBindings")
    if not isinstance(key, Mapping) or not isinstance(candidate, Mapping) \
            or not isinstance(objects, Mapping):
        raise AtomicAuthorityError("ATOMIC_COMPILER_AUTHORITY_PAYLOAD_INVALID", "compiler fragment authority payload is malformed")
    from .fragment_source_range import equal, FragmentRangeError
    try:
        equal("source_digest", source_digest, key.get("sourceDigest"))
        equal("function_identity", raw_authority.get("functionIdentity"), key.get("functionIdentity"))
        equal("candidate_key", dict(key), candidate.get("fragmentBindingKey"))
        for field in ("complete", "compilerStructureComplete", "operandClassificationComplete"):
            equal(field, True, candidate.get(field))
        if ranged:
            validate_fragment_source_range(raw_authority["sourceRangeBinding"], key,
                fragment_id=fragment_id, source_digest=source_digest,
                begin_offset=begin_offset, end_offset=end_offset, frontend_fragment=frontend_fragment)
        else:
            equal("begin_offset", begin_offset, key.get("beginOffset"))
            equal("end_offset", end_offset, key.get("endOffset"))
    except FragmentRangeError as exc:
        raise AtomicAuthorityError(exc.reason_code, str(exc), exc.failure_stage) from exc
    try:
        validate_closed_compiler_fragment_candidate(candidate)
    except ValueError as exc:
        raise AtomicAuthorityError("ATOMIC_COMPILER_CLOSURE_INVALID", str(exc)) from exc
    register_map = getattr(runtime_facts, "rv_to_operand_index", {})
    width_map = getattr(runtime_facts, "operand_width_bits", {})
    address_register = getattr(atomic_operation, "address_binding", "")
    address_index = register_map.get(address_register)
    width_bits = getattr(atomic_operation, "width_bits", None)
    if (not isinstance(address_index, int) or isinstance(address_index, bool)
            or width_bits not in {32, 64}):
        raise AtomicAuthorityError("ATOMIC_DECODER_ADDRESS_UNBOUND", "atomic decoder address binding is unavailable")
    bindings = candidate.get("operandBindings")
    carriers = candidate.get("operandCarriers")
    if not isinstance(bindings, list) or not isinstance(carriers, list):
        raise AtomicAuthorityError("ATOMIC_COMPILER_OPERANDS_MISSING", "compiler operand authority is unavailable")
    expected_indexes = set(int(item) for item in width_map)
    binding_indexes = {item.get("operandIndex") for item in bindings
                       if isinstance(item, Mapping)}
    carrier_by_index = {item.get("operandIndex"): item for item in carriers
                        if isinstance(item, Mapping)}
    binding_by_index = {item.get("operandIndex"): item for item in bindings
                        if isinstance(item, Mapping)}
    if binding_indexes != expected_indexes or set(carrier_by_index) != expected_indexes:
        raise AtomicAuthorityError("ATOMIC_OPERAND_INDEX_SET_MISMATCH", "compiler/assembler operand authority mismatch")
    binding = binding_by_index.get(address_index)
    carrier = carrier_by_index.get(address_index)
    projection = None
    if isinstance(carrier, Mapping) and carrier.get('carrierKind')=='memory_lvalue':
        from .memory_address_projection import project_memory_address
        try:projection=project_memory_address(candidate,address_index)
        except ValueError as exc:
            raise AtomicAuthorityError('ATOMIC_ADDRESS_PROJECTION_UNPROVEN',str(exc)) from exc
        pointer=compiler_operand_type_from_dict(projection['compilerPointerType'])
        # A typed address view, not an extra GNU operand or declaration carrier.
        binding={**binding,'declarationIdentity':projection['baseDeclarationIdentity'],
            'widthBits':pointer.width_bits,'access':'input'}
        carrier={**carrier,'carrierKind':'pointer','declarationIdentity':projection['baseDeclarationIdentity'],
            'widthBits':pointer.width_bits}

    if (not isinstance(binding, Mapping) or not isinstance(carrier, Mapping)
            or carrier.get("carrierKind") != "pointer"
            or binding.get("access") not in {"input", "read_write"}
            or binding.get("declarationIdentity") != carrier.get("declarationIdentity")
            or binding.get("valueNodeIdentity") != carrier.get("valueNodeIdentity")
            or binding.get("complete") is not True or carrier.get("complete") is not True):
        raise AtomicAuthorityError("ATOMIC_ADDRESS_CARRIER_INCOMPLETE", "atomic address is not a complete compiler pointer binding")
    value_index = register_map.get(getattr(
        atomic_operation, "input_value_binding", ""))
    result_name = getattr(atomic_operation, "result_binding", None)
    result_index = None if result_name is None else register_map.get(result_name)
    result_semantics = getattr(atomic_operation, "result_semantics", None)
    value_binding = binding_by_index.get(value_index)
    value_carrier = carrier_by_index.get(value_index)
    register_width=getattr(atomic_operation,'register_width_bits',0)
    extension=getattr(atomic_operation,'result_extension','')
    def carrier_width_supported(width):
        return width==width_bits or (width_bits==32 and width==64 and register_width==64
            and extension in {'sign_extend','none'})
    if (not isinstance(value_index, int)
            or not isinstance(value_binding, Mapping)
            or not isinstance(value_carrier, Mapping)
            or value_binding.get("access") not in {"input", "read_write"}
            or value_carrier.get("carrierKind") != "integer"
            or not carrier_width_supported(value_binding.get("widthBits"))
            or value_binding.get("valueNodeIdentity") !=
                value_carrier.get("valueNodeIdentity")):
        raise AtomicAuthorityError("ATOMIC_INPUT_VALUE_BINDING_INCOMPLETE", "atomic input value binding is incomplete")
    if (value_binding.get("declarationIdentity") != value_carrier.get("declarationIdentity")
            or value_carrier.get("widthBits") != value_binding.get("widthBits")
            or value_carrier.get("signedness") != value_binding.get("signedness")
            or value_binding.get("complete") is not True
            or value_carrier.get("complete") is not True):
        raise AtomicAuthorityError("ATOMIC_INPUT_CARRIER_MISMATCH", "atomic input carrier/value authority disagrees")
    # The finite decoder family is AMO RMW, not CAS or LR/SC. Accepting an
    # arbitrary result-semantics enum here would approve a different operation.
    if result_semantics not in {"old_value", "none"}:
        raise AtomicAuthorityError("ATOMIC_RESULT_SEMANTICS_MISMATCH", "AMO RMW returns old_value or discards rd")
    if result_semantics == "none":
        if result_name is not None:
            raise AtomicAuthorityError("ATOMIC_DISCARDED_RESULT_BOUND", "discarded atomic result has a result binding")
    elif result_semantics in {"old_value", "new_value", "success_flag"}:
        result_binding = binding_by_index.get(result_index)
        result_carrier = carrier_by_index.get(result_index)
        if (not isinstance(result_index, int)
                or not isinstance(result_binding, Mapping)
                or result_binding.get("access") not in {"output", "read_write"}):
            raise AtomicAuthorityError("ATOMIC_RESULT_BINDING_INCOMPLETE", "atomic result binding is incomplete")
        if (not isinstance(result_carrier, Mapping)
                or result_carrier.get("carrierKind") != "integer"
                or result_binding.get("valueNodeIdentity") != result_carrier.get("valueNodeIdentity")
                or result_binding.get("declarationIdentity") != result_carrier.get("declarationIdentity")
                or not carrier_width_supported(result_binding.get("widthBits"))
                or result_carrier.get("widthBits") != result_binding.get("widthBits")
                or result_binding.get("complete") is not True
                or result_carrier.get("complete") is not True):
            raise AtomicAuthorityError("ATOMIC_RESULT_CARRIER_MISMATCH", "atomic result carrier width/value binding disagrees")
    else:
        raise AtomicAuthorityError("ATOMIC_RESULT_SEMANTICS_UNSUPPORTED", "atomic result semantics is unsupported")
    expression_memory_bindings = []
    expression_memory_indexes = []
    expression_access_bindings = []
    if candidate.get('schemaVersion') == 'riscv2x86.closed-compiler-fragment.v2':
        evaluation = candidate['expressionEvaluation']
        from .compiler_expression import direct_declaration_carrier
        if binding.get('access') != 'input':
            raise AtomicAuthorityError('ATOMIC_EXPRESSION_ADDRESS_PHASE_UNPROVEN',
                'Expression-backed objects require a read-only pointer carrier')
        for evaluated, joined in zip(evaluation['bindings'], evaluation['expressionJoin']['operands']):
            if evaluated['role'] != 'memory_lvalue':
                continue
            expression = joined['expression']
            while expression['kind'] == 'ParenExpr':
                expression = expression['children'][0]
            if (expression['kind'] != 'UnaryOperator' or expression['operation'] != '*'
                    or len(expression['children']) != 1
                    or direct_declaration_carrier(expression['children'][0]) != binding['declarationIdentity']
                    or evaluated['access'] != 'read_write'
                    or joined['compilerType']['widthBits'] != width_bits):
                raise AtomicAuthorityError('ATOMIC_EXPRESSION_OBJECT_ADDRESS_UNPROVEN',
                    'Memory lvalue must be an exact read-write dereference of the bound pointer at the access width')
            expression_memory_bindings.append(evaluated['bindingIdentity'])
            expression_memory_indexes.append(evaluated['operandIndex'])
            expression_access_bindings.append({
                'schemaVersion':'riscv2x86.atomic-memory-access-binding.v1',
                'fragmentId':fragment_id,'sourceDigest':source_digest,
                'compilerAuthorityIdentity':raw_authority['authorityIdentity'],
                'memoryOperandIndex':evaluated['operandIndex'],'addressOperandIndex':address_index,
                'memoryExpressionIdentity':evaluated['expressionIdentity'],
                'evaluationBindingIdentity':evaluated['bindingIdentity'],
                'addressValueNodeIdentity':binding['valueNodeIdentity'],
                'memoryAddressValueNodeIdentity':evaluated['addressNode']['valueNodeIdentity'],
                'memoryObjectIdentity':'', 'offsetBytes':0,'widthBits':width_bits,
                'access':evaluated['access'],'relationKind':'exact_dereference_of_carrier'})

    declaration = str(binding.get("declarationIdentity") or "")
    type_bindings = raw_authority.get("compilerTypeBindings", {})
    type_binding = type_bindings.get(str(address_index)) if isinstance(type_bindings, Mapping) else None
    if projection is not None:
        type_binding={'operandIndex':address_index,'valueNodeIdentity':binding['valueNodeIdentity'],
            'compilerType':projection['compilerPointerType']}
    if (not isinstance(type_binding, Mapping)
            or set(type_binding) != {"operandIndex", "valueNodeIdentity", "compilerType"}
            or type_binding.get("operandIndex") != address_index
            or type_binding.get("valueNodeIdentity") != binding["valueNodeIdentity"]):
        raise AtomicAuthorityError("ATOMIC_POINTEE_TYPE_AUTHORITY_MISSING", "Compiler pointer/pointee type binding is required; a value node is not a C type")
    try:
        pointer_type = compiler_operand_type_from_dict(type_binding["compilerType"])
    except ValueError as exc:
        raise AtomicAuthorityError("ATOMIC_POINTEE_TYPE_AUTHORITY_INVALID", str(exc)) from exc
    if (not pointer_type.is_pointer or not pointer_type.side_effect_free
            or pointer_type.width_bits != binding["widthBits"]
            or pointer_type.pointee_width_bits != width_bits):
        raise AtomicAuthorityError("ATOMIC_POINTEE_WIDTH_MISMATCH", "Compiler pointee width disagrees with atomic memory access")
    if pointer_type.pointee_qualifiers:
        raise AtomicAuthorityError("ATOMIC_POINTEE_QUALIFIER_CONTRACT_REQUIRED", "Qualified atomic objects require a dedicated qualifier/shell contract")
    memory_object = objects.get(declaration)
    if not isinstance(memory_object, Mapping):
        raise AtomicAuthorityError("ATOMIC_MEMORY_OBJECT_MISSING", "atomic memory object binding is missing")
    object_required = {
        "schemaVersion", "objectIdentity", "baseDeclarationIdentity",
        "objectSizeBytes", "provenAlignmentBytes", "aliasDomainIdentity",
        "addressSpaceIdentity", "volatile", "bindingOrigin",
        "producerIdentity", "sourceDigest", "bindingIdentity",
    }
    object_unsigned = {k: v for k, v in memory_object.items()
                       if k != "bindingIdentity"}
    alignment = memory_object.get("provenAlignmentBytes")
    size = memory_object.get("objectSizeBytes")
    if (set(memory_object) != object_required
            or memory_object.get("schemaVersion") != "riscv2x86.memory-object-binding.v1"
            or memory_object.get("sourceDigest") != source_digest
            or memory_object.get("baseDeclarationIdentity") != declaration
            or memory_object.get("bindingIdentity") != _identity(object_unsigned)
            or not isinstance(alignment, int) or isinstance(alignment, bool)
            or alignment < width_bits // 8 or alignment & (alignment - 1)
            or type(memory_object.get("volatile")) is not bool
            or not all(isinstance(memory_object.get(k), str) and memory_object[k]
                for k in ("objectIdentity", "aliasDomainIdentity", "addressSpaceIdentity",
                          "bindingOrigin", "producerIdentity"))):
        raise AtomicAuthorityError("ATOMIC_MEMORY_OBJECT_PROVENANCE_INVALID", "atomic memory object alignment/provenance is incomplete")
    if not isinstance(size, int) or isinstance(size, bool) or size < width_bits // 8:
        raise AtomicAuthorityError("ATOMIC_MEMORY_OBJECT_BOUNDS_UNPROVEN", "atomic access is not covered by the bound object")
    if memory_object["addressSpaceIdentity"] != "c.default":
        raise AtomicAuthorityError("ATOMIC_ADDRESS_SPACE_UNSUPPORTED", "Only explicitly bound default C memory is supported")
    # v1 describes a harness-owned object at offset zero. It is not a static
    # proof of arbitrary caller memory; do not silently turn it into one.
    if (memory_object["bindingOrigin"] != "automatic-aligned-memory-object-harness-v1"
            or memory_object["producerIdentity"] != "automatic-l1-memory-harness.v1"):
        raise AtomicAuthorityError("ATOMIC_OBJECT_ENVIRONMENT_CONTRACT_REQUIRED", "Non-harness memory needs a versioned object/environment contract")
    operation_kind = getattr(atomic_operation, "operation_kind", "")
    arithmetic = {
        "exchange": "exchange", "fetch_add": "add_mod_2n",
        "fetch_and": "and_bits", "fetch_or": "or_bits",
        "fetch_xor": "xor_bits",
    }.get(operation_kind)
    if arithmetic is None or getattr(atomic_operation, "complete", False) is not True:
        raise AtomicAuthorityError("ATOMIC_OPERATION_UNSUPPORTED", "atomic operation is outside the production RMW capability")
    ordering = (
        "before:" + str(getattr(atomic_operation, "ordering_before", "")),
        "after:" + str(getattr(atomic_operation, "ordering_after", "")),
    )
    relation = {
        "schemaVersion": "riscv2x86.atomic-compiler-decoder-join.v1",
        "compilerAuthorityIdentity": raw_authority["authorityIdentity"],
        "fragmentId": fragment_id, "addressOperandIndex": address_index,
        "valueOperandIndex": value_index, "resultOperandIndex": result_index,
        "decoderOperationKind": operation_kind, "widthBits": width_bits,
        "ordering": list(ordering),
        "sourceAddressSpace": memory_object["addressSpaceIdentity"],
        "architecturalAddressSpace": getattr(
            atomic_operation, "address_space_identity", ""),
        "targetTriple": raw_authority["targetTriple"],
        "memoryObjectBindingIdentity": memory_object["bindingIdentity"],
        "environmentAssumption": memory_object["bindingOrigin"],
        "memoryAccessWidth": width_bits, "inputEffectiveWidth": width_bits,
        "inputCarrierWidth":value_binding['widthBits'],
        "inputTruncation":'low_bits' if value_binding['widthBits']>width_bits else 'none',
        "sourceRegisterWidth":register_width,
        "registerResultWidth": (register_width or result_binding.get('widthBits')) if result_semantics=='old_value' else 0,
        "resultCarrierWidth":result_binding.get('widthBits') if result_semantics=='old_value' else 0,
        "resultExtension":extension or ('identity' if result_semantics=='old_value' else 'none'),
        "resultSemantics": result_semantics,
        "compilerPointerTypeIdentity": pointer_type.type_identity,
        "compilerPointeeTypeIdentity": pointer_type.pointee_type_identity,
        "expressionMemoryBindingIdentities": sorted(expression_memory_bindings),
    }
    if expression_access_bindings:
        for association in expression_access_bindings:
            association['memoryObjectIdentity']=memory_object['objectIdentity']
        relation['schemaVersion']='riscv2x86.atomic-compiler-decoder-join.v2'
        relation['expressionMemoryAccessBindings']=expression_access_bindings
    if projection is not None:relation["addressProjection"] = projection
    join_identity = _identity(relation)
    address_fact = AtomicMemoryObjectRuntimeFact(
        address_projection=projection,
        object_identity=str(memory_object["objectIdentity"]),
        address_space_identity=str(getattr(
            atomic_operation, "address_space_identity", "")),
        alignment_bytes=alignment,
        pointee_type_id=pointer_type.pointee_type_identity,
        authority_identity=join_identity,
        operation_kind=operation_kind,
        arithmetic_relation=arithmetic,
        wraparound_width_bits=width_bits,
        ordering=ordering,
        read_effect_identity=join_identity + ":read",
        write_effect_identity=join_identity + ":write",
        address_space_relation_identity=join_identity + ":address-space",
    )
    objects={address_index:address_fact}
    from .atomic_memory_binding import validate_binding
    for association in expression_access_bindings:
        association={**association,'joinPayload':json.loads(json.dumps(relation)),
            'authorityIdentity':join_identity,
            'readEffectIdentity':address_fact.read_effect_identity,
            'writeEffectIdentity':address_fact.write_effect_identity}
        association['bindingIdentity']=_identity(association)
        validate_binding(association)
        objects[association['memoryOperandIndex']]=replace(address_fact,
            operand_role='memory_lvalue',memory_access_binding=association)
    return objects



def atomic_runtime_objects_from_bundle(
    raw_bundle: Mapping[str, object], *, fragment_id: str, source_digest: str,
    operand_indexes: frozenset[int],
) -> dict[int, AtomicMemoryObjectRuntimeFact]:
    """Validate a sidecar and materialize only complete atomic object facts."""
    known_nodes = frozenset(f"operand:{item}" for item in operand_indexes)
    bundle = semantic_authority_bundle_from_dict(
        raw_bundle, expected_fragment_id=fragment_id,
        expected_source_digest=source_digest,
        producer_registry=ATOMIC_AUTHORITY_PRODUCER_REGISTRY,
        known_decoder_node_ids=known_nodes,
    )
    atomic = [item for item in bundle.authorities
              if item.fact_kind == "atomic_operation"]
    if len(atomic) != 1 or not atomic[0].complete:
        raise SemanticAuthorityError(
            "atomic authority bundle requires exactly one complete atomic operation"
        )
    authority = atomic[0]
    payload = authority.payload
    if not isinstance(payload, AtomicOperationFacts):
        raise SemanticAuthorityError("atomic authority payload has wrong type")
    index = payload.address_operand_index
    if index not in operand_indexes or payload.address_node_id != f"operand:{index}":
        raise SemanticAuthorityError("atomic address operand authority mismatch")
    expected_relation = {
        "exchange": "exchange", "fetch_add": "add_mod_2n",
        "fetch_and": "and_bits", "fetch_or": "or_bits",
        "fetch_xor": "xor_bits", "compare_exchange": "compare_exchange",
    }.get(payload.operation_kind)
    if expected_relation is None or payload.arithmetic_relation != expected_relation:
        raise SemanticAuthorityError("atomic arithmetic relation mismatch")
    return {index: AtomicMemoryObjectRuntimeFact(
        object_identity=str(payload.memory_object_identity),
        address_space_identity=str(payload.address_space_identity),
        alignment_bytes=int(payload.alignment_bytes),
        pointee_type_id=str(payload.pointee_type_id),
        authority_identity=authority.authority_identity,
        operation_kind=str(payload.operation_kind),
        arithmetic_relation=str(payload.arithmetic_relation),
        wraparound_width_bits=int(payload.wraparound_width_bits),
        ordering=tuple(payload.ordering),
        read_effect_identity=str(payload.read_effect_identity),
        write_effect_identity=str(payload.write_effect_identity),
        address_space_relation_identity=authority.authority_identity
        + ":address-space-relation",
    )}
