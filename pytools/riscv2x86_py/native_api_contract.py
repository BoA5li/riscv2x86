"""Compiler-declaration-driven, bounded API harnesses.

An executable allocation/initialization contract, not an inferred callee memory
safety theorem. Declared preconditions remain explicit assumptions. Unsupported
aggregate/variadic/attribute/typedef layouts cannot silently become scalars.
"""
import re
from .project_build_records import identity

SCHEMA='riscv2x86.native-api-domain.v1'
IDENT=re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
MAX_ELEMENTS=65536
BASE={
 'signed char':('1',True),'unsigned char':('1',False),
 'short':('__SIZEOF_SHORT__',True),'unsigned short':('__SIZEOF_SHORT__',False),
 'int':('__SIZEOF_INT__',True),'unsigned int':('__SIZEOF_INT__',False),
 'long':('__SIZEOF_LONG__',True),'unsigned long':('__SIZEOF_LONG__',False),
 'long long':('__SIZEOF_LONG_LONG__',True),'unsigned long long':('__SIZEOF_LONG_LONG__',False),
}


def fields(value,expected,label):
    if not isinstance(value,dict) or set(value)!=set(expected):raise ValueError(label+'_FIELDS_INVALID')


def ctype(facts,model,*,allow_void=False):
    if not isinstance(facts,dict):raise ValueError('API_COMPILER_TYPE_REQUIRED')
    spelling=facts.get('desugaredQualType',facts.get('qualType',''))
    if not isinstance(spelling,str):raise ValueError('API_COMPILER_TYPE_REQUIRED')
    name=' '.join(spelling.split());pointer=name.endswith('*')
    if pointer:name=name[:-1].strip()
    const=name.startswith('const ')
    if const:name=name[6:]
    if name=='void' and allow_void and not pointer and not const:
        return {'cType':'void','kind':'void','bits':0,'signed':False,'const':False}
    if name not in BASE or (const and not pointer):raise ValueError('API_TYPE_LAYOUT_UNSUPPORTED:'+spelling)
    key,signed=BASE[name]
    size=int(key if key=='1' else model.get(key,0))
    if (any(model.get(k)!=v for k,v in {'__CHAR_BIT__':'8','__SIZEOF_POINTER__':'8',
            '__SIZEOF_SHORT__':'2','__SIZEOF_INT__':'4','__SIZEOF_LONG__':'8','__SIZEOF_LONG_LONG__':'8'}.items())
            or size not in (1,2,4,8)):
        raise ValueError('API_SCALAR_LP64_MODEL_REQUIRED')
    return {'cType':('const ' if const else '')+name+(' *' if pointer else ''),
            'elementType':name,'kind':'pointer' if pointer else 'integer',
            'bits':size*8,'signed':signed,'const':const}


def signature(facts,model):
    fields(facts,('type','variadic','parameters','attributes'),'API_SIGNATURE')
    if facts['variadic'] is not False or not isinstance(facts['attributes'],list) or any(
            a not in ('NoThrowAttr','NonNullAttr') for a in facts['attributes']):
        raise ValueError('API_FIXED_DEFAULT_C_ABI_REQUIRED')
    spelling=(facts['type'] or {}).get('qualType','')
    # This restricted parser only extracts an ordinary C return type. Parameter
    # classification uses compiler-resolved ParmVarDecl types, never this text.
    if not isinstance(spelling,str) or spelling.count('(')!=1 or spelling.count(')')!=1:
        raise ValueError('API_FUNCTION_PROTOTYPE_REQUIRED')
    result=ctype({'qualType':spelling.split('(',1)[0].strip()},model,allow_void=True)
    if result['kind']=='pointer':raise ValueError('API_POINTER_RETURN_LIFETIME_CONTRACT_REQUIRED')
    args=[ctype(p,model) for p in facts['parameters']]
    if len(args)>32:raise ValueError('API_PARAMETER_BUDGET_EXCEEDED')
    return {'return':result,'parameters':args,'profile':'fixed-default-C-scalar-pointer-LP64.v1',
            'declarationAttributes':list(facts['attributes'])}



def resolve_signature(facts,type_graph):
    """Resolve aliases solely from compiler-owned TypedefDecl records.

    Signature comparison deliberately strips AST-local declaration IDs. When
    that loses the ability to disambiguate a shadowed alias, reject rather than
    resolving it from a name found in a header or an external type dictionary.
    """
    from copy import deepcopy
    aliases={}
    for row in type_graph:
        node=row['node']
        if node.get('kind') in ('TypedefDecl','TypeAliasDecl'):
            aliases.setdefault(node.get('name'),[]).append(node.get('type',{}))
    keywords={'void','signed','unsigned','char','short','int','long','const'}
    def expand(facts,stack=()):
        text=facts.get('desugaredQualType',facts.get('qualType',''))
        if not isinstance(text,str) or len(text)>1024 or len(stack)>16:raise ValueError('API_TYPE_RESOLUTION_BUDGET_EXCEEDED')
        words=re.findall(r'[A-Za-z_][A-Za-z0-9_]*|\*|\S',text)
        out=[]
        for word in words:
            if word in keywords or word=='*':out.append(word);continue
            definitions=aliases.get(word,[])
            if not IDENT.fullmatch(word) or len(definitions)!=1 or word in stack:
                raise ValueError('API_COMPILER_TYPE_ALIAS_NOT_UNIQUE_OR_UNSUPPORTED:'+word)
            out.append(expand(definitions[0],(*stack,word)))
        return ' '.join(out)
    result=deepcopy(facts);type_spelling=facts['type']['qualType']
    if type_spelling.count('(')!=1:raise ValueError('API_FUNCTION_PROTOTYPE_REQUIRED')
    result['type']={'qualType':expand({'qualType':type_spelling.split('(',1)[0]})+' (resolved)'}
    result['parameters']=[{'qualType':expand(p)} for p in facts['parameters']]
    return result


def compatible(source,candidate,source_model,target_model):
    left=signature(source,source_model);right=signature(candidate,target_model)
    attributes={'source':left.pop('declarationAttributes'),'target':right.pop('declarationAttributes')}
    if left!=right:raise ValueError('API_SOURCE_TARGET_SIGNATURE_LAYOUT_MISMATCH')
    left['declarationAttributes']=attributes
    return left


def integer(value,typ):
    bits=typ['bits'];low=-(1<<(bits-1)) if typ['signed'] else 0
    high=(1<<(bits-int(typ['signed'])))-1
    if type(value) is not int or not low<=value<=high:raise ValueError('API_INTEGER_OUT_OF_RANGE')
    return value


def expression(node,arguments,objects,*,depth=0):
    if depth>16:raise ValueError('API_PRECONDITION_DEPTH_EXCEEDED')
    if not isinstance(node,dict) or len(node)!=1:raise ValueError('API_PRECONDITION_INVALID')
    op,value=next(iter(node.items()))
    if op=='constant':
        if type(value) is not int or abs(value)>2**63:raise ValueError('API_PRECONDITION_CONSTANT_INVALID')
        return value
    if op in ('argument','remainingElements'):
        if type(value) is not int or not 0<=value<len(arguments):raise ValueError('API_PRECONDITION_PARAMETER_INVALID')
        arg=arguments[value]
        if op=='argument':
            if set(arg)!={'integer'}:raise ValueError('API_PRECONDITION_INTEGER_REQUIRED')
            return arg['integer']
        if set(arg)!={'object','offsetElements'}:raise ValueError('API_PRECONDITION_POINTER_REQUIRED')
        return len(objects[arg['object']]['values'])-arg['offsetElements']
    if op in ('sameObject','disjoint','aligned'):
        arity=4 if op=='disjoint' else 2
        if not isinstance(value,list) or len(value)!=arity:raise ValueError('API_POINTER_PREDICATE_ARITY_INVALID')
        def pointer(index):
            if type(index) is not int or not 0<=index<len(arguments) or set(arguments[index])!={'object','offsetElements'}:
                raise ValueError('API_POINTER_PREDICATE_PARAMETER_INVALID')
            return arguments[index]
        a=pointer(value[0])
        if op=='aligned':
            alignment=value[1];obj=objects[a['object']]
            if type(alignment) is not int or not 1<=alignment<=4096 or alignment&(alignment-1):
                raise ValueError('API_POINTER_ALIGNMENT_INVALID')
            return obj['alignment']%alignment==0 and (a['offsetElements']*(obj['type']['bits']//8))%alignment==0
        b=pointer(value[1])
        if op=='sameObject':return a['object']==b['object']
        lengths=[expression(v,arguments,objects,depth=depth+1) for v in value[2:]]
        for arg,length in zip((a,b),lengths):
            if type(length) is not int or not 0<=length<=len(objects[arg['object']]['values'])-arg['offsetElements']:
                raise ValueError('API_POINTER_SPAN_OUTSIDE_OBJECT')
        return (a['object']!=b['object'] or a['offsetElements']+lengths[0]<=b['offsetElements']
                or b['offsetElements']+lengths[1]<=a['offsetElements'])
    if op not in ('add','multiply','eq','ne','lt','le','gt','ge') or not isinstance(value,list) or len(value)!=2:
        raise ValueError('API_PRECONDITION_OPERATOR_UNSUPPORTED')
    a,b=[expression(n,arguments,objects,depth=depth+1) for n in value]
    if type(a) is not int or type(b) is not int:raise ValueError('API_PRECONDITION_INTEGER_OPERANDS_REQUIRED')
    result={'add':lambda:a+b,'multiply':lambda:a*b,'eq':lambda:a==b,'ne':lambda:a!=b,
            'lt':lambda:a<b,'le':lambda:a<=b,'gt':lambda:a>b,'ge':lambda:a>=b}[op]()
    if type(result) is int and abs(result)>2**127:raise ValueError('API_PRECONDITION_ARITHMETIC_BUDGET_EXCEEDED')
    return result


def validate(domain,interface):
    fields(domain,('schemaVersion','cases','preconditions','claimScope'),'API_DOMAIN')
    if (domain['schemaVersion']!=SCHEMA or domain['claimScope']!='bounded-api-under-declared-preconditions'
            or not isinstance(domain['cases'],list) or not 1<=len(domain['cases'])<=256
            or not isinstance(domain['preconditions'],list) or len(domain['preconditions'])>64):
        raise ValueError('API_DOMAIN_INVALID')
    budget=[0];pending=list(domain['preconditions'])
    while pending:
        node=pending.pop();budget[0]+=1
        if budget[0]>1024:raise ValueError('API_PRECONDITION_NODE_BUDGET_EXCEEDED')
        if isinstance(node,dict):
            for value in node.values():
                if isinstance(value,list):pending.extend(value)
    cases=[];all_elements=0
    for case in domain['cases']:
        fields(case,('arguments','objects'),'API_CASE')
        if not isinstance(case['objects'],list) or len(case['objects'])>32:raise ValueError('API_OBJECT_BUDGET_EXCEEDED')
        objects={};total=0
        for obj in case['objects']:
            fields(obj,('id','type','alignment','values'),'API_OBJECT')
            name=obj['id']
            if not isinstance(name,str) or not IDENT.fullmatch(name) or name in objects:raise ValueError('API_OBJECT_ID_INVALID')
            typ=ctype({'qualType':obj['type']},{'__CHAR_BIT__':'8','__SIZEOF_POINTER__':'8',
                '__SIZEOF_SHORT__':'2','__SIZEOF_INT__':'4','__SIZEOF_LONG__':'8','__SIZEOF_LONG_LONG__':'8'})
            if typ['kind']!='integer':raise ValueError('API_SCALAR_ARRAY_REQUIRED')
            alignment=obj['alignment'];values=obj['values']
            if (type(alignment) is not int or alignment<typ['bits']//8 or alignment>4096
                    or alignment&(alignment-1) or not isinstance(values,list) or not values):
                raise ValueError('API_OBJECT_LAYOUT_INVALID')
            total+=len(values);all_elements+=len(values)
            if total>MAX_ELEMENTS or all_elements>MAX_ELEMENTS:raise ValueError('API_OBJECT_ELEMENT_BUDGET_EXCEEDED')
            for n in values:integer(n,typ)
            objects[name]={'type':typ,'alignment':alignment,'values':values}
        args=case['arguments']
        if not isinstance(args,list) or len(args)!=len(interface['parameters']):raise ValueError('API_ARGUMENT_ARITY_MISMATCH')
        for arg,typ in zip(args,interface['parameters']):
            if typ['kind']=='integer':
                fields(arg,('integer',),'API_INTEGER_ARGUMENT');integer(arg['integer'],typ)
            else:
                fields(arg,('object','offsetElements'),'API_POINTER_ARGUMENT')
                obj=objects.get(arg['object']);offset=arg['offsetElements']
                if (obj is None or obj['type']['elementType']!=typ['elementType']
                        or type(offset) is not int or not 0<=offset<len(obj['values'])):
                    raise ValueError('API_POINTER_OBJECT_TYPE_OR_BOUNDS_INVALID')
        for condition in domain['preconditions']:
            if expression(condition,args,objects) is not True:raise ValueError('API_DECLARED_PRECONDITION_NOT_SATISFIED')
        cases.append({'arguments':args,'objects':objects})
    return cases


def literal(value,typ):
    integer(value,typ)
    # Avoid the C grammar/overflow corner of spelling INT64_MIN as unary minus
    # applied to an out-of-range signed literal.
    if value<0:return f'(({typ["elementType"]})(-{-(value+1)}LL - 1LL))'
    return f'(({typ["elementType"]}){value}ULL)'


def harness(name,interface,domain):
    if not isinstance(name,str) or not IDENT.fullmatch(name):raise ValueError('API_C_LINKER_IDENTIFIER_REQUIRED')
    cases=validate(domain,interface)
    result=interface['return'];ret=result['cType'];parameters=interface['parameters']
    prototype=', '.join(t['cType'] for t in parameters) or 'void'
    lines=['#include <stdio.h>',f'extern {ret} {name}({prototype});','int main(void) {']
    for index,case in enumerate(cases):
        lines.append('{')
        names={name:f'obj_{i}' for i,name in enumerate(case['objects'])}
        for oid,obj in case['objects'].items():
            values=','.join(literal(n,obj['type']) for n in obj['values'])
            lines.append(f'_Alignas({obj["alignment"]}) {obj["type"]["cType"]} {names[oid]}[{len(obj["values"])}] = {{{values}}};')
        args=[literal(a['integer'],t) if t['kind']=='integer' else f'&{names[a["object"]]}[{a["offsetElements"]}]'
              for a,t in zip(case['arguments'],parameters)]
        call=f'{name}('+','.join(args)+')'
        if result['kind']=='void':lines.append(call+';')
        else:lines.append(f'{ret} result = {call}; printf("case:{index}:return:%llu\\n",(unsigned long long)result);')
        for i,(oid,obj) in enumerate(case['objects'].items()):
            # Print typed integer values, not padding or host-endian encodings.
            lines.append(f'for(unsigned long j=0;j<{len(obj["values"])};j++) printf("case:{index}:object:{i}:%lu:%llu\\n",j,(unsigned long long){names[oid]}[j]);')
        lines.append(f'puts("case:{index}:complete:1");')
        lines.append('}')
    lines.extend(['return 0;','}'])
    text='\n'.join(lines)+'\n'
    return text,{'interfaceIdentity':identity(interface),'domainIdentity':identity(domain),
        'initializedScalarArraysConstructed':True,'pointerOffsetsWithinAllocatedObjects':True,
        'aliasingBySharedObjectIdentity':True,'callLifetimeEnforcedByHarness':True,
        'calleePreconditions':'declared-not-inferred','calleeAllAccessesProvedLegal':False,
        'scope':'bounded-api-under-declared-preconditions'}


def declaration_witness(name,interface):
    if not IDENT.fullmatch(name):raise ValueError('API_C_LINKER_IDENTIFIER_REQUIRED')
    params=', '.join(p['cType'] for p in interface['parameters']) or 'void'
    return ('\n_Static_assert(__builtin_types_compatible_p(__typeof__(&'+name+'), '+
            interface['return']['cType']+' (*)('+params+')), "native API declaration mismatch");\n')


def abi_layout(interface,profile):
    """Standard fixed scalar INTEGER-class slots; no aggregate/FP/variadic ABI.

    This is a required layout, not proof that arbitrary machine code preserves
    registers or obeys it. Narrow AMD64 upper bits deliberately remain unknown.
    """
    if profile=='sysv_amd64':regs=['rdi','rsi','rdx','rcx','r8','r9'];base=8;ret='rax'
    elif profile in ('riscv_lp64','riscv_lp64f','riscv_lp64d'):regs=['a'+str(i) for i in range(8)];base=0;ret='a0'
    else:raise ValueError('API_ABI_PROFILE_UNSUPPORTED')
    slots=[]
    for i,typ in enumerate(interface['parameters']):
        slots.append({'parameterIndex':i,'type':typ,
            'location':{'register':regs[i]} if i<len(regs) else {'entryStackOffset':base+8*(i-len(regs))},
            'carrierBits':64,'valueBits':64 if typ['kind']=='pointer' else typ['bits'],
            'upperBits':'not-claimed' if profile=='sysv_amd64' else 'riscv-integer-extension-rule'})
    return {'profile':profile,'parameters':slots,'stackAlignmentBytes':16,
        'entryStackResidue':8 if profile=='sysv_amd64' else 0,
        'returnRegister':None if interface['return']['kind']=='void' else ret,
        'machineCalleeSavedPreservationVerified':False,'machineAbiClosureVerified':False}


def output_protocol(raw,interface,domain):
    """Require every planned case/result/object element, not two empty logs."""
    cases=validate(domain,interface);labels=[]
    for index,case in enumerate(cases):
        if interface['return']['kind']!='void':labels.append(f'case:{index}:return:')
        for i,(_,obj) in enumerate(case['objects'].items()):
            labels.extend(f'case:{index}:object:{i}:{j}:' for j in range(len(obj['values'])))
    # Void/no-object calls still need an explicit completion witness per case.
    # The generated harness always emits this record after all observations.
    expected=[]
    for index,case in enumerate(cases):
        prefix=[x for x in labels if x.startswith(f'case:{index}:')]
        expected.extend(prefix);expected.append(f'case:{index}:complete:')
    try:lines=raw.decode('ascii').splitlines()
    except UnicodeDecodeError:return False
    if len(lines)!=len(expected):return False
    for line,label in zip(lines,expected):
        if not line.startswith(label):return False
        value=line[len(label):]
        if (not value or not value.isascii() or not value.isdecimal() or len(value)>20
                or str(int(value))!=value or int(value)>2**64-1
                or (label.endswith('complete:') and value!='1')):return False
    return True
