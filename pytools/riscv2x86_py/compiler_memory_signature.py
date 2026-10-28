"""LP64 scalar/pointer call facts from compiler-resolved declaration types.

These facts describe types, not permission to invoke a function or semantic approval.
Each consumer must bind its own objects, expressions and observable shell.
"""
from .compiler_value_flow import identity

SCHEMA = 'riscv2x86.compiler-memory-call.v1'
UNSIGNED = {'unsigned char':8, 'unsigned short':16, 'unsigned short int':16,
            'unsigned':32, 'unsigned int':32, 'unsigned long':64,
            'unsigned long int':64, 'unsigned long long':64, 'unsigned long long int':64}
SIGNED = {'signed char':8, 'short':16, 'short int':16, 'signed short':16,
          'signed short int':16, 'int':32, 'signed':32, 'signed int':32,
          'long':64, 'long int':64, 'signed long':64, 'signed long int':64,
          'long long':64, 'long long int':64, 'signed long long':64, 'signed long long int':64}


def type_fact(text):
    text=' '.join(text.split())
    if text=='void':return {'kind':'void','cType':'void'}
    if text.endswith('*'):
        pointee_text=text[:-1].strip()
        qualifiers=[]
        while pointee_text.startswith('const '):
            qualifiers.append('const');pointee_text=pointee_text[6:]
        if len(qualifiers)>1:return None
        pointee=type_fact(pointee_text)
        if pointee is None or pointee['kind']!='integer':return None
        return dict({'kind':'pointer','cType':text,'widthBits':64,'pointee':pointee},**({'pointeeQualifiers':qualifiers} if qualifiers else {}))
    width=UNSIGNED.get(text) or SIGNED.get(text)
    if width is None:return None
    return {'kind':'integer','cType':text,'widthBits':width,'signed':text in SIGNED}


def export(function, parameters, result, resolve):
    facts=[type_fact(resolve(t)) for t in parameters+[result]]
    if any(t is None for t in facts) or any(t['kind']=='void' for t in facts[:-1]):return None
    declarations=function['l2OperandBoundary']['parameterDeclarationIds']
    if len(declarations)!=len(parameters) or len(set(declarations))!=len(declarations):return None
    body={'schemaVersion':SCHEMA,'functionIdentity':function['functionId'],
        'sourceDigest':function['sourceDigest'],'targetABI':'linux-lp64',
        'parameters':[dict(t,declarationIdentity=d) for t,d in zip(facts,declarations)],
        'result':facts[-1]}
    return dict(body,factsIdentity=identity(body))
