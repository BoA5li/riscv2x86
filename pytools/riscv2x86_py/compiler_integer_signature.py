"""LP64 integer ABI facts from the compiler AST and resolved typedef graph."""
from .compiler_value_flow import identity


def export(function, parameters, result, resolve):
    # Only builtin LP64 integer types after compiler typedef resolution. This
    # table states an explicit ABI domain, not a whitelist of user typedefs.
    domain={'long':True,'long int':True,'signed long':True,'signed long int':True,
            'long long':True,'long long int':True,'signed long long':True,
            'unsigned long':False,'unsigned long int':False,
            'unsigned long long':False,'unsigned long long int':False}
    types=[resolve(t) for t in parameters+[result]]
    if not 1<=len(parameters)<=4 or any(t not in domain for t in types):return None
    decls=function['l2OperandBoundary']['parameterDeclarationIds']
    if len(decls)!=len(parameters) or any(not d for d in decls):return None
    def item(typ,decl):
        return {'declarationIdentity':decl,'typeIdentity':identity({'schemaVersion':'riscv2x86.compiler-c-type.v1',
            'canonicalType':typ,'widthBits':64,'alignmentBytes':8}),
            'widthBits':64,'signed':domain[typ],'cType':typ}
    body={'schemaVersion':'riscv2x86.compiler-integer-call-signature.v1',
          'functionIdentity':function['functionId'],'sourceDigest':function['sourceDigest'],
          'targetABI':'linux-lp64-integer64','parameters':[item(t,d) for t,d in zip(types,decls)],
          'result':item(types[-1],identity({'functionIdentity':function['functionId'],'role':'return-type'}))}
    return dict(body,factsIdentity=identity(body))
