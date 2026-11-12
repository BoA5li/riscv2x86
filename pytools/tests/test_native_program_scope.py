"""Scope conservatism, exact source/candidate roots and finite initializer proofs."""
from copy import deepcopy

import pytest

from .test_native_contract_evidence import fn
from riscv2x86_py.native_contract_evidence import ast_graph
from riscv2x86_py.native_program_scope import local_scope,derive
from riscv2x86_py.native_object_initializers import derive as initializers


def call(id,name):
    return {'kind':'CallExpr','inner':[{'kind':'DeclRefExpr','referencedDecl':
        {'kind':'FunctionDecl','id':id,'name':name,'type':{'qualType':'int (int)'}}}]}


def graph():
    root=fn('arbitrary_root','fn:1',0,30,body=True)
    leaf=fn('leaf','fn:2',40,70,body=True)
    header=fn('unused_header','fn:3',80,120,body=True)
    root['inner'][-1]['inner']=[call('fn:2','leaf')]
    leaf['inner'][-1]['inner']=[call('external:1','external')]
    header['inner'][-1]['inner']=[{'kind':'CallExpr','inner':[
        {'kind':'DeclRefExpr','referencedDecl':{'kind':'ParmVarDecl','id':'fp:1','name':'callback'}}]}]
    ast={'kind':'TranslationUnitDecl','inner':[root,leaf,header,
        {'kind':'VarDecl','id':'obj:1','name':'decl','storageClass':'extern','type':{'qualType':'int'}}]}
    return ast_graph(ast,'actual-fixture-ast')


def test_unvisited_header_callback_is_not_mistaken_for_an_executed_error_or_proved_unreachable():
    g=graph();scope=local_scope(g,[[0]],'explicit-bound-root')
    assert scope['visitedFunctionAstPaths']==[[0],[1]]
    assert scope['unvisitedFunctionAstPaths']==[[2]]
    assert len(scope['terminalCallObligations'])==1
    assert scope['terminalCallObligations'][0]['classification']=='direct'
    assert not scope['unvisitedFunctionsProvedUnreachable'] and not scope['programReachabilityComplete']
    assert scope['objectRoles'][0]['role']=='external-declaration'
    assert not scope['objectRoles'][0]['legalObjectContractVerified']


def test_reached_callback_remains_an_obligation_and_missing_root_is_rejected():
    g=graph();scope=local_scope(g,[[2]],'bound-callback-owner')
    assert scope['terminalCallObligations'][0]['classification']=='unresolved'
    assert 'INDIRECT_TARGET_SET_AND_CALL_CONTRACT_REQUIRED' in scope['terminalCallObligations'][0]['requirements']
    with pytest.raises(ValueError,match='ROOT_MISSING'):local_scope(g,[[999]],'invalid')


def test_candidate_ast_index_is_transported_not_reused_and_pic_difference_is_retained():
    g=graph();candidate=deepcopy(g)
    candidate['functionDefinitions'][0]['astPath']=[9]
    candidate['callSites'][0]['functionAstPath']=[9]
    ctx={'instances':[{'sourceFunctionAstPath':[0],'bridgeInstanceIdentity':'bound-instance'}],
         'candidateTargetArguments':['cc','-O2'],'producerTargetArguments':['cc','-O2','-fPIC']}
    joins=[{'sourceAstPath':[0],'candidateAstPath':[9],'byteLineageDeclarationCorrespondenceVerified':True}]
    scope=derive(ctx,{'source':g,'candidate':candidate},[],joins,{'artifacts':[]})
    assert scope['localScopes']['candidate']['rootAstPaths']==[[9]]
    assert not scope['explicitPICArgumentsEqual'] and not scope['targetContextCompatibilityVerified']
    assert not scope['nativeAbiMachineEvidenceAcquired']


MODEL={'__CHAR_BIT__':'8','__SIZEOF_INT__':'4','__SIZEOF_LONG__':'8','__SIZEOF_LONG_LONG__':'8'}


def test_constant_initializer_reuses_integer_semantics_without_granting_object_legality():
    literal={'kind':'IntegerLiteral','value':'7','type':{'qualType':'int'}}
    ast={'kind':'TranslationUnitDecl','inner':[{'kind':'VarDecl','id':'o:1','name':'value',
        'type':{'qualType':'unsigned long'},'inner':[{'kind':'ImplicitCastExpr','castKind':'IntegralCast',
            'type':{'qualType':'unsigned long'},'inner':[literal]}]}]}
    result=initializers(ast_graph(ast,'fixture'),MODEL)[0]
    assert result['inspectionTypedConstantInitializerVerified'] and result['value']==7
    assert not result['nativeInitializationSemanticsVerified'] and not result['runtimeObjectIdentityVerified']


@pytest.mark.parametrize('initializer',[
    [],[{'kind':'CallExpr','type':{'qualType':'int'},'inner':[]}],
    [{'kind':'DeclRefExpr','type':{'qualType':'int'},'referencedDecl':{'kind':'VarDecl','id':'other'}}],
    [{'kind':'IntegerLiteral','value':str(2**31),'type':{'qualType':'int'}}],
    [{'kind':'IntegerLiteral','value':'1','type':{'qualType':'double'}}]])
def test_missing_runtime_dependent_or_out_of_range_initializers_do_not_prove_values(initializer):
    ast={'kind':'TranslationUnitDecl','inner':[{'kind':'VarDecl','id':'o:1','name':'value',
         'type':{'qualType':'int'},'inner':initializer}]}
    result=initializers(ast_graph(ast,'fixture'),MODEL)[0]
    assert not result['inspectionTypedConstantInitializerVerified'] and result['reasonCodes']
