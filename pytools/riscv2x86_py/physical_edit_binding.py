"""An additive projection from checked compiler ranges to frozen CPP storage.

Presumed diagnostic paths and compiler-exported facts are never rewritten.
This projection authorizes only the isolated byte-identical translation unit;
it cannot authorize changing an original header or macro definition.
"""
from copy import deepcopy
from pathlib import Path
from .project_build_records import identity

SCHEMA='riscv2x86.frozen-physical-edit-binding.v1'


def project(report,bindings,source,prepared_path):
    from . import native_captured_deployment as d
    result=deepcopy(report);by_range={tuple(r['physicalStatementRange']):r for r in bindings['records']}
    for index,f in enumerate(result['findings']):
        if f.get('subjectKind')!='AsmFragment':continue
        key=(f.get('rewriteBeginOffset'),f.get('rewriteEndOffset'))
        row=by_range.get(key)
        if row is None or 'physicalEditBinding' in f:raise ValueError('PHYSICAL_EDIT_COMPILER_RANGE_REQUIRED')
        body={'schemaVersion':SCHEMA,'preparedInputPath':str(Path(prepared_path).resolve()),
            'source':d.snapshot(source),'findingIndex':index,
            'instanceBindingIdentity':row['instanceBindingIdentity'],
            'physicalRange':list(key),'statementDigest':row['statementDigest'],
            'diagnosticFile':f['fileName'],'fragmentId':f['fragment']['id'],
            'artifactDomain':'frozen-preprocessed-translation-unit','originalSourceEditAuthorized':False}
        f['physicalEditBinding']=dict(body,physicalEditBindingIdentity=identity(body))
    return result


def source_path(finding,root):
    from . import native_captured_deployment as d
    from .native_original_pipeline import check_input
    from .schema import load_report
    b=finding.physicalEditBinding
    if (not isinstance(b,dict) or b.get('schemaVersion')!=SCHEMA
            or b.get('physicalEditBindingIdentity')!=identity({k:v for k,v in b.items() if k!='physicalEditBindingIdentity'})):
        raise ValueError('PHYSICAL_EDIT_BINDING_INVALID')
    prepared=check_input(b['preparedInputPath'])
    index=b['findingIndex']
    if type(index) is not int or index<0:raise ValueError('PHYSICAL_EDIT_FINDING_INDEX_INVALID')
    originals=load_report(prepared['frontendReport']['path'])
    if index>=len(originals):raise ValueError('PHYSICAL_EDIT_FINDING_INDEX_INVALID')
    original=originals[index]
    if b!=original.physicalEditBinding or b['source']!=prepared['source']:
        raise ValueError('PHYSICAL_EDIT_BINDING_NOT_DERIVED_FROM_COMPILER')
    for key in ('fileName','line','column','rawSourceText','rewriteBeginOffset','rewriteEndOffset','hasRewriteRange','fromMacroExpansion','macroName'):
        if getattr(finding,key)!=getattr(original,key):raise ValueError('PHYSICAL_EDIT_FINDING_SOURCE_CHANGED:'+key)
    if finding.fragment is None or original.fragment is None:raise ValueError('PHYSICAL_EDIT_FRAGMENT_REQUIRED')
    for key in ('kind','id','fileName','rawAsmText','outputs','inputs','clobbers','gotoLabels',
                'isVolatile','beginOffset','endOffset','astBeginOffset','astEndOffset'):
        if getattr(finding.fragment,key)!=getattr(original.fragment,key):
            raise ValueError('PHYSICAL_EDIT_FRAGMENT_SOURCE_CHANGED:'+key)
    path=Path(b['source']['path']).resolve();d.verify_snapshot(b['source'])
    if path.parent!=Path(root).resolve():raise ValueError('PHYSICAL_EDIT_SOURCE_ROOT_MISMATCH')
    start,stop=b['physicalRange']
    from .compiler_native_instance_binding import bytes_identity
    raw=path.read_bytes()
    if (type(start) is not int or type(stop) is not int or not 0<=start<stop<=len(raw)
            or bytes_identity(raw[start:stop])!=b['statementDigest']
            or raw[start:stop]!=finding.rawSourceText.encode()):raise ValueError('PHYSICAL_EDIT_SOURCE_BYTES_MISMATCH')
    return path


def validate_report(prepared,report_path):
    from .schema import load_report
    expected=load_report(prepared['frontendReport']['path'])
    actual=load_report(str(report_path))
    if len(actual)!=len(expected):raise ValueError('PHYSICAL_EDIT_REPORT_COVERAGE_MISMATCH')
    for a,b in zip(actual,expected):
        if b.subjectKind!='AsmFragment':
            if a.physicalEditBinding or a.fileName!=b.fileName or a.rawSourceText!=b.rawSourceText:
                raise ValueError('PHYSICAL_EDIT_UNSUPPORTED_FINDING_PROJECTION')
            continue
        if not a.physicalEditBinding or a.physicalEditBinding!=b.physicalEditBinding:
            raise ValueError('PHYSICAL_EDIT_REPORT_BINDING_MISMATCH')
        source_path(a,Path(prepared['source']['path']).parent)
