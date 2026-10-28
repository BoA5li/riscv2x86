"""Select a compiler-bound entry, not the only function in a translation unit.

This grants no call-graph permission. The consuming route must still prove its
existing no-other-effects shell and exact deployed code/artifact relationship.
"""

def entry(functions,function_id):
    if not isinstance(function_id,str) or not function_id:
        raise ValueError('L3_COMPILER_ENTRY_IDENTITY_REQUIRED')
    matches=[f for f in functions if isinstance(f,dict) and f.get('functionId')==function_id]
    if len(matches)!=1:raise ValueError('L3_COMPILER_ENTRY_IDENTITY_AMBIGUOUS')
    return matches[0]
