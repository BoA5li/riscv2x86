"""Versioned coverage expectations, independent of seed names or observed success.

This catalog describes implementation scope. Only proof/call/observer validators
can establish membership; this file never grants translation or L3 approval.
"""
from pathlib import Path
from .l3_trace_support import identity,digest

BASELINE = '99b5f2fe80551828ddd3a3369b8d730ea1437d97'


def catalog():
    axes = [
        ('mixed-mechanisms','M1','partial','l3_joint_spec.py','load/scalar/store and ordinary rw/rw fence; no control/atomic combination'),
        ('program-regions','M1','partial','compiler_joint_scope.py','direct acyclic regions; no dynamic CFG or calls'),
        ('typed-invocation','M1','partial','compiler_memory_signature.py','joint: 1-4 parameters; unsigned64 scalar carriers and return; typed object pointers with explicit invocation layouts'),
        ('multiple-accesses-and-objects','M2','partial','l3_joint_spec.py','multiple typed views and explicit separated/same-address/overlap layouts; one proved access per memory region; general multi-effect asm pending'),
        ('ordinary-load-extension','M2','partial','memory_contracts.py','single-access typed load and joint 8/16/32/64 accesses; approved sign/zero extension to uint64 carrier'),
        ('general-store-values','M2','partial','l3_memory_call.py','typed isolated stores; joint low-bit stores into signed/unsigned integer objects; signed scalar expressions pending'),
        ('memory-control','M5','pending','l3_control_spec.py','no joint memory/control or bounded-loop route'),
        ('memory-fence','M3','partial','l3_fence_spec.py','joint ordinary rw/rw single-instruction fence with actual same-invocation access sequence; other fence domains pending'),
        ('atomic-address-invocation','M4','partial','l3_atomic_spec.py','isolated bounded atomic contract; general address and joint route pending'),
        ('atomic-family-lrsc-live-output','M4','partial','l2_lrsc_authority.py','existing operation families only; active auxiliary output observation pending'),
        ('whole-program-audit','M1','partial','l3_joint_route.py','joint closed members and persisted L2 replay; general mixed CFG audit pending'),
        ('visibility-environment','M7','pending','l3_sync_obligations.py','environment-specific L3 automatic execution route pending'),
    ]
    files={p:digest(Path(__file__).with_name(p)) for p in {row[3] for row in axes}}
    body={'implementationIdentity':identity(files),'implementationFiles':files,'schemaVersion':'riscv2x86.l3-supported-domain.v1','baselineCommit':BASELINE,
        'scope':'implementation-expectations; not source membership or runtime acceptance',
        'axes':[dict(axisId=a,milestone=m,implementationStatus=s,implementationAnchor=p,limitations=l)
                for a,m,s,p,l in axes],
        'jointDomain':{'domainId':'direct-typed-object-view-regions.v2',
            'membershipValidator':'l3_joint_spec.spec','observationContract':'l2_joint_contract.providers',
            'parameters':[1,4],'regions':[2,16],'accessWidthBits':[8,16,32,64],
            'preconditions':['compiler-bound declarations and direct return','complete member proofs and dependency graph',
                'valid private object layout; aliases only from explicit compatible typed views','defined scalar inputs','no C initializer, call, loop, control or atomic; only approved ordinary rw/rw fences'],
            'requiredStages':['proof','invocation','composition','provider-resolution','backend-validation','deployment','execution','comparison','independent-audit']},
        'semanticApproval':False,'productionAcceptanceComplete':False}
    return dict(body,catalogIdentity=identity(body))
