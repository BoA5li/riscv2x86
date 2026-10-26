"""Bounded fence refinement, not a C seq_cst or concurrency proof.

R/W pairs refer only to ordinary coherent memory. Compiler ordering is an
independent obligation. Unknown kinds, I/O domains and scope conversions reject.
"""
from .l3_trace_support import identity

DOMAIN = 'ordinary-coherent-memory'
RW_PAIRS = (('R', 'R'), ('R', 'W'), ('W', 'R'), ('W', 'W'))
C_ORDERS = {'relaxed', 'consume', 'acquire', 'release', 'acq_rel', 'seq_cst'}


def ordering_covers(source, target):
    if source == 'rw_rw' or target == 'rw_rw':
        # No conversion from an ISA fence to a C abstract order is inferred.
        return source == target == 'rw_rw'
    return target in {
        'relaxed': C_ORDERS,
        'consume': {'consume', 'acquire', 'acq_rel', 'seq_cst'},
        'acquire': {'acquire', 'acq_rel', 'seq_cst'},
        'release': {'release', 'acq_rel', 'seq_cst'},
        'acq_rel': {'acq_rel', 'seq_cst'}, 'seq_cst': {'seq_cst'},
    }.get(source, set())


def scope_covers(source, target, *, source_hardware=False):
    if source not in {'compiler', 'thread', 'system'} or target not in {'compiler', 'thread', 'system'}:
        return False
    # Only registered scope inclusion, never a generic numeric rank.
    return source == target or (not source_hardware and source == 'compiler' and target == 'system')


def refinement(source, target):
    """Tuples: compiler, hardware, ordering, scope; None means unproved."""
    sc, sh, so, ss = source; tc, th, to, ts = target
    if any(type(v) is not bool for v in (sc, sh, tc, th)):
        return None
    if not (sc or sh) or not (tc or th) or (sh and ss == 'compiler') or (th and ts == 'compiler'):
        return None
    if (sc and not tc) or (sh and not th) or not ordering_covers(so, to):
        return None
    if so == 'rw_rw' and (not sh or not th or ss != 'system' or ts != 'system'):
        return None
    if not scope_covers(ss, ts, source_hardware=sh):
        return None
    return 'exact' if source == target else 'strengthened'


def describe(compiler, hardware, ordering, scope):
    if refinement((compiler, hardware, ordering, scope), (compiler, hardware, ordering, scope)) is None:
        raise ValueError('FENCE_SEMANTIC_DOMAIN_INVALID')
    body = {'schemaVersion': 'riscv2x86.fence-ordering-domain.v1',
            'kind': 'isa-rw-fence' if ordering == 'rw_rw' else 'abstract-memory-order',
            'compilerOrdering': compiler, 'hardwareOrdering': hardware,
            'ordering': ordering, 'scope': scope,
            'memoryDomain': DOMAIN if hardware else 'compiler-only',
            'predecessors': ['R','W'] if ordering == 'rw_rw' else [],
            'successors': ['R','W'] if ordering == 'rw_rw' else [],
            'orderedPairs': [list(p) for p in RW_PAIRS] if ordering == 'rw_rw' else [],
            'globalSequentialConsistencyClaimed': False}
    return dict(body, domainIdentity=identity(body))
