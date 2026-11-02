"""One switch for Phase134 cost changes, never an acceptance predicate."""
import os


def enabled():
    mode=os.environ.get('RV2X86_JOINT_PERFORMANCE_V2','1')
    if mode not in {'0','1'}:raise ValueError('JOINT_PERFORMANCE_V2_MODE_INVALID')
    return mode=='1'
