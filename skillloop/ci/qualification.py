"""Blocking outcomes for a qualification check after evidence verification.

Experiment transport checks retain their separate, historical semantics.
This mapping establishes neither evidence validity nor branch protection.
"""
_OUTCOMES = {'pass': (0, 'success'), 'fail': (1, 'failure'),
             'inconclusive': (3, 'failure'), 'needs_contract': (4, 'action_required')}

def qualification_outcome(verdict):
    if not isinstance(verdict, str) or verdict not in _OUTCOMES:
        raise ValueError('unsupported_qualification_verdict')
    code, conclusion = _OUTCOMES[verdict]
    return {'exit_code': code, 'conclusion': conclusion}
