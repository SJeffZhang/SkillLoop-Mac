"""Blocking outcomes for a qualification check after evidence verification.

Experiment transport checks retain their separate, historical semantics.
This mapping establishes neither evidence validity nor branch protection.
"""
from .decision import CODES

_CONCLUSIONS = {'pass': 'success', 'fail': 'failure',
                'inconclusive': 'failure', 'needs_contract': 'action_required'}

def qualification_outcome(verdict):
    if not isinstance(verdict, str) or verdict not in _CONCLUSIONS:
        raise ValueError('unsupported_qualification_verdict')
    return {'exit_code': CODES[verdict], 'conclusion': _CONCLUSIONS[verdict]}

def publish_qualification(app, registry, *, pr, check_id, head_sha,
                          config_digest, generation, campaign, decision, summary):
    """Publish a trusted caller's verified decision under exact identity fences.

    Caller derives the decision from raw/API4 verification and current original
    attestation consumption. This transport cannot authenticate evidence itself.
    Branch protection configuration remains a separate acceptance requirement.
    """
    from .github_app import check_identity
    outcome = qualification_outcome(decision['verdict'])
    identity = check_identity(app.repository, pr, head_sha, config_digest, generation)
    project = app.repository + '#' + str(pr)
    def fence(expected_status, expected_conclusion=None):
        if app.request('/pulls/' + str(pr))['head']['sha'] != head_sha:
            raise ValueError('stale_head')
        check = app.request('/check-runs/' + str(check_id))
        if (check['head_sha'] != head_sha or check.get('external_id') != identity
                or check.get('name') != 'SkillLoop qualification'
                or check.get('status') != expected_status
                or (expected_conclusion is not None and check.get('conclusion') != expected_conclusion)
                or check['app']['id'] != app.app_id):
            raise ValueError('check_identity_mismatch')
        registry.verify_current(project, head_sha, config_digest, generation, campaign, decision)
    fence('in_progress')
    fence('in_progress')
    result = app.request('/check-runs/' + str(check_id), 'PATCH', {
        'status': 'completed', 'conclusion': outcome['conclusion'],
        'output': {'title': 'Qualification decision: ' + decision['verdict'],
                   'summary': summary}})
    fence('completed', outcome['conclusion'])
    if result.get('conclusion') != outcome['conclusion'] or result.get('status') != 'completed':
        raise ValueError('check_completion_mismatch')
    # The local receipt follows an independently observed completed Check. A
    # lost PATCH reply leaves the original remote write unknown and is handled
    # by read-only inspection, never by an automatic second PATCH.
    registry.complete(project, head_sha, config_digest, generation, campaign, decision)
    return result
