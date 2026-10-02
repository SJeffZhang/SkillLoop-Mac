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

def publish_qualification(app, registry, *, pr, check_id, head_sha,
                          config_digest, generation, campaign, decision, summary):
    """Publish a trusted caller's verified decision under exact identity fences.

    Caller derives the decision from raw/API4 verification and current original
    attestation consumption. This transport cannot authenticate evidence itself.
    Branch protection configuration remains a separate acceptance requirement.
    """
    from .github_app import check_identity
    outcome = qualification_outcome(decision['verdict'])
    identity = check_identity(app.repository, pr, head_sha, config_digest)
    project = app.repository + '#' + str(pr)
    def fence():
        if app.request('/pulls/' + str(pr))['head']['sha'] != head_sha:
            raise ValueError('stale_head')
        check = app.request('/check-runs/' + str(check_id))
        if (check['head_sha'] != head_sha or check.get('external_id') != identity
                or check['app']['id'] != app.app_id):
            raise ValueError('check_identity_mismatch')
        registry.complete(project, head_sha, config_digest, generation, campaign, decision)
    fence()
    fence()
    result = app.request('/check-runs/' + str(check_id), 'PATCH', {
        'status': 'completed', 'conclusion': outcome['conclusion'],
        'output': {'title': 'Qualification decision: ' + decision['verdict'],
                   'summary': summary}})
    fence()
    if result.get('conclusion') != outcome['conclusion'] or result.get('status') != 'completed':
        raise ValueError('check_completion_mismatch')
    return result
