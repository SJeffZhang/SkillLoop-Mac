"""GitHub API timeline ingress; does not claim webhook delivery or qualification."""
import re

from skillloop.protocol import digest_jcs


def ingest_force_push(registry, repository, pr, profile, event, current_head, config_digest):
    """Caller fetches the event and current PR head from the scoped App API."""
    if (event.get('event') != 'head_ref_force_pushed'
            or type(event.get('id')) is not int or event['id'] <= 0
            or not re.fullmatch('[0-9a-f]{40}', event.get('commit_id') or '')):
        raise ValueError('invalid_force_push_event')
    if event['commit_id'] != current_head:
        raise ValueError('stale_event_head')
    project = repository + '#' + str(pr) + ':' + profile
    trigger = registry.trigger(project, current_head, config_digest)
    body = {'source': 'github_api_poll', 'event_id': event['id'],
            'event_digest': digest_jcs(event), 'repository': repository, 'pr': pr,
            'profile': profile, 'head_sha': current_head, 'config_digest': config_digest,
            'trigger': trigger, 'qualification_asserted': False}
    return {**body, 'digest': digest_jcs(body)}
