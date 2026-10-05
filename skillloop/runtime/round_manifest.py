"""Admin-owned whole-round admission; a phase digest alone is insufficient."""
import re

from skillloop.protocol import digest_jcs
from skillloop.repair.budget import LIMITS


STAGES = {'approval_deployment', 'import_scan', 'development', 'repair_pairing',
          'private_factory_lifecycle', 'protected', 'gate_qualification_report',
          'github_lifecycle', 'resource_archive_restore'}


def read_round_manifest(path):
    from skillloop.discovery.formal_task_gate import read_owned
    value = read_owned(path, uid=21010, gid=21001, limit=8388608)
    validate_round_manifest(value)
    return value


def validate_round_manifest(value):
    required = {'kind','source_digest','image','deployment_epoch','campaigns','digest'}
    if (type(value) is not dict or set(value) != required
            or value['kind'] != 'FrozenWholeRound'
            or value['digest'] != digest_jcs({k:v for k,v in value.items() if k != 'digest'})
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', value['source_digest'])
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', value['image'])
            or type(value['deployment_epoch']) is not str or not value['deployment_epoch']):
        raise ValueError('whole_round_manifest_identity')
    campaigns = value['campaigns']
    if type(campaigns) is not list or len(campaigns) != 3:
        raise ValueError('whole_round_three_serial_campaigns_required')
    profiles = set(); identities = set()
    for campaign in campaigns:
        if (type(campaign) is not dict or set(campaign) !=
                {'campaign_digest','profile','victim_seconds','reserved_victim_attempts',
                 'reserved_input_tokens','reserved_output_tokens','reserved_disk_bytes',
                 'phase_reservations','phase_epochs','stages','terminal_seconds'}):
            raise ValueError('whole_round_campaign_budget_shape')
        identity = campaign['campaign_digest']; profile = campaign['profile']
        if (type(identity) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}', identity)
                or identity in identities or profile in profiles
                or profile not in {'orders_total','refunds_total','markdown_index'}):
            raise ValueError('whole_round_campaign_scope')
        identities.add(identity); profiles.add(profile)
        epochs=campaign['phase_epochs']
        if (type(epochs) is not dict or set(epochs)!={'dev','protected'}
                or any(type(e) is not str or not 1<=len(e)<=256 for e in epochs.values())
                or any(e!=value['deployment_epoch'] for e in epochs.values())):
            # The Factory creates a new SuiteManifest.epoch_id after finalist
            # freeze. A deployment epoch changes only for a new deployment or
            # restoration; switching it here would invalidate the dev chain's
            # real approvals and credentials rather than isolate the backend.
            raise ValueError('whole_round_same_deployment_separate_factory_epoch_required')
        integers = ('victim_seconds','reserved_victim_attempts','reserved_input_tokens',
                    'reserved_output_tokens','reserved_disk_bytes','terminal_seconds')
        if any(type(campaign[k]) is not int or campaign[k] < 1 for k in integers):
            raise ValueError('whole_round_positive_costs_required')
        if (campaign['reserved_victim_attempts'] > LIMITS['victim_attempts']
                or campaign['reserved_input_tokens'] > LIMITS['input_tokens']
                or campaign['reserved_output_tokens'] > LIMITS['output_tokens']
                or campaign['reserved_disk_bytes'] > LIMITS['disk_bytes']
                or campaign['terminal_seconds'] < 120):
            raise ValueError('whole_round_campaign_budget_exceeded')
        stages = campaign['stages']
        if type(stages) is not dict or set(stages) != STAGES:
            raise ValueError('whole_round_complete_stage_costs_required')
        for cost in stages.values():
            if (type(cost) is not dict or set(cost) != {'count','seconds','input_tokens','output_tokens','disk_bytes'}
                    or type(cost['count']) is not int or cost['count'] < 1
                    or type(cost['seconds']) is not int or cost['seconds'] < 1
                    or any(type(cost[k]) is not int or cost[k]<0 for k in ('input_tokens','output_tokens','disk_bytes'))):
                raise ValueError('whole_round_stage_reserve_required')
        complete = (campaign['reserved_victim_attempts'] * campaign['victim_seconds']
                    + sum(c['count'] * c['seconds'] for c in stages.values())
                    + campaign['terminal_seconds'])
        if complete > LIMITS['wall_seconds']:
            raise ValueError('whole_round_full_cost_exceeds_original_clock')
        # Victim upper bounds include all 16 possible model responses. Token
        # reservations also include generator/patcher and other auxiliary calls.
        victims=campaign['reserved_victim_attempts']
        lower_input=victims*16*14336+sum(c['count']*c['input_tokens'] for c in stages.values())
        lower_output=victims*16*2048+sum(c['count']*c['output_tokens'] for c in stages.values())
        lower_disk=victims*8*1048576+536870912+sum(c['count']*c['disk_bytes'] for c in stages.values())
        if (campaign['reserved_input_tokens']<lower_input or campaign['reserved_output_tokens']<lower_output
                or campaign['reserved_disk_bytes']<lower_disk):
            raise ValueError('whole_round_auxiliary_or_unused_cost_omitted')
        reservations = campaign['phase_reservations']
        if (type(reservations) is not dict or set(reservations) != {'dev','protected'}
                or any(type(v) is not int or v < 120 for v in reservations.values())
                or sum(reservations.values()) > complete):
            raise ValueError('whole_round_phase_budget_allocation')
    return value


def admit_phase(manifest, phase, ledger, epoch):
    campaign = next((c for c in manifest['campaigns']
                     if c['campaign_digest'] == phase['plan']['body']['campaign_id']), None)
    if (campaign is None or manifest['digest'] != phase['whole_round_manifest_digest']
            or phase['phase'] not in {'dev','protected'}
            or campaign['phase_epochs'][phase['phase']] != epoch
            or campaign['victim_seconds'] != ledger.victim_seconds
            or phase['reserved_phase_seconds'] != campaign['phase_reservations'][phase['phase']]
            or any(unit['entry']['source_index_digest'] != manifest['source_digest']
                   or unit['entry']['config']['mac_runtime_image'] != manifest['image']
                   for unit in phase['entries'])):
        raise ValueError('whole_round_phase_not_admitted')
    state=ledger.read()
    if (state.get('campaign_started_at')!=ledger.campaign_started_at
            or state.get('whole_round_binding')!=
                {'manifest_digest':manifest['digest'],'campaign':campaign['campaign_digest']}
            or state.get('whole_round_cost_reservation',{}).get('campaign')!=campaign['campaign_digest']):
        raise ValueError('whole_round_phase_original_campaign_ledger_required')
    return campaign
