import tempfile
import unittest
from pathlib import Path

from skillloop.ci.registry import LocalRegistry


class TimelineIngressTests(unittest.TestCase):
    def test_real_event_duplicate_survives_restart(self):
        from skillloop.ci.github_events import ingest_force_push
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'registry.sqlite'
            event = {'id': 12, 'event': 'head_ref_force_pushed', 'commit_id': 'a' * 40}
            first = ingest_force_push(LocalRegistry(path), 'owner/repo', 1, 'orders', event, 'a' * 40, 'config')
            second = ingest_force_push(LocalRegistry(path), 'owner/repo', 1, 'orders', event, 'a' * 40, 'config')
            self.assertFalse(first['trigger']['deduplicated'])
            self.assertTrue(second['trigger']['deduplicated'])
            self.assertEqual(first['trigger']['campaign'], second['trigger']['campaign'])

    def test_stale_event_cannot_replace_current_head(self):
        from skillloop.ci.github_events import ingest_force_push
        with tempfile.TemporaryDirectory() as root:
            registry = LocalRegistry(Path(root) / 'registry.sqlite')
            event = {'id': 12, 'event': 'head_ref_force_pushed', 'commit_id': 'a' * 40}
            with self.assertRaisesRegex(ValueError, 'stale_event_head'):
                ingest_force_push(registry, 'owner/repo', 1, 'orders', event, 'b' * 40, 'config')

    def test_event_identity_required(self):
        from skillloop.ci.github_events import ingest_force_push
        with tempfile.TemporaryDirectory() as root:
            registry = LocalRegistry(Path(root) / 'registry.sqlite')
            with self.assertRaisesRegex(ValueError, 'invalid_force_push_event'):
                ingest_force_push(registry, 'owner/repo', 1, 'orders', {'event': 'head_ref_force_pushed'}, 'a' * 40, 'config')
