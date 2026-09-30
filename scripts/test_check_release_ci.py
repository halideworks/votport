import unittest
from check_release_ci import ci_state


class ReleaseCiTests(unittest.TestCase):
    def test_exact_main_commit_requires_the_latest_run_to_succeed(self):
        good = dict(id=1, head_sha='release', event='push', head_branch='main',
                    status='completed', conclusion='success', created_at='2026-09-30')
        self.assertEqual(ci_state([good], 'release'), 'success')
        for change in [{'head_sha': 'other'}, {'event': 'pull_request'}, {'head_branch': 'feature'}]:
            self.assertEqual(ci_state([{**good, **change}], 'release'), 'pending')
        for conclusion in ['failure', 'cancelled', 'timed_out', None]:
            newer = {**good, 'id': 2, 'conclusion': conclusion}
            self.assertEqual(ci_state([good, newer], 'release'), 'failure')
        self.assertEqual(ci_state([good, {**good, 'id': 2, 'status': 'in_progress'}], 'release'), 'pending')
        self.assertEqual(ci_state([], 'release'), 'pending')


if __name__ == '__main__':
    unittest.main()
