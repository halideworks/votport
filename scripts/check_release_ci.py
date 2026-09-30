#!/usr/bin/env python3
"""Require a successful main CI run for the exact release commit."""
import json
import os
import subprocess
import sys
import time


def ci_state(runs, revision):
    matching = [run for run in runs if run.get('head_sha') == revision
                and run.get('event') == 'push' and run.get('head_branch') == 'main']
    if not matching:
        return 'pending'
    latest = max(matching, key=lambda run: (run.get('created_at', ''), run['id']))
    if latest.get('status') != 'completed':
        return 'pending'
    return 'success' if latest.get('conclusion') == 'success' else 'failure'


def main():
    repository, revision = os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_SHA']
    for _ in range(120):
        result = subprocess.run(['gh', 'api',
            f'repos/{repository}/actions/workflows/ci.yml/runs?head_sha={revision}&event=push&per_page=100'],
            check=True, capture_output=True, text=True, timeout=30)
        state = ci_state(json.loads(result.stdout)['workflow_runs'], revision)
        if state == 'success':
            print(f'Main CI passed for {revision}')
            return 0
        if state == 'failure':
            print(f'Main CI did not pass for {revision}', file=sys.stderr)
            return 1
        time.sleep(30)
    print(f'Main CI did not finish for {revision} within one hour', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
