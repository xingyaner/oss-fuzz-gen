# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Unit tests for the deterministic pre-repair safety boundary."""

import datetime as dt
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from experimental.build_fixer import pre_repair


class PreRepairSelectionTest(unittest.TestCase):

  def test_key_project_requires_success_and_error_in_latest_seven(self):
    self.assertTrue(
        pre_repair._is_key_project(['error', 'error', 'success', 'error']))
    self.assertFalse(pre_repair._is_key_project(['error'] * 7 + ['success']))
    self.assertFalse(pre_repair._is_key_project(['success'] * 7))

  def test_acquisition_rejects_unknown_mode_before_browser_access(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      with self.assertRaisesRegex(pre_repair.PreRepairError,
                                  'unsupported acquisition mode'):
        pre_repair.acquire_logs(Path(temp_dir), ['cups-filters'], 'unknown')

  def test_zero_download_error_preserves_acquisition_diagnostics(self):
    status = {'name': 'airflow', 'history': [{}]}
    with tempfile.TemporaryDirectory() as temp_dir:
      with mock.patch.object(pre_repair,
                             '_status_projects',
                             return_value=[status]), self.assertRaises(
                                 pre_repair.PreRepairError) as raised:
        pre_repair.acquire_logs(Path(temp_dir), ['airflow'], 'all')
    report = raised.exception.report
    self.assertIsNotNone(report)
    assert report is not None
    self.assertEqual(report['selected_projects'], ['airflow'])
    self.assertEqual(report['downloaded'], [])
    self.assertEqual(report['project_observations']['airflow']['history_count'],
                     0)

  def test_all_mode_builds_log_urls_directly_from_status_data(self):
    status = {
        'name': 'airflow',
        'history': [{
            'build_id': 'failure-id',
            'finish_time': '2026-09-21T06:20:11Z',
            'success': False
        }],
        'last_successful_build': {
            'build_id': 'success-id',
            'finish_time': '2026-03-23T07:11:41Z'
        }
    }
    with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
        pre_repair, '_status_projects',
        return_value=[status]), mock.patch.object(pre_repair,
                                                  '_download') as download:
      report = pre_repair.acquire_logs(Path(temp_dir), ['airflow'], 'all')
    self.assertEqual(len(report['downloaded']), 2)
    self.assertEqual({call.args[0] for call in download.call_args_list}, {
        pre_repair.BUILD_LOG_ROOT + '/log-failure-id.txt',
        pre_repair.BUILD_LOG_ROOT + '/log-success-id.txt'
    })

  def test_all_mode_filters_continuous_errors_before_download(self):
    history = [{
        'build_id': f'failure-{day}',
        'finish_time': f'2026-09-{day:02d}T06:20:11Z',
        'success': False
    } for day in range(21, 14, -1)]
    status = {
        'name': 'airflow',
        'history': history,
        'last_successful_build': {
            'build_id': 'success-id',
            'finish_time': '2026-03-23T07:11:41Z',
            'success': True
        }
    }
    with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
        pre_repair, '_status_projects',
        return_value=[status]), mock.patch.object(pre_repair,
                                                  '_download') as download:
      report = pre_repair.acquire_logs(Path(temp_dir), ['airflow'], 'all')

    self.assertEqual([item['file'] for item in report['downloaded']],
                     ['2026_03_23 success', '2026_09_15 error'])
    self.assertEqual(download.call_count, 2)
    observation = report['project_observations']['airflow']
    self.assertEqual(observation['candidate_log_count'], 8)
    self.assertEqual(observation['selected_log_count'], 2)
    self.assertEqual(observation['filtered_log_count'], 6)

  def test_pre_download_filter_keeps_success_edges_and_day_collision(self):

    def entry(day, status):
      return {'date': f'2026/09/{day:02d}', 'status': status}

    candidates = [
        entry(10, 'success'),
        entry(11, 'success'),
        entry(12, 'error'),
        entry(12, 'success'),
        entry(13, 'success'),
        entry(14, 'success'),
    ]
    selected = pre_repair._select_boundary_entries(candidates)
    self.assertEqual([(item['date'], item['status']) for item in selected], [
        ('2026/09/10', 'success'),
        ('2026/09/11', 'success'),
        ('2026/09/12', 'success'),
        ('2026/09/12', 'error'),
        ('2026/09/13', 'success'),
        ('2026/09/14', 'success'),
    ])

  def test_pre_download_filter_drops_project_with_only_successes(self):
    candidates = [
        {
            'date': '2026/09/10',
            'status': 'success'
        },
        {
            'date': '2026/09/11',
            'status': 'success'
        },
    ]
    self.assertEqual(pre_repair._select_boundary_entries(candidates), [])

  def test_pre_download_filter_discovers_multiple_dynamic_runs(self):
    candidates = [
        {
            'date': '2026/01/03',
            'status': 'error'
        },
        {
            'date': '2026/01/08',
            'status': 'error'
        },
        {
            'date': '2026/02/14',
            'status': 'success'
        },
        {
            'date': '2026/04/01',
            'status': 'success'
        },
        {
            'date': '2026/07/19',
            'status': 'error'
        },
        {
            'date': '2026/08/30',
            'status': 'error'
        },
    ]
    selected = pre_repair._select_boundary_entries(reversed(candidates))
    self.assertEqual([(item['date'], item['status']) for item in selected], [
        ('2026/01/03', 'error'),
        ('2026/02/14', 'success'),
        ('2026/04/01', 'success'),
        ('2026/07/19', 'error'),
    ])

  def test_calendar_window_matches_requested_example(self):
    self.assertEqual(pre_repair.subtract_calendar_months(dt.date(2026, 9, 20)),
                     dt.date(2026, 6, 20))
    self.assertEqual(pre_repair.subtract_calendar_months(dt.date(2026, 5, 31)),
                     dt.date(2026, 2, 28))

  def test_continuous_error_keeps_earliest_and_success_keeps_boundaries(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      root = Path(temp_dir)
      names = [
          '2026_6_20 success', '2026_6_21 success', '2026_6_22 error',
          '2026_6_23 error', '2026_6_24 success', '2026_6_25 success'
      ]
      logs = []
      for name in names:
        path = root / name
        path.touch()
        logs.append(pre_repair.parse_log_name(path))
      kept, collisions = pre_repair.select_boundary_logs(logs)
      self.assertEqual(collisions, [])
      self.assertEqual({path.name for path in kept}, {
          '2026_6_20 success', '2026_6_21 success', '2026_6_22 error',
          '2026_6_24 success', '2026_6_25 success'
      })

  def test_same_day_conflict_is_preserved(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      root = Path(temp_dir)
      names = ['2026_6_20 error', '2026_6_20 success', '2026_6_21 error']
      logs = []
      for name in names:
        path = root / name
        path.touch()
        logs.append(pre_repair.parse_log_name(path))
      kept, collisions = pre_repair.select_boundary_logs(logs)
      self.assertEqual(collisions, ['2026-06-20'])
      self.assertEqual({path.name for path in kept}, set(names))

  def test_project_filter_limits_selected_log_tree(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      root = Path(temp_dir)
      source = root / 'source'
      destination = root / 'destination'
      for project in ('cups-filters', 'qemu'):
        project_dir = source / project
        project_dir.mkdir(parents=True)
        (project_dir / '2026_6_20 error').touch()
      report = pre_repair.filter_log_tree(source, destination, ['cups-filters'])
      self.assertTrue(
          (destination / 'cups-filters' / '2026_6_20 error').is_file())
      self.assertFalse((destination / 'qemu').exists())
      self.assertEqual(report['copied_count'], 1)

  def test_project_filter_reports_missing_requested_projects(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      root = Path(temp_dir)
      source = root / 'source'
      (source / 'cups-filters').mkdir(parents=True)
      (source / 'cups-filters' / '2026_6_20 error').touch()
      report = pre_repair.filter_log_tree(root / 'source', root / 'destination',
                                          ['qemu'])
      self.assertEqual(report['missing_projects'], ['qemu'])
      self.assertEqual(report['copied_count'], 0)

  def test_required_metadata_rejects_empty_values(self):
    entry = {field: 'set' for field in pre_repair.REQUIRED_METADATA}
    entry['engine'] = ''
    self.assertEqual(pre_repair._valid_entry(entry), ['engine'])

  def test_vertex_alias_matches_full_fixer_alias(self):
    self.assertEqual(pre_repair._vertex_model_name('vertex_ai_gemini-3-1-pro'),
                     'gemini-3.1-pro-preview')

  def test_commit_mapping_uses_latest_commit_strictly_before_error_date(self):
    mapping = [{
        'timestamp_utc': '2026-06-19T23:00:00+00:00',
        'sha': 'anchor'
    }, {
        'timestamp_utc': '2026-06-20T12:00:00+00:00',
        'sha': 'inside-window'
    }]
    self.assertEqual(
        pre_repair._checkout_for_date(mapping, dt.date(2026, 6, 20)), 'anchor')
    self.assertEqual(
        pre_repair._checkout_for_date(mapping, dt.date(2026, 6, 21)),
        'inside-window')

  def test_copy_oss_fuzz_creates_nested_destination_parent(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      root = Path(temp_dir)
      absolute_destination = root / 'missing' / 'nested' / 'oss-fuzz'
      destination = Path(os.path.relpath(absolute_destination, Path.cwd()))
      completed = mock.Mock(returncode=0, stdout='false\n')
      with mock.patch.object(pre_repair, '_run', return_value=completed) as run:
        pre_repair._copy_oss_fuzz(root / 'source', destination)

      self.assertTrue(absolute_destination.parent.is_dir())
      clone_command, clone_cwd = run.call_args_list[0].args[:2]
      self.assertEqual(Path(clone_command[-1]), absolute_destination)
      self.assertEqual(clone_cwd, absolute_destination.parent)

  def test_reproduction_workspace_is_temporary_and_cleaned_on_failure(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      root = Path(temp_dir)
      log_root = root / 'logs' / 'thrift-cpp'
      log_root.mkdir(parents=True)
      (log_root / '2026_09_16 error').touch()
      observed_workspace = None

      def fail_mapping(_source, workspace, _start, _end):
        nonlocal observed_workspace
        observed_workspace = workspace
        self.assertFalse(str(workspace).startswith(str(root / 'pre_repair')))
        raise pre_repair.PreRepairError('mapping failed')

      with mock.patch.object(pre_repair,
                             'build_commit_mapping',
                             side_effect=fail_mapping), self.assertRaises(
                                 pre_repair.PreRepairError):
        pre_repair.run_reproduction_and_extraction(str(root),
                                                   str(root / 'oss-fuzz'),
                                                   'vertex_ai_gemini-3-1-pro',
                                                   str(root / 'logs'),
                                                   ['thrift-cpp'],
                                                   dt.date(2026, 9, 22))

      self.assertIsNotNone(observed_workspace)
      assert observed_workspace is not None
      self.assertFalse(observed_workspace.exists())
      self.assertFalse(
          (root / 'pre_repair' / 'reproduction_workspace').exists())


if __name__ == '__main__':
  unittest.main()
