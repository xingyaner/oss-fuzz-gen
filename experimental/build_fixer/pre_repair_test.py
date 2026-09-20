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
import tempfile
import unittest
from pathlib import Path

from experimental.build_fixer import pre_repair


class PreRepairSelectionTest(unittest.TestCase):

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


if __name__ == '__main__':
  unittest.main()
