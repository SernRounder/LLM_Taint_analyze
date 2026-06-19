"""
tests/test_local_db.py – unit tests for src/local_db.LocalAnalysisDB and LocalFlowDB.

These tests run entirely in-memory and require no MongoDB instance.
"""

from __future__ import annotations

import json
import importlib
import tempfile
from pathlib import Path


def _local_db():
    return importlib.import_module('src.local_db')


# ---------------------------------------------------------------------------
# LocalAnalysisDB tests
# ---------------------------------------------------------------------------

class TestLocalAnalysisDB:
    def _make(self, **kwargs):
        mod = _local_db()
        return mod.LocalAnalysisDB(**kwargs)

    def _sample(self, uid='u1', address='0x1000', name='main'):
        return {
            'uid': uid,
            'address': address,
            'function_name': name,
            'decompiled_code': 'int main() {}',
            'callees': [],
            'llm_result': None,
            'is_source': False,
            'is_sink': False,
        }

    def test_upsert_and_get_function(self):
        db = self._make()
        rec = self._sample()
        db.upsert_function(rec)
        got = db.get_function('u1', '0x1000')
        assert got is not None
        assert got['function_name'] == 'main'

    def test_get_function_missing_returns_none(self):
        db = self._make()
        assert db.get_function('u1', '0xdead') is None

    def test_upsert_updates_existing(self):
        db = self._make()
        db.upsert_function(self._sample())
        db.upsert_function({**self._sample(), 'function_name': 'renamed'})
        assert db.get_function('u1', '0x1000')['function_name'] == 'renamed'

    def test_upsert_functions_bulk(self):
        db = self._make()
        recs = [self._sample(address=f'0x{i:04x}') for i in range(5)]
        db.upsert_functions(recs)
        assert db.count_functions('u1') == 5

    def test_get_all_functions_filters_by_uid(self):
        db = self._make()
        db.upsert_function(self._sample(uid='u1'))
        db.upsert_function(self._sample(uid='u2', address='0x2000'))
        assert len(db.get_all_functions('u1')) == 1
        assert len(db.get_all_functions('u2')) == 1

    def test_get_unanalyzed_functions(self):
        db = self._make()
        db.upsert_function(self._sample(address='0x1000'))
        db.upsert_function(self._sample(address='0x2000'))
        db.update_llm_result('u1', '0x1000', '{"is_source":true}', True, False)
        unanalyzed = db.get_unanalyzed_functions('u1')
        assert len(unanalyzed) == 1
        assert unanalyzed[0]['address'] == '0x2000'

    def test_update_llm_result(self):
        db = self._make()
        db.upsert_function(self._sample())
        db.update_llm_result('u1', '0x1000', '{"is_sink":true}', False, True)
        rec = db.get_function('u1', '0x1000')
        assert rec['is_sink'] is True
        assert rec['llm_result'] == '{"is_sink":true}'

    def test_count_functions(self):
        db = self._make()
        assert db.count_functions('u1') == 0
        db.upsert_function(self._sample())
        assert db.count_functions('u1') == 1

    def test_delete_uid(self):
        db = self._make()
        db.upsert_functions([self._sample(address=f'0x{i:04x}') for i in range(3)])
        deleted = db.delete_uid('u1')
        assert deleted == 3
        assert db.count_functions('u1') == 0

    def test_save_json(self):
        db = self._make()
        db.upsert_function(self._sample())
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            path = Path(f.name)
        try:
            db.save_json(path)
            data = json.loads(path.read_text())
            assert isinstance(data, list)
            assert len(data) == 1
            assert data[0]['function_name'] == 'main'
        finally:
            path.unlink(missing_ok=True)

    def test_save_json_output_json_constructor_param(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            path = Path(f.name)
        try:
            db = self._make(output_json=str(path))
            db.upsert_function(self._sample())
            db.save_json()
            data = json.loads(path.read_text())
            assert len(data) == 1
        finally:
            path.unlink(missing_ok=True)

    def test_save_json_no_path_is_noop(self):
        db = self._make()
        db.upsert_function(self._sample())
        # Should not raise even without a path
        db.save_json()


# ---------------------------------------------------------------------------
# LocalFlowDB tests
# ---------------------------------------------------------------------------

class TestLocalFlowDB:
    def _make(self, uid='u1', **kwargs):
        mod = _local_db()
        return mod.LocalFlowDB(uid=uid, **kwargs)

    def _path_rec(self, src='0x1000', snk='0x2000', flow=None):
        return {
            'uid': 'u1',
            'source_address': src,
            'sink_address': snk,
            'taint_flow': flow or [src, snk],
            'functions': [],
            'sink_decompiled': '',
            'flow_llm_result': None,
        }

    def test_insert_and_get_all(self):
        db = self._make()
        db.insert_path(self._path_rec())
        paths = db.get_all_paths()
        assert len(paths) == 1

    def test_insert_duplicate_ignored(self):
        db = self._make()
        rec = self._path_rec()
        db.insert_path(rec)
        db.insert_path(rec)
        assert db.count_paths() == 1

    def test_insert_paths_returns_count(self):
        db = self._make()
        recs = [
            self._path_rec(src='0x1000', snk='0x2000', flow=['0x1000', '0x2000']),
            self._path_rec(src='0x3000', snk='0x4000', flow=['0x3000', '0x4000']),
        ]
        inserted = db.insert_paths(recs)
        assert inserted == 2

    def test_get_paths_from_source(self):
        db = self._make()
        db.insert_path(self._path_rec(src='0x1000', snk='0x2000', flow=['0x1000', '0x2000']))
        db.insert_path(self._path_rec(src='0x3000', snk='0x4000', flow=['0x3000', '0x4000']))
        assert len(db.get_paths_from_source('0x1000')) == 1

    def test_get_paths_to_sink(self):
        db = self._make()
        db.insert_path(self._path_rec(src='0x1000', snk='0x2000', flow=['0x1000', '0x2000']))
        db.insert_path(self._path_rec(src='0x3000', snk='0x2000', flow=['0x3000', '0x2000']))
        assert len(db.get_paths_to_sink('0x2000')) == 2

    def test_update_flow_llm_result(self):
        db = self._make()
        rec = self._path_rec()
        db.insert_path(rec)
        db.update_flow_llm_result(
            rec['source_address'],
            rec['sink_address'],
            rec['taint_flow'],
            '{"severity":"high"}',
        )
        paths = db.get_all_paths()
        assert paths[0]['flow_llm_result'] == '{"severity":"high"}'

    def test_get_unanalyzed_paths(self):
        db = self._make()
        db.insert_path(self._path_rec(src='0x1000', snk='0x2000', flow=['0x1000', '0x2000']))
        db.insert_path(self._path_rec(src='0x3000', snk='0x4000', flow=['0x3000', '0x4000']))
        db.update_flow_llm_result('0x1000', '0x2000', ['0x1000', '0x2000'], 'done')
        pending = db.get_unanalyzed_paths()
        assert len(pending) == 1
        assert pending[0]['source_address'] == '0x3000'

    def test_count_paths_filters_by_uid(self):
        mod = _local_db()
        db1 = mod.LocalFlowDB(uid='u1')
        db2 = mod.LocalFlowDB(uid='u2')
        db1.insert_path(self._path_rec())
        assert db2.count_paths() == 0

    def test_save_json(self):
        db = self._make()
        db.insert_path(self._path_rec())
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            path = Path(f.name)
        try:
            db.save_json(path)
            data = json.loads(path.read_text())
            assert isinstance(data, list)
            assert len(data) == 1
        finally:
            path.unlink(missing_ok=True)

    def test_save_json_no_path_is_noop(self):
        db = self._make()
        db.insert_path(self._path_rec())
        db.save_json()  # should not raise


# ---------------------------------------------------------------------------
# analyze.py parser: new flags
# ---------------------------------------------------------------------------

class TestAnalyzeParserLocalFlags:
    def _parser(self):
        mod = importlib.import_module('analyze')
        return mod._build_parser()

    def test_output_json_default_none(self):
        args = self._parser().parse_args(['uid1', '0x401000'])
        assert args.output_json is None

    def test_output_json_custom(self):
        args = self._parser().parse_args(['uid1', '0x401000', '--output-json', '/tmp/out.json'])
        assert args.output_json == '/tmp/out.json'

    def test_binary_file_accepted(self):
        args = self._parser().parse_args(['uid1', '0x401000', '--binary-file', '/tmp/fw.bin'])
        assert args.binary_file == '/tmp/fw.bin'
