import unittest
from pathlib import Path
from ohvul.engine_shards import scan_engine_shard


class EngineShardTests(unittest.TestCase):
    def test_missing_file_is_input_error(self):
        result = scan_engine_shard(Path('.'), {'files': ['does-not-exist.c']})
        self.assertEqual(result['status'], 'input_error')
        self.assertEqual(len(result['input_errors']), 1)


if __name__ == '__main__':
    unittest.main()
