import unittest
from pathlib import Path
from ohvul.engine_profile import load_profile, profile_compile_args, validate_profile_sources, validate_profile_provenance


class EngineProfileTests(unittest.TestCase):
    def test_camera_profile_loads_and_maps_args(self):
        profile = load_profile(Path('docs/design/camera_app_engine_profile.json'))
        args = profile_compile_args(profile, Path('.'))
        self.assertIn('-DABILITY_WINDOW_SUPPORT', args)
        self.assertTrue(any(x.startswith('-I/mnt/c/') for x in args))

    def test_invalid_commit_rejected(self):
        import json, tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'profile.json'
            path.write_text(json.dumps({'schema': 'engine-profile-0.1', 'component': 'x', 'source_repositories': {'x': 'bad'}, 'source_files': [], 'include_dirs': [], 'defines': [], 'extra_compile_args': [], 'engines': []}))
            with self.assertRaises(ValueError):
                load_profile(path)

    def test_profile_source_validation_reports_missing_inputs(self):
        profile = {'source_files': ['a.c'], 'include_dirs': ['include']}
        result = validate_profile_sources(profile, Path('.'))
        self.assertFalse(result['complete'])
        self.assertIn('a.c', result['missing_files'])

    def test_profile_provenance_reports_missing_git_worktree(self):
        profile = {'source_repositories': {'missing': 'a'*40}}
        result = validate_profile_provenance(profile, Path('.'))
        self.assertFalse(result['verified'])


if __name__ == '__main__':
    unittest.main()
