import unittest
from pathlib import Path
from ohvul.engine_profile import load_profile, profile_compile_args


class EngineProfileTests(unittest.TestCase):
    def test_camera_profile_loads_and_maps_args(self):
        profile = load_profile(Path('docs/design/camera_app_engine_profile.json'))
        args = profile_compile_args(profile, Path('.'))
        self.assertIn('-DABILITY_WINDOW_SUPPORT', args)
        self.assertTrue(any(x.startswith('-I/mnt/c/') for x in args))


if __name__ == '__main__':
    unittest.main()
