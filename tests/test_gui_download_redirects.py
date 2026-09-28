"""Real URL parsing checks for the upstream download redirect boundary."""
import importlib.util
from pathlib import Path
import sys
import unittest
import urllib.request


path = Path(__file__).resolve().parents[1] / "tools/download_gui_assets.py"
spec = importlib.util.spec_from_file_location("download_redirect_assets", path)
assets = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = assets
spec.loader.exec_module(assets)


class DownloadRedirectTests(unittest.TestCase):
    def test_current_official_sumatra_file_host_is_accepted(self):
        source = assets.asset_for("sumatrapdf").url
        target = "https://files.sumatrapdfreader.org/software/sumatrapdf/rel/3.6.1/SumatraPDF-3.6.1-64.exe"
        try:
            request = assets.AllowlistedRedirect().redirect_request(
                urllib.request.Request(source), None, 307, "Temporary Redirect", {}, target
            )
        except assets.AssetError as error:
            self.fail(f"Official upstream redirect was rejected: {error}")
        self.assertEqual(request.full_url, target)

    def test_official_name_does_not_allow_downgrade_or_lookalike(self):
        source = assets.asset_for("sumatrapdf").url
        for target in (
            "http://files.sumatrapdfreader.org/file.exe",
            "https://files.sumatrapdfreader.org.attacker.example/file.exe",
            "https://files.sumatrapdfreader.org@attacker.example/file.exe",
        ):
            with self.subTest(target=target), self.assertRaises(assets.AssetError):
                assets.AllowlistedRedirect().redirect_request(
                    urllib.request.Request(source), None, 307, "Temporary Redirect", {}, target
                )


if __name__ == "__main__":
    unittest.main()
