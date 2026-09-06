import unittest
from unittest import mock
import tempfile
from pathlib import Path

import build_android_cores
import check_build_resources

ROOT = Path(__file__).resolve().parent
class AndroidProjectTests(unittest.TestCase):
    def test_dual_core_and_locales(self):
        gradle = (ROOT / "app/build.gradle.kts").read_text()
        self.assertIn("INCLUDE_GO_CORE", gradle); self.assertIn("INCLUDE_RUST_CORE", gradle)
        self.assertIn("INCLUDE_GATE", gradle)
        self.assertNotIn('id("org.jetbrains.kotlin.android")', gradle)
        english = (ROOT / "app/src/main/res/values/strings.xml").read_text()
        chinese = (ROOT / "app/src/main/res/values-zh-rCN/strings.xml").read_text()
        import re
        self.assertEqual(set(re.findall(r'name="([^"]+)"', english)), set(re.findall(r'name="([^"]+)"', chinese)))
    def test_security_boundaries(self):
        manifest = (ROOT / "app/src/main/AndroidManifest.xml").read_text()
        self.assertIn('android:usesCleartextTraffic="false"', manifest)
        core = (ROOT / "app/src/main/java/org/shadow6/android/core/CoreRuntime.kt").read_text()
        config = (ROOT / "app/src/main/java/org/shadow6/android/core/CoreConfig.kt").read_text()
        self.assertNotIn("sh -c", core); self.assertIn("app-private storage", core)
        self.assertIn('ProcessBuilder("su", "0", "/system/bin/id", "-u")', core)
        self.assertIn('"listen_addr"', config)
        self.assertIn("CoreRole.BROKER", config)
        self.assertIn("CoreRole.AGENT", config)
        self.assertIn("CoreRole.CLIENT", config)
        self.assertIn("Files.isSymbolicLink", core)
        self.assertIn("MAX_OUTPUT_CHARS", core)
        cross_build = (ROOT / "build_android_cores.py").read_text()
        self.assertIn('"--locked"', cross_build)
        self.assertIn("NDK must contain exactly one non-symlink", cross_build)
        self.assertIn("libshadow6_gate.so", cross_build)
        gate = (ROOT / "app/src/main/java/org/shadow6/android/gate/GateRuntime.kt").read_text()
        self.assertIn("no Termux, Tailscale, or shell", gate)
        self.assertIn("Gate remains disabled until explicitly enabled", gate)
    def test_android_ui_controls_and_branding(self):
        manifest = (ROOT / "app/src/main/AndroidManifest.xml").read_text()
        activity = (ROOT / "app/src/main/java/org/shadow6/android/MainActivity.kt").read_text()
        self.assertIn('android:icon="@mipmap/ic_launcher"', manifest)
        self.assertTrue((ROOT / "app/src/main/res/drawable-nodpi/shadow6_app_icon.png").is_file())
        self.assertIn("CoreStatusPill", activity)
        self.assertIn("CoreRole.entries", activity)
        self.assertIn("generateIdentity", activity)
        self.assertIn("shadow6_public6_profile", activity)
        self.assertIn("SearchScreen(visible)", activity)
        self.assertIn("onNavigate(entry.destination)", activity)
        self.assertIn("LANGUAGE_SYSTEM", activity)
        self.assertIn("attachBaseContext", activity)
    def test_low_memory_build_defaults(self):
        properties = (ROOT / "gradle.properties").read_text()
        self.assertIn("-Xmx384m", properties)
        self.assertIn("org.gradle.parallel=false", properties)
        self.assertIn("org.gradle.workers.max=1", properties)
        self.assertIn("kotlin.compiler.execution.strategy=in-process", properties)
        makefile = ROOT.parent.joinpath("Makefile").read_text()
        self.assertIn("--no-configuration-cache --max-workers=1", makefile)
        gradle = (ROOT / "app/build.gradle.kts").read_text()
        self.assertNotIn("material-icons-extended", gradle.replace(
            "// material-icons-extended:", "// removed-large-icons:"
        ))
        self.assertIn("material-icons-core", gradle)
        self.assertIn("compose-bom:2025.12.01", gradle)
    def test_resource_meminfo_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "meminfo"
            source.write_text("MemTotal: 2048 kB\nMemAvailable: 1024 kB\nSwapTotal: 0 kB\n")
            self.assertEqual(check_build_resources.meminfo(source)["MemTotal"], 2 * 1024 * 1024)
    def test_cgroup_budget_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "memory.max").write_text("2147483648\n")
            (root / "memory.current").write_text("536870912\n")
            (root / "memory.swap.max").write_text("0\n")
            (root / "memory.swap.current").write_text("0\n")
            self.assertEqual(check_build_resources.cgroup_available(root), (2147483648, 1610612736))
    def test_android_native_jobs_are_bounded(self):
        with mock.patch.dict("os.environ", {"SHADOW6_ANDROID_BUILD_JOBS": "17"}):
            with self.assertRaises(SystemExit):
                build_android_cores.build_jobs()
if __name__ == "__main__": unittest.main()
