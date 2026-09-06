"""Fixture-pinned unit tests for /usr/libexec/shadowfetch-hwscan.

Run from the component root with either:
    python3 -m pytest tests/
    python3 -m unittest discover -s tests -v

These tests pin the deterministic capability table (including the low-core
fold and the 16 GB CPU-only wording fix), the subprocess output
parsers, the sysfs GPU scan, and the exact fact-file schema. Nothing
here touches real hardware: every input is a fixture.
"""

import importlib.machinery
import importlib.util
import json
import os
import pathlib
import shutil
import stat
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
SRC = HERE.parent / "usr" / "libexec" / "shadowfetch-hwscan"

_loader = importlib.machinery.SourceFileLoader("hwscan", str(SRC))
_spec = importlib.util.spec_from_loader("hwscan", _loader)
hwscan = importlib.util.module_from_spec(_spec)
_loader.exec_module(hwscan)


def fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


def mk_cpu(cores=8, threads=16, avx2=True):
    return {
        "model": "Fixture CPU",
        "cores": cores,
        "threads": threads,
        "flags": {"avx2": avx2, "fma": avx2, "f16c": avx2,
                  "avx512f": False, "avx512_vnni": False, "amx": False},
    }


def mk_gpu(vendor="nvidia", driver="nvidia", vram=None, source="unknown",
           flags=None, name="Fixture GPU", addr="0000:01:00.0"):
    return {"addr": addr, "vendor": vendor, "name": name, "driver": driver,
            "vram_gb": vram, "vram_source": source,
            "flags": list(flags or [])}


class TestRuleTable(unittest.TestCase):
    """Every row of the deterministic recommendation table."""

    def verdict(self, ram_gb, cores=8, avx2=True, gpus=()):
        return hwscan.build_verdict(mk_cpu(cores=cores, avx2=avx2),
                                    ram_gb, list(gpus))

    def test_under_6gb_tier(self):
        v = self.verdict(4.0)
        self.assertEqual(v["sentence"], hwscan.S_CPU_LT6)
        self.assertEqual(v["badges"], {})

    def test_8gb_tier(self):
        v = self.verdict(8.0)
        self.assertEqual(v["sentence"], hwscan.S_CPU_8)

    def test_16gb_cpu_only_reports_measured_ram(self):
        # A CPU-only system must not claim measured graphics memory.
        v = self.verdict(16.0)
        self.assertEqual(v["sentence"], hwscan.S_CPU_16)
        self.assertNotEqual(v["sentence"], hwscan.S_GPU_8)
        self.assertNotIn("comfortably run 7B", v["sentence"])

    def test_low_core_16gb_keeps_core_count_note(self):
        # Core-count limitations remain visible with local inference deferred.
        v = self.verdict(16.0, cores=2)
        self.assertIn(hwscan.SFX_LOW_CORE, v["suffixes"])

    def test_32gb_tier(self):
        v = self.verdict(32.0)
        self.assertEqual(v["sentence"], hwscan.S_CPU_32)
        self.assertIn("24 GB system RAM", v["sentence"])

    def test_no_avx2_suffix_and_cap(self):
        v = self.verdict(16.0, avx2=False)
        self.assertIn(hwscan.SFX_NO_AVX2, v["suffixes"])

    def test_no_avx2_8gb_tier(self):
        v = self.verdict(8.0, avx2=False)
        self.assertEqual(v["sentence"], hwscan.S_CPU_8)
        self.assertIn(hwscan.SFX_NO_AVX2, v["suffixes"])

    def test_gpu_12gb_full_offload(self):
        gpu = mk_gpu(vram=12.0, source="nvml-smi")
        v = self.verdict(16.0, gpus=[gpu])
        self.assertEqual(v["sentence"], hwscan.S_GPU_12)

    def test_gpu_8gb_reports_measured_graphics_memory(self):
        # Report the sourced memory tier without model performance promises.
        gpu = mk_gpu(vram=8.0, source="nvml-smi")
        v = self.verdict(16.0, gpus=[gpu])
        self.assertEqual(v["sentence"], hwscan.S_GPU_8)
        self.assertIn("8 GB graphics memory", v["sentence"])
        self.assertNotIn("models", v["sentence"])

    def test_gpu_memory_tiers_distinct_below_8gb(self):
        gpu = mk_gpu(vram=6.0, source="sysfs", vendor="amd", driver="amdgpu")
        v = self.verdict(16.0, gpus=[gpu])
        self.assertEqual(v["sentence"], hwscan.S_GPU_6)
        self.assertNotEqual(v["sentence"], hwscan.S_GPU_8)

    def test_gpu_4gb_tier(self):
        gpu = mk_gpu(vram=4.0, source="sysfs", vendor="amd", driver="amdgpu")
        v = self.verdict(16.0, gpus=[gpu])
        self.assertEqual(v["sentence"], hwscan.S_GPU_4)

    def test_nvidia_without_driver_uses_cpu_rules(self):
        gpu = mk_gpu(driver="none", flags=["missing-driver"])
        v = self.verdict(8.0, gpus=[gpu])
        self.assertEqual(v["sentence"], hwscan.S_CPU_8)
        self.assertIn(hwscan.SFX_NV_NO_DRIVER, v["suffixes"])

    def test_nvidia_without_driver_ignores_vulkan_estimate_for_offload(self):
        # NVK may estimate VRAM pre-driver, but the verdict stays on CPU
        # rules until the driver is installed.
        gpu = mk_gpu(driver="nouveau", vram=12.0, source="vulkan",
                     flags=["missing-driver", "vulkan-ok"])
        v = self.verdict(8.0, gpus=[gpu])
        self.assertEqual(v["sentence"], hwscan.S_CPU_8)
        self.assertIn(hwscan.SFX_NV_NO_DRIVER, v["suffixes"])

    def test_low_core_modifier_is_cpu_path_only(self):
        gpu = mk_gpu(vram=12.0, source="nvml-smi")
        v = self.verdict(16.0, cores=2, gpus=[gpu])
        self.assertNotIn(hwscan.SFX_LOW_CORE, v["suffixes"])
        self.assertEqual(v["sentence"], hwscan.S_GPU_12)

    def test_shared_vram_never_counts_for_offload(self):
        gpu = mk_gpu(vendor="intel", driver="i915", vram=None,
                     source="shared")
        v = self.verdict(16.0, gpus=[gpu])
        self.assertEqual(v["sentence"], hwscan.S_CPU_16)

    def test_model_badges_are_delegated_to_buzz(self):
        v = self.verdict(8.0)
        self.assertEqual(v["badges"], {})


class TestParsers(unittest.TestCase):

    def _proc_tree(self, cpuinfo_fixture, meminfo_fixture="meminfo-8g.txt"):
        root = tempfile.mkdtemp(prefix="hwscan-proc-")
        self.addCleanup(shutil.rmtree, root)
        (pathlib.Path(root) / "cpuinfo").write_text(
            fixture(cpuinfo_fixture), encoding="utf-8")
        (pathlib.Path(root) / "meminfo").write_text(
            fixture(meminfo_fixture), encoding="utf-8")
        return root

    def test_cpuinfo_qemu64_lacks_avx2(self):
        cpu = hwscan.read_cpu(self._proc_tree("cpuinfo-qemu64.txt"))
        self.assertEqual(cpu["model"], "QEMU Virtual CPU version 2.5+")
        self.assertFalse(cpu["flags"]["avx2"])
        self.assertFalse(cpu["flags"]["amx"])

    def test_cpuinfo_host_has_avx2(self):
        cpu = hwscan.read_cpu(self._proc_tree("cpuinfo-host-avx2.txt"))
        self.assertTrue(cpu["flags"]["avx2"])
        self.assertTrue(cpu["flags"]["fma"])
        self.assertTrue(cpu["flags"]["f16c"])
        self.assertFalse(cpu["flags"]["avx512f"])

    def test_meminfo_total_only(self):
        self.assertEqual(
            hwscan.read_ram_gb(self._proc_tree("cpuinfo-qemu64.txt")), 8.0)

    def test_pci_ids_lookup(self):
        ids = str(FIXTURES / "pci.ids")
        vname, dname = hwscan.pci_names(0x10DE, 0x2504, ids)
        self.assertEqual(vname, "NVIDIA Corporation")
        self.assertEqual(dname, "GA106 [GeForce RTX 3060 Lite Hash Rate]")
        vname, dname = hwscan.pci_names(0x1002, 0x73DF, ids)
        self.assertEqual(vname, "Advanced Micro Devices, Inc. [AMD/ATI]")
        self.assertIn("Navi 22", dname)

    def test_pci_ids_unknown_device_and_vendor(self):
        ids = str(FIXTURES / "pci.ids")
        vname, dname = hwscan.pci_names(0x10DE, 0xFFFF, ids)
        self.assertEqual(vname, "NVIDIA Corporation")
        self.assertIsNone(dname)
        vname, dname = hwscan.pci_names(0xDEAD, 0xBEEF, ids)
        self.assertIsNone(vname)
        self.assertIsNone(dname)

    def test_pci_ids_missing_file(self):
        self.assertEqual(hwscan.pci_names(0x10DE, 0x2504,
                                          "/nonexistent/pci.ids"),
                         (None, None))

    def test_vulkaninfo_classic_layout(self):
        rows = hwscan.parse_vulkaninfo(fixture("vulkaninfo-classic.json"))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["vendor_id"], 0x1002)
        self.assertEqual(rows[0]["vram_gb"], 12.0)
        self.assertIn("6700 XT", rows[0]["name"])

    def test_vulkaninfo_profiles_layout(self):
        rows = hwscan.parse_vulkaninfo(fixture("vulkaninfo-profiles.json"))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["vendor_id"], 0x10DE)
        self.assertEqual(rows[0]["vram_gb"], 12.0)

    def test_vulkaninfo_garbage_is_unknown(self):
        self.assertEqual(
            hwscan.parse_vulkaninfo(fixture("vulkaninfo-garbage.txt")), [])

    def test_vulkaninfo_none_is_unknown(self):
        self.assertEqual(hwscan.parse_vulkaninfo(None), [])

    def test_nvidia_smi_parse(self):
        rows = hwscan.parse_nvidia_smi(fixture("nvidia-smi-3060.csv"))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "NVIDIA GeForce RTX 3060")
        self.assertEqual(rows[0]["vram_gb"], 12.0)

    def test_nvidia_smi_gib_and_garbage_lines(self):
        rows = hwscan.parse_nvidia_smi(
            "Some GPU, 12 GiB\nnot a csv line\n, 100 MiB\n")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["vram_gb"], 12.0)

    def test_nvidia_smi_none(self):
        self.assertEqual(hwscan.parse_nvidia_smi(None), [])

    def test_run_boxed_missing_binary(self):
        self.assertIsNone(
            hwscan.run_boxed(["shadowfetch-no-such-binary-exists"]))

    def test_run_boxed_nonzero_exit(self):
        self.assertIsNone(hwscan.run_boxed(["sh", "-c", "exit 3"]))

    def test_run_boxed_timeout(self):
        self.assertIsNone(
            hwscan.run_boxed(["sh", "-c", "sleep 2"], timeout_s=0.2))

    def test_vulkan_json_file_output_is_isolated_from_caller(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            caller = root / "caller"
            caller.mkdir()
            vulkaninfo = root / "vulkaninfo"
            vulkaninfo.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' '{\"Profiles\": []}' "
                "> 'VP_VULKANINFO_Fixture_1.json'\n",
                encoding="utf-8",
            )
            vulkaninfo.chmod(vulkaninfo.stat().st_mode | stat.S_IXUSR)
            previous = os.getcwd()
            try:
                os.chdir(caller)
                output = hwscan.run_boxed([str(vulkaninfo), "--json"])
            finally:
                os.chdir(previous)
            self.assertEqual(json.loads(output), {"Profiles": []})
            self.assertEqual(list(caller.iterdir()), [])

    def test_vulkan_json_stdout_compatibility_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            vulkaninfo = pathlib.Path(temporary) / "vulkaninfo"
            vulkaninfo.write_text(
                "#!/bin/sh\nprintf '%s\\n' '{\"Profiles\": []}'\n",
                encoding="utf-8",
            )
            vulkaninfo.chmod(vulkaninfo.stat().st_mode | stat.S_IXUSR)
            output = hwscan.run_boxed([str(vulkaninfo), "--json"])
            self.assertEqual(json.loads(output), {"Profiles": []})

    def test_run_boxed_success(self):
        self.assertEqual(hwscan.run_boxed(["sh", "-c", "echo hi"]), "hi\n")


class TestScanAndReport(unittest.TestCase):
    """sysfs scan, VRAM resolution and the exact fact-file schema."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="hwscan-sys-")
        self.addCleanup(shutil.rmtree, self.root)
        self.sys_root = os.path.join(self.root, "sys")
        self.proc_root = os.path.join(self.root, "proc")
        os.makedirs(os.path.join(self.sys_root, "bus/pci/devices"))
        os.makedirs(self.proc_root)
        with open(os.path.join(self.proc_root, "cpuinfo"), "w") as fh:
            fh.write(fixture("cpuinfo-qemu64.txt"))
        with open(os.path.join(self.proc_root, "meminfo"), "w") as fh:
            fh.write(fixture("meminfo-8g.txt"))
        self.ids = str(FIXTURES / "pci.ids")

    def add_pci(self, addr, pci_class, vendor, device, driver=None,
                vram_bytes=None):
        dev = os.path.join(self.sys_root, "bus/pci/devices", addr)
        os.makedirs(dev)
        for name, value in (("class", pci_class), ("vendor", vendor),
                            ("device", device)):
            with open(os.path.join(dev, name), "w") as fh:
                fh.write(value + "\n")
        if driver:
            drv = os.path.join(self.sys_root, "bus/pci/drivers", driver)
            os.makedirs(drv, exist_ok=True)
            os.symlink(drv, os.path.join(dev, "driver"))
        if vram_bytes is not None:
            with open(os.path.join(dev, "mem_info_vram_total"), "w") as fh:
                fh.write(str(vram_bytes) + "\n")
        return dev

    def scan(self):
        return hwscan.scan_gpus(self.sys_root, self.ids)

    def test_virtio_gpu_row(self):
        self.add_pci("0000:00:01.0", "0x030000", "0x1af4", "0x1050",
                     driver="virtio-pci")
        gpus = self.scan()
        self.assertEqual(len(gpus), 1)
        self.assertEqual(gpus[0]["vendor"], "virtio")
        self.assertEqual(gpus[0]["name"], "virtio (virtual)")
        self.assertIsNone(gpus[0]["vram_gb"])
        self.assertEqual(gpus[0]["vram_source"], "unknown")
        self.assertEqual(gpus[0]["flags"], [])

    def test_non_display_devices_are_skipped(self):
        self.add_pci("0000:00:02.0", "0x020000", "0x8086", "0x1533",
                     driver="igb")  # an ethernet controller
        self.assertEqual(self.scan(), [])

    def test_amd_vram_is_measured_from_sysfs(self):
        self.add_pci("0000:03:00.0", "0x030000", "0x1002", "0x73df",
                     driver="amdgpu", vram_bytes=12884901888)
        gpus = self.scan()
        self.assertEqual(gpus[0]["vendor"], "amd")
        self.assertEqual(gpus[0]["vram_gb"], 12.0)
        self.assertEqual(gpus[0]["vram_source"], "sysfs")
        self.assertIn("Navi 22", gpus[0]["name"])

    def test_intel_igpu_is_shared_never_a_number(self):
        self.add_pci("0000:00:02.0", "0x030000", "0x8086", "0x46a6",
                     driver="i915")
        gpus = self.scan()
        self.assertEqual(gpus[0]["vram_source"], "shared")
        self.assertIsNone(gpus[0]["vram_gb"])

    def test_nvidia_missing_driver_flag(self):
        self.add_pci("0000:01:00.0", "0x030000", "0x10de", "0x2504")
        gpus = self.scan()
        self.assertEqual(gpus[0]["driver"], "none")
        self.assertIn("missing-driver", gpus[0]["flags"])

    def test_nvidia_nouveau_counts_as_missing_driver(self):
        self.add_pci("0000:01:00.0", "0x030000", "0x10de", "0x2504",
                     driver="nouveau")
        self.assertIn("missing-driver", self.scan()[0]["flags"])

    def test_nvidia_post_driver_vram_via_smi_csv(self):
        self.add_pci("0000:01:00.0", "0x030000", "0x10de", "0x2504",
                     driver="nvidia")
        gpus = self.scan()

        def runner(argv, timeout_s=hwscan.TIMEOUT_S):
            if argv[0] == "nvidia-smi":
                return fixture("nvidia-smi-3060.csv")
            return None

        hwscan.resolve_vram(gpus, runner)
        self.assertEqual(gpus[0]["vram_gb"], 12.0)
        self.assertEqual(gpus[0]["vram_source"], "nvml-smi")

    def test_vulkan_estimate_for_pre_driver_nvidia(self):
        self.add_pci("0000:01:00.0", "0x030000", "0x10de", "0x2504")
        gpus = self.scan()

        def runner(argv, timeout_s=hwscan.TIMEOUT_S):
            if argv[0] == "vulkaninfo":
                return fixture("vulkaninfo-profiles.json")
            return None

        hwscan.resolve_vram(gpus, runner)
        self.assertEqual(gpus[0]["vram_gb"], 12.0)
        self.assertEqual(gpus[0]["vram_source"], "vulkan")
        self.assertIn("vulkan-ok", gpus[0]["flags"])
        self.assertIn("missing-driver", gpus[0]["flags"])

    def test_llvmpipe_never_produces_an_estimate(self):
        self.add_pci("0000:00:01.0", "0x030000", "0x1af4", "0x1050",
                     driver="virtio-pci")
        gpus = self.scan()

        def runner(argv, timeout_s=hwscan.TIMEOUT_S):
            if argv[0] == "vulkaninfo":
                return fixture("vulkaninfo-llvmpipe.json")
            return None

        hwscan.resolve_vram(gpus, runner)
        self.assertIsNone(gpus[0]["vram_gb"])
        self.assertEqual(gpus[0]["vram_source"], "unknown")
        self.assertNotIn("vulkan-ok", gpus[0]["flags"])

    def test_probe_failure_leaves_unknown(self):
        self.add_pci("0000:00:01.0", "0x030000", "0x1af4", "0x1050",
                     driver="virtio-pci")
        gpus = self.scan()
        hwscan.resolve_vram(gpus, lambda argv, timeout_s=3: None)
        self.assertEqual(gpus[0]["vram_source"], "unknown")

    def report(self):
        return hwscan.build_report(self.proc_root, self.sys_root, self.ids,
                                   runner=lambda argv, timeout_s=3: None)

    def test_report_schema_is_exact(self):
        self.add_pci("0000:00:01.0", "0x030000", "0x1af4", "0x1050",
                     driver="virtio-pci")
        report = self.report()
        self.assertEqual(set(report), {"schema", "scanned_at", "cpu",
                                       "ram_gb", "gpus", "verdict"})
        self.assertEqual(report["schema"], 1)
        self.assertRegex(report["scanned_at"],
                         r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertEqual(set(report["cpu"]),
                         {"model", "cores", "threads", "flags"})
        self.assertEqual(set(report["cpu"]["flags"]),
                         {"avx2", "fma", "f16c", "avx512f", "avx512_vnni",
                          "amx"})
        self.assertEqual(report["ram_gb"], 8.0)
        self.assertEqual(len(report["gpus"]), 1)
        self.assertEqual(set(report["gpus"][0]),
                         {"addr", "vendor", "name", "driver", "vram_gb",
                          "vram_source", "flags"})
        self.assertEqual(set(report["verdict"]),
                         {"sentence", "suffixes", "badges"})
        # It must round-trip as JSON, exactly as the service writes it.
        self.assertEqual(json.loads(json.dumps(report)), report)

    def test_qemu64_report_wording(self):
        # TS1: no VRAM number anywhere, no-AVX2 suffix, 8 GB tier verdict.
        self.add_pci("0000:00:01.0", "0x030000", "0x1af4", "0x1050",
                     driver="virtio-pci")
        report = self.report()
        self.assertEqual(report["verdict"]["sentence"], hwscan.S_CPU_8)
        self.assertIn(hwscan.SFX_NO_AVX2, report["verdict"]["suffixes"])
        self.assertIsNone(report["gpus"][0]["vram_gb"])
        human = hwscan.human_report(report)
        self.assertIn("virtio (virtual)", human)
        self.assertIn("VRAM: measured after driver install", human)
        self.assertNotIn("VRAM 0", human)

    def test_shared_vram_degradation_string(self):
        self.add_pci("0000:00:02.0", "0x030000", "0x8086", "0x46a6",
                     driver="i915")
        human = hwscan.human_report(self.report())
        self.assertIn("shares system RAM", human)

    def test_write_state_atomic_world_readable(self):
        path = os.path.join(self.root, "var/lib/shadowfetch/hwscan.json")
        report = self.report()
        hwscan.write_state(report, path)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode, 0o644)
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), report)
        self.assertFalse(os.path.exists(path + ".tmp"))
        # A rewrite replaces, never appends or errors.
        hwscan.write_state(report, path)
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), report)


if __name__ == "__main__":
    unittest.main()
