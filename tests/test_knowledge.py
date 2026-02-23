"""Tests for knowledge base modules."""

import pytest
import json
from pathlib import Path

# Data directory
DATA_DIR = Path(__file__).parent.parent / "whirlpool" / "data"


class TestGTFOBinsData:
    """Tests for GTFOBins data file."""

    @pytest.fixture
    def gtfobins(self):
        with open(DATA_DIR / "gtfobins.json") as f:
            return json.load(f)

    def test_file_exists(self):
        """Test that GTFOBins data file exists."""
        assert (DATA_DIR / "gtfobins.json").exists()

    def test_has_binaries(self, gtfobins):
        """Test that GTFOBins has binaries."""
        assert "binaries" in gtfobins
        assert len(gtfobins["binaries"]) > 0

    def test_common_binaries_exist(self, gtfobins):
        """Test that common binaries are present."""
        common = ["vim", "find", "python", "bash", "awk", "perl"]
        for binary in common:
            assert binary in gtfobins["binaries"], f"Missing common binary: {binary}"

    def test_binary_has_techniques(self, gtfobins):
        """Test that binaries have exploitation techniques."""
        for name, binary in gtfobins["binaries"].items():
            # Each binary should have at least one technique
            techniques = []
            if "suid" in binary:
                techniques.append("suid")
            if "sudo" in binary:
                techniques.append("sudo")
            if "capabilities" in binary:
                techniques.append("capabilities")
            assert len(techniques) > 0, f"Binary {name} has no techniques"

    def test_technique_has_commands(self, gtfobins):
        """Test that techniques have commands."""
        for name, binary in gtfobins["binaries"].items():
            for technique_name in ["suid", "sudo", "capabilities"]:
                if technique_name in binary:
                    technique = binary[technique_name]
                    assert "commands" in technique, f"{name}.{technique_name} missing commands"
                    assert len(technique["commands"]) > 0


class TestKernelExploitsData:
    """Tests for kernel exploits data file."""

    @pytest.fixture
    def kernel_exploits(self):
        with open(DATA_DIR / "kernel_exploits.json") as f:
            return json.load(f)

    def test_file_exists(self):
        """Test that kernel exploits data file exists."""
        assert (DATA_DIR / "kernel_exploits.json").exists()

    def test_has_linux_exploits(self, kernel_exploits):
        """Test that Linux exploits are present."""
        assert "linux" in kernel_exploits
        assert len(kernel_exploits["linux"]) > 0

    def test_has_windows_exploits(self, kernel_exploits):
        """Test that Windows exploits are present."""
        assert "windows" in kernel_exploits
        assert len(kernel_exploits["windows"]) > 0

    def test_exploit_has_required_fields(self, kernel_exploits):
        """Test that exploits have required fields."""
        required_fields = ["name", "description", "affected_versions"]

        for platform in ["linux", "windows"]:
            for cve, exploit in kernel_exploits[platform].items():
                for field in required_fields:
                    assert field in exploit, f"{cve} missing field: {field}"

    def test_known_exploits_present(self, kernel_exploits):
        """Test that well-known exploits are present."""
        # Linux
        linux_cves = list(kernel_exploits["linux"].keys())
        assert any("CVE-2022-0847" in cve for cve in linux_cves)  # DirtyPipe
        assert any("CVE-2021-4034" in cve for cve in linux_cves)  # PwnKit

        # Windows
        windows_cves = list(kernel_exploits["windows"].keys())
        assert any("CVE-2021-34527" in cve for cve in windows_cves)  # PrintNightmare


class TestPotatoMatrixData:
    """Tests for potato matrix data file."""

    @pytest.fixture
    def potato_matrix(self):
        with open(DATA_DIR / "potato_matrix.json") as f:
            return json.load(f)

    def test_file_exists(self):
        """Test that potato matrix data file exists."""
        assert (DATA_DIR / "potato_matrix.json").exists()

    def test_has_attacks(self, potato_matrix):
        """Test that potato attacks are present."""
        assert "attacks" in potato_matrix
        assert len(potato_matrix["attacks"]) > 0

    def test_known_potatoes_present(self, potato_matrix):
        """Test that well-known potato attacks are present."""
        known = ["JuicyPotato", "PrintSpoofer", "GodPotato", "SweetPotato"]
        attacks = potato_matrix["attacks"]
        for potato in known:
            assert potato in attacks, f"Missing potato: {potato}"

    def test_potato_has_compatibility(self, potato_matrix):
        """Test that potatoes have OS compatibility info."""
        for name, potato in potato_matrix["attacks"].items():
            assert "os_compatibility" in potato, f"{name} missing os_compatibility"

    def test_has_decision_matrix(self, potato_matrix):
        """Test that decision matrix is present."""
        assert "decision_matrix" in potato_matrix
        assert "recommended_order" in potato_matrix["decision_matrix"]


class TestLOLBASData:
    """Tests for LOLBAS data file."""

    @pytest.fixture
    def lolbas(self):
        with open(DATA_DIR / "lolbas.json") as f:
            return json.load(f)

    def test_file_exists(self):
        """Test that LOLBAS data file exists."""
        assert (DATA_DIR / "lolbas.json").exists()

    def test_has_binaries(self, lolbas):
        """Test that LOLBAS has binaries."""
        assert "binaries" in lolbas
        assert len(lolbas["binaries"]) > 0

    def test_common_lolbins_present(self, lolbas):
        """Test that common LOLBAS binaries are present."""
        common = [
            "certutil.exe",
            "mshta.exe",
            "regsvr32.exe",
            "powershell.exe",
            "bitsadmin.exe"
        ]
        for binary in common:
            assert binary in lolbas["binaries"], f"Missing LOLBAS binary: {binary}"

    def test_binary_has_techniques(self, lolbas):
        """Test that binaries have techniques."""
        for name, binary in lolbas["binaries"].items():
            assert "techniques" in binary, f"{name} missing techniques"
            assert len(binary["techniques"]) > 0


