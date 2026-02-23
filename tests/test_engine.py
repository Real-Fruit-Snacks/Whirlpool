"""Tests for analysis engine."""

import pytest
from whirlpool.engine.analyzer import Analyzer, ExploitationPath, Category, Confidence, Risk
from whirlpool.engine.ranker import Ranker, RankingProfile, RankingWeights
from whirlpool.engine.chain import ChainDetector


class MockLinuxResults:
    """Mock Linux enumeration results for testing."""

    def __init__(self):
        from whirlpool.parser.linpeas import (
            SUIDEntry, CapabilityEntry, SudoEntry, CronEntry, DockerInfo
        )

        self.kernel_version = "5.4.0"
        self.current_user = "testuser"
        self.current_uid = 1000
        self.current_groups = ["testuser", "sudo", "docker"]
        self.hostname = "testhost"

        self.suid_binaries = [
            SUIDEntry(path="/usr/bin/vim"),
            SUIDEntry(path="/usr/bin/find"),
            SUIDEntry(path="/usr/bin/unknown_binary"),
        ]

        self.capabilities = [
            CapabilityEntry(
                path="/usr/bin/python3",
                capabilities=["cap_setuid"],
                cap_string="cap_setuid+ep"
            )
        ]

        self.sudo_rights = [
            SudoEntry(
                user="testuser",
                runas="ALL",
                commands=["/usr/bin/vim"],
                nopasswd=True,
                raw_line="(ALL) NOPASSWD: /usr/bin/vim"
            )
        ]

        self.cron_jobs = [
            CronEntry(
                schedule="* * * * *",
                command="backup.sh",  # Relative path
                user="root",
                file_path="/etc/crontab",
                writable=False
            )
        ]

        self.docker = DockerInfo(
            in_container=False,
            docker_socket_accessible=False,
            docker_group_member=True
        )

        self.nfs_no_root_squash = ["/shared"]
        self.path_writable = ["/tmp"]


class TestAnalyzer:
    """Tests for the Analyzer class."""

    def test_analyze_suid_known_binary(self):
        """Test SUID analysis for known GTFOBins binary."""
        analyzer = Analyzer()
        results = MockLinuxResults()
        paths = analyzer.analyze_linux(results)

        # Should find vim and find as exploitable
        suid_paths = [p for p in paths if p.category == Category.SUID]
        technique_names = [p.technique_name for p in suid_paths]

        assert any("vim" in name.lower() for name in technique_names)
        assert any("find" in name.lower() for name in technique_names)

    def test_analyze_suid_unknown_binary(self):
        """Test SUID analysis for unknown binary."""
        analyzer = Analyzer()
        results = MockLinuxResults()
        paths = analyzer.analyze_linux(results)

        suid_paths = [p for p in paths if p.category == Category.SUID]
        unknown = [p for p in suid_paths if "unknown" in p.technique_name.lower()]

        # Should flag unknown binary for manual review
        assert len(unknown) > 0
        assert unknown[0].confidence == Confidence.LOW

    def test_analyze_capabilities(self):
        """Test capabilities analysis."""
        analyzer = Analyzer()
        results = MockLinuxResults()
        paths = analyzer.analyze_linux(results)

        cap_paths = [p for p in paths if p.category == Category.CAPABILITIES]
        assert len(cap_paths) > 0
        assert any("cap_setuid" in p.technique_name.lower() for p in cap_paths)

    def test_analyze_sudo(self):
        """Test sudo analysis."""
        analyzer = Analyzer()
        results = MockLinuxResults()
        paths = analyzer.analyze_linux(results)

        sudo_paths = [p for p in paths if p.category == Category.SUDO]
        assert len(sudo_paths) > 0
        assert any("vim" in p.technique_name.lower() for p in sudo_paths)

    def test_analyze_docker(self):
        """Test Docker group analysis."""
        analyzer = Analyzer()
        results = MockLinuxResults()
        paths = analyzer.analyze_linux(results)

        docker_paths = [p for p in paths if p.category == Category.DOCKER]
        assert len(docker_paths) > 0

    def test_analyze_nfs(self):
        """Test NFS no_root_squash analysis."""
        analyzer = Analyzer()
        results = MockLinuxResults()
        paths = analyzer.analyze_linux(results)

        nfs_paths = [p for p in paths if p.category == Category.NFS]
        assert len(nfs_paths) > 0


class TestRanker:
    """Tests for the Ranker class."""

    def test_rank_paths(self):
        """Test basic ranking."""
        ranker = Ranker()

        paths = [
            ExploitationPath(
                category=Category.SUID,
                technique_name="Test SUID",
                description="Test",
                finding="/usr/bin/test",
                reliability_score=50,
                safety_score=50,
                simplicity_score=50,
                stealth_score=50
            ),
            ExploitationPath(
                category=Category.SUDO,
                technique_name="Test Sudo",
                description="Test",
                finding="sudo vim",
                reliability_score=90,
                safety_score=90,
                simplicity_score=90,
                stealth_score=50
            )
        ]

        ranked = ranker.rank(paths)

        # Higher scoring path should be first
        assert ranked[0].technique_name == "Test Sudo"

    def test_get_quick_wins(self):
        """Test quick wins selection."""
        ranker = Ranker()

        paths = [
            ExploitationPath(
                category=Category.SUID,
                technique_name="Low Score",
                description="Test",
                finding="test",
                confidence=Confidence.LOW,
                reliability_score=30,
                safety_score=30,
                simplicity_score=30,
                stealth_score=30
            ),
            ExploitationPath(
                category=Category.SUDO,
                technique_name="High Score",
                description="Test",
                finding="test",
                confidence=Confidence.HIGH,
                risk=Risk.LOW,
                reliability_score=95,
                safety_score=95,
                simplicity_score=95,
                stealth_score=80
            )
        ]

        quick_wins = ranker.get_quick_wins(paths, top_n=1)
        assert len(quick_wins) == 1
        assert quick_wins[0].technique_name == "High Score"

    def test_ranking_profiles(self):
        """Test different ranking profiles."""
        path = ExploitationPath(
            category=Category.SUID,
            technique_name="Test",
            description="Test",
            finding="test",
            reliability_score=90,
            safety_score=30,  # Low safety
            simplicity_score=90,
            stealth_score=90
        )

        default_ranker = Ranker(profile=RankingProfile.DEFAULT)
        safe_ranker = Ranker(profile=RankingProfile.SAFE)

        default_score = default_ranker.get_score(path)
        safe_score = safe_ranker.get_score(path)

        # Safe profile should penalize low safety more
        assert safe_score < default_score

    def test_filter_by_confidence(self):
        """Test filtering by minimum confidence."""
        ranker = Ranker()

        paths = [
            ExploitationPath(
                category=Category.SUID,
                technique_name="Low Confidence",
                description="Test",
                finding="test",
                confidence=Confidence.LOW
            ),
            ExploitationPath(
                category=Category.SUDO,
                technique_name="High Confidence",
                description="Test",
                finding="test",
                confidence=Confidence.HIGH
            )
        ]

        filtered = ranker.rank(paths, min_confidence=Confidence.HIGH)
        assert len(filtered) == 1
        assert filtered[0].confidence == Confidence.HIGH

    def test_filter_by_risk(self):
        """Test filtering by maximum risk."""
        ranker = Ranker()

        paths = [
            ExploitationPath(
                category=Category.SUID,
                technique_name="High Risk",
                description="Test",
                finding="test",
                risk=Risk.HIGH
            ),
            ExploitationPath(
                category=Category.SUDO,
                technique_name="Low Risk",
                description="Test",
                finding="test",
                risk=Risk.LOW
            )
        ]

        filtered = ranker.rank(paths, max_risk=Risk.LOW)
        assert len(filtered) == 1
        assert filtered[0].risk == Risk.LOW

    def test_group_by_category(self):
        """Test grouping by category."""
        ranker = Ranker()

        paths = [
            ExploitationPath(
                category=Category.SUID,
                technique_name="SUID 1",
                description="Test",
                finding="test"
            ),
            ExploitationPath(
                category=Category.SUID,
                technique_name="SUID 2",
                description="Test",
                finding="test"
            ),
            ExploitationPath(
                category=Category.SUDO,
                technique_name="Sudo 1",
                description="Test",
                finding="test"
            )
        ]

        grouped = ranker.group_by_category(paths)
        assert Category.SUID in grouped
        assert Category.SUDO in grouped
        assert len(grouped[Category.SUID]) == 2
        assert len(grouped[Category.SUDO]) == 1


class TestChainDetector:
    """Tests for the ChainDetector class."""

    def test_detect_docker_escape(self):
        """Test Docker escape chain detection."""
        detector = ChainDetector()
        results = MockLinuxResults()
        chains = detector.detect_chains(results)

        docker_chains = [c for c in chains if "docker" in c.name.lower()]
        assert len(docker_chains) > 0

    def test_detect_nfs_chain(self):
        """Test NFS no_root_squash chain detection."""
        detector = ChainDetector()
        results = MockLinuxResults()
        chains = detector.detect_chains(results)

        nfs_chains = [c for c in chains if "nfs" in c.name.lower()]
        assert len(nfs_chains) > 0

    def test_chain_has_steps(self):
        """Test that detected chains have steps."""
        detector = ChainDetector()
        results = MockLinuxResults()
        chains = detector.detect_chains(results)

        for chain in chains:
            assert chain.total_steps > 0
            assert len(chain.steps) == chain.total_steps
