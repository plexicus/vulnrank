"""Unit tests for collector modules."""

import pytest
from collectors.osv_advisories import extract_cves, _osv_ecosystem
from collectors.cisa_kev import load_cve_set
from collectors.epss import load_epss_map
from collectors.github_diff import _tag_candidates, _normalise_repo


class TestOsvEcosystem:
    def test_all_ecosystems(self):
        mapping = {
            "npm": "npm", "pypi": "PyPI", "go": "Go",
            "maven": "Maven", "cargo": "crates.io",
            "nuget": "NuGet", "rubygems": "RubyGems",
        }
        for eco, expected in mapping.items():
            assert _osv_ecosystem(eco) == expected


class TestExtractCves:
    def test_extracts_cve_from_aliases(self):
        advisories = [{"id": "GHSA-abc", "aliases": ["CVE-2021-44228"]}]
        assert "CVE-2021-44228" in extract_cves(advisories)

    def test_extracts_cve_from_id(self):
        advisories = [{"id": "CVE-2022-1234", "aliases": []}]
        assert "CVE-2022-1234" in extract_cves(advisories)

    def test_deduplicates(self):
        advisories = [
            {"id": "CVE-2021-44228", "aliases": ["CVE-2021-44228"]},
        ]
        cves = extract_cves(advisories)
        assert cves.count("CVE-2021-44228") == 1

    def test_empty(self):
        assert extract_cves([]) == []

    def test_skips_non_cve_ids(self):
        advisories = [{"id": "GHSA-abc", "aliases": ["GHSA-def"]}]
        assert extract_cves(advisories) == []


class TestLoadCveSet:
    def test_returns_set_when_file_missing(self, tmp_path):
        result = load_cve_set(str(tmp_path / "nonexistent.json"))
        assert isinstance(result, set)
        assert len(result) == 0

    def test_loads_from_file(self, tmp_path):
        import json
        f = tmp_path / "kev.json"
        f.write_text(json.dumps([{"cve_id": "CVE-2021-44228"}, {"cve_id": "CVE-2020-1234"}]))
        result = load_cve_set(str(f))
        assert "CVE-2021-44228" in result
        assert "CVE-2020-1234" in result


class TestLoadEpssMap:
    def test_returns_dict_when_file_missing(self, tmp_path):
        result = load_epss_map(str(tmp_path / "nonexistent.json"))
        assert isinstance(result, dict)

    def test_loads_scores(self, tmp_path):
        import json
        f = tmp_path / "epss.json"
        f.write_text(json.dumps([{"cve_id": "CVE-2021-44228", "epss": 0.97}]))
        result = load_epss_map(str(f))
        assert result["CVE-2021-44228"] == pytest.approx(0.97)


class TestGithubDiff:
    def test_tag_candidates_v_prefix(self):
        tags = _tag_candidates("2.14.0")
        assert "v2.14.0" in tags
        assert "2.14.0" in tags

    def test_tag_candidates_already_prefixed(self):
        tags = _tag_candidates("v2.14.0")
        assert "v2.14.0" in tags

    def test_normalise_repo_strips_url(self):
        assert _normalise_repo("https://github.com/owner/repo") == "owner/repo"
        assert _normalise_repo("owner/repo") == "owner/repo"
