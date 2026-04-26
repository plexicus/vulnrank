"""Unit tests for ranker modules."""

import pytest
from ranker.normalizer import log_normalize, normalize_series
from ranker.scorer import score_ecosystem, _build_purl


class TestLogNormalize:
    def test_zero_value(self):
        assert log_normalize(0, 100) == 0.0

    def test_max_value(self):
        assert log_normalize(100, 100) == pytest.approx(1.0)

    def test_zero_max(self):
        assert log_normalize(50, 0) == 0.0

    def test_midpoint_less_than_one(self):
        result = log_normalize(50, 100)
        assert 0.0 < result < 1.0

    def test_log_compression(self):
        # log normalisation compresses large values
        r1 = log_normalize(10, 100)
        r2 = log_normalize(50, 100)
        r3 = log_normalize(90, 100)
        assert r1 < r2 < r3
        # gap between r2 and r3 smaller than gap between r1 and r2 × 4
        assert (r3 - r2) < (r2 - r1) * 4


class TestNormalizeSeries:
    def test_empty(self):
        assert normalize_series([]) == []

    def test_single(self):
        assert normalize_series([42]) == [pytest.approx(1.0)]

    def test_ordering_preserved(self):
        result = normalize_series([10, 50, 100])
        assert result[0] < result[1] < result[2]
        assert result[2] == pytest.approx(1.0)


class TestBuildPurl:
    def test_npm(self):
        assert _build_purl("npm", "lodash") == "pkg:npm/lodash"

    def test_pypi(self):
        assert _build_purl("pypi", "requests") == "pkg:pypi/requests"

    def test_maven(self):
        purl = _build_purl("maven", "org.springframework:spring-core")
        assert purl == "pkg:maven/org.springframework/spring-core"

    def test_go(self):
        assert _build_purl("go", "github.com/gin-gonic/gin") == "pkg:golang/github.com/gin-gonic/gin"

    def test_rubygems(self):
        assert _build_purl("rubygems", "rails") == "pkg:gem/rails"


class TestScoreEcosystem:
    def _make_pkg(self, name, deps=1000, stars=500, forks=100, cves=None):
        return {
            "name": name, "ecosystem": "npm",
            "default_version": "1.0.0", "github_repo": "owner/repo",
            "deps_dev_dependent_count": deps,
            "github_stars": stars, "github_forks": forks,
            "associated_cves": cves or [],
            "max_cvss": None,
        }

    def test_composite_score_range(self):
        import yaml
        with open("config/weights.yaml") as f:
            weights = yaml.safe_load(f)
        pkgs = [self._make_pkg("a", deps=10000, stars=5000),
                self._make_pkg("b", deps=100, stars=10)]
        results = score_ecosystem(pkgs, set(), {}, weights)
        for r in results:
            s = r["scores"]["composite_score"]
            assert 0.0 <= s <= 1.0

    def test_kev_sets_critical(self):
        import yaml
        with open("config/weights.yaml") as f:
            weights = yaml.safe_load(f)
        pkgs = [self._make_pkg("vuln", cves=["CVE-2021-44228"])]
        results = score_ecosystem(pkgs, {"CVE-2021-44228"}, {}, weights)
        assert results[0]["curation"]["priority"] == "critical"

    def test_sorted_descending(self):
        import yaml
        with open("config/weights.yaml") as f:
            weights = yaml.safe_load(f)
        pkgs = [
            self._make_pkg("a", deps=100),
            self._make_pkg("b", deps=10000),
        ]
        results = score_ecosystem(pkgs, set(), {}, weights)
        assert results[0]["scores"]["composite_score"] >= results[1]["scores"]["composite_score"]

    def test_purl_built(self):
        import yaml
        with open("config/weights.yaml") as f:
            weights = yaml.safe_load(f)
        pkgs = [self._make_pkg("lodash")]
        results = score_ecosystem(pkgs, set(), {}, weights)
        assert results[0]["purl"] == "pkg:npm/lodash"
