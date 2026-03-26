"""
lib/scoring.py — ADScan Risk Score Configuration Loader

Loads scoring.toml (or any TOML file passed via --scoring-config) and exposes
a single helper, apply_deduction(), that resolves the correct point deduction
for a finding using this priority order:

    1. [overrides] table — exact match on finding["title"]
    2. [severity_weights] table — match on finding["severity"]
    3. finding["deduction"] — the value hardcoded in the check module itself

This means scoring.toml is entirely optional: if it is absent, or if a finding
has no override and no severity-weight entry, the check's own hardcoded value
is used unchanged, preserving full backwards compatibility.

Typical usage in adscan.py::

    from lib.scoring import ScoringConfig
    scoring = ScoringConfig.load(args.scoring_config)   # path or None
    ...
    score = max(0, score - scoring.deduction_for(finding))

TOML compatibility
------------------
Python 3.11+ ships tomllib in the standard library.
Python 3.9 / 3.10 require the 'tomli' backport (pip install tomli).
If neither is available the loader prints a warning and falls back to
built-in deduction values so the tool still works without any TOML library.
"""

from __future__ import annotations

import os
import sys
import warnings
from typing import Any

# ---------------------------------------------------------------------------
# TOML import with graceful fallback
# ---------------------------------------------------------------------------

def _import_toml():
    """Return a tomllib-compatible module or None if none is available."""
    if sys.version_info >= (3, 11):
        import tomllib
        return tomllib
    try:
        import tomli as tomllib  # type: ignore[no-redef]
        return tomllib
    except ImportError:
        return None


_TOML = _import_toml()

# Built-in severity defaults — mirrors what the check modules themselves use.
# These are the last-resort fallback when no config file is loaded.
_BUILTIN_SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 20,
    "high":     15,
    "medium":   8,
    "low":      5,
    "info":     0,
}

# Default path, relative to the project root (same directory as adscan.py)
DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "scoring.toml"
)


class ScoringConfig:
    """
    Holds resolved severity weights and per-finding title overrides.

    Construct via ScoringConfig.load(path) rather than directly.
    """

    def __init__(
        self,
        severity_weights: dict[str, int],
        overrides: dict[str, int],
        source: str,
        initial_score: int = 100,
    ) -> None:
        # Normalise severity keys to lowercase
        self._weights: dict[str, int] = {
            k.lower(): int(v) for k, v in severity_weights.items()
        }
        self._overrides: dict[str, int] = {
            str(k): int(v) for k, v in overrides.items()
        }
        self._source = source
        self._initial_score: int = max(0, min(100, int(initial_score)))

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, path: str | None = None) -> "ScoringConfig":
        """
        Load a TOML scoring config from *path*.

        If *path* is None the default scoring.toml next to adscan.py is tried.
        If the file does not exist a default config is returned silently.
        If the file exists but cannot be parsed an error is printed and defaults
        are used so the scan can still proceed.
        """
        resolved = path or DEFAULT_CONFIG_PATH

        # File not found — silently use defaults (scoring.toml is optional)
        if not os.path.isfile(resolved):
            if path:
                # User explicitly requested a file that doesn't exist — warn
                print(f"[!] Scoring config not found: {resolved} — using built-in weights")
            return cls._defaults(source="<built-in defaults>")

        if _TOML is None:
            warnings.warn(
                f"scoring.toml found at {resolved} but no TOML library is available. "
                "Install tomli (pip install tomli) on Python < 3.11, or upgrade to "
                "Python 3.11+. Falling back to built-in deduction values.",
                stacklevel=2,
            )
            return cls._defaults(source="<built-in defaults (no TOML library)>")

        try:
            with open(resolved, "rb") as fh:
                data: dict[str, Any] = _TOML.load(fh)
        except Exception as exc:
            print(f"[!] Failed to parse scoring config {resolved}: {exc}")
            print("[!] Falling back to built-in deduction weights.")
            return cls._defaults(source="<built-in defaults (parse error)>")

        weights = data.get("severity_weights", {})
        overrides = data.get("overrides", {})
        initial_score = int(data.get("initial_score", 100))

        # Merge with built-ins so any missing severity tier still has a value
        merged_weights = dict(_BUILTIN_SEVERITY_WEIGHTS)
        merged_weights.update({k.lower(): int(v) for k, v in weights.items()})

        return cls(
            severity_weights=merged_weights,
            overrides=overrides,
            source=resolved,
            initial_score=initial_score,
        )

    @classmethod
    def _defaults(cls, source: str) -> "ScoringConfig":
        return cls(
            severity_weights=dict(_BUILTIN_SEVERITY_WEIGHTS),
            overrides={},
            source=source,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def deduction_for(self, finding: dict) -> int:
        """
        Return the point deduction for *finding*, applying override priority.

        Priority:
            1. Per-title override from [overrides]
            2. Severity-tier weight from [severity_weights]
            3. finding["deduction"] — the check module's own hardcoded value
        """
        title = str(finding.get("title", ""))
        severity = str(finding.get("severity", "")).lower()
        builtin = int(finding.get("deduction", 0))

        # 1. Exact title override
        if title in self._overrides:
            return max(0, self._overrides[title])

        # 2. Severity weight
        if severity in self._weights:
            return max(0, self._weights[severity])

        # 3. Built-in fallback
        return max(0, builtin)

    @property
    def source(self) -> str:
        """Path or description of where this config was loaded from."""
        return self._source

    @property
    def initial_score(self) -> int:
        """Starting score before deductions (default 100; configurable via scoring.toml)."""
        return self._initial_score

    def summary(self) -> str:
        """One-line human-readable summary for the startup banner."""
        override_count = len(self._overrides)
        weights_str = ", ".join(
            f"{k}={v}"
            for k, v in sorted(self._weights.items(),
                                key=lambda x: -x[1])
        )
        parts = [f"weights=[{weights_str}]"]
        if override_count:
            parts.append(f"{override_count} title override(s)")
        return f"{self._source} — {', '.join(parts)}"


# ---------------------------------------------------------------------------
# Ratio-based scoring  (Option 2 + 3)
# ---------------------------------------------------------------------------

def compute_scores(findings: list, scoring_config: "ScoringConfig") -> dict:
    """
    Compute the overall score and per-category sub-scores using a ratio-based
    model: score = points_earned / points_possible * 100.

    A finding with severity "info" (deduction == 0) is treated as informational
    and does NOT contribute to points_possible — it neither helps nor hurts the
    score.

    Returns a dict with two keys:
        "overall"    : int  (0-100, rounded)
        "categories" : dict mapping category_name -> {
            "score"    : int   (0-100),
            "earned"   : int   (points earned — only from passing checks),
            "possible" : int   (total points possible in this category),
            "counts"   : {     (finding counts by severity)
                "critical": int, "high": int, "medium": int,
                "low": int, "info": int, "pass": int,
            },
        }

    A "passing" check is one where finding["severity"] == "info" and
    deduction == 0.  Any finding with a non-zero deduction is a failure.

    NOTE: the same check_category may appear in multiple findings.  Each
    non-info finding contributes its weight to points_possible and 0 to
    points_earned; each info finding contributes its weight to both (it
    passed).  Info findings with deduction==0 still get the severity-weight
    of "info" which is 0, so they add nothing numerically — instead we use
    the check's implicit weight via its category.

    Simpler model used here:
        - Every non-info finding: possible += weight, earned += 0  (failed)
        - Every info finding:     possible += weight, earned += weight (passed)
        - weight = scoring_config.deduction_for(finding) if non-zero,
          else fall back to _BUILTIN_SEVERITY_WEIGHTS for the severity tier.
    """
    from collections import defaultdict

    # category_name -> {"earned": int, "possible": int, "counts": dict}
    cat: dict = defaultdict(lambda: {
        "earned": 0, "possible": 0,
        "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "pass": 0},
    })

    total_earned   = 0
    total_possible = 0

    for finding in findings:
        sev     = str(finding.get("severity", "info")).lower()
        cats    = finding.get("check_category") or finding.get("category") or ["Uncategorised"]
        if isinstance(cats, str):
            cats = [cats]

        # Determine weight for this finding
        weight = scoring_config.deduction_for(finding)
        # Info findings have weight 0 by convention — treat them as 0-point passes
        is_pass = (sev == "info") or (weight == 0)

        for cat_name in cats:
            entry = cat[cat_name]
            if is_pass:
                # Passing check: earns its weight (0 for info, which adds nothing)
                entry["earned"]   += weight
                entry["possible"] += weight
                entry["counts"]["pass"] += 1
            else:
                # Failing check: contributes weight to possible but 0 to earned
                entry["possible"] += weight
                sev_key = sev if sev in entry["counts"] else "info"
                entry["counts"][sev_key] += 1

        # Overall totals (use first category only to avoid double-counting)
        if is_pass:
            total_earned   += weight
            total_possible += weight
        else:
            total_possible += weight

    # Build category sub-scores
    category_scores: dict = {}
    for cat_name, data in sorted(cat.items()):
        poss = data["possible"]
        earned = data["earned"]
        sub_score = round(earned / poss * 100) if poss > 0 else 100
        category_scores[cat_name] = {
            "score":    sub_score,
            "earned":   earned,
            "possible": poss,
            "counts":   data["counts"],
        }

    overall = round(total_earned / total_possible * 100) if total_possible > 0 else 100

    return {
        "overall":    overall,
        "categories": category_scores,
    }
