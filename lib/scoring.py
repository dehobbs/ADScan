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
    ) -> None:
        # Normalise severity keys to lowercase
        self._weights: dict[str, int] = {
            k.lower(): int(v) for k, v in severity_weights.items()
        }
        self._overrides: dict[str, int] = {
            str(k): int(v) for k, v in overrides.items()
        }
        self._source = source

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

        # Merge with built-ins so any missing severity tier still has a value
        merged_weights = dict(_BUILTIN_SEVERITY_WEIGHTS)
        merged_weights.update({k.lower(): int(v) for k, v in weights.items()})

        return cls(
            severity_weights=merged_weights,
            overrides=overrides,
            source=resolved,
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
