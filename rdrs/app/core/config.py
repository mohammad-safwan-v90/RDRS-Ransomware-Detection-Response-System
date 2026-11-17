"""
Configuration Loader module for RDRS.
Loads config.yaml safely with fallback for pure Python standard library.
"""

import os
import re
import sys
from datetime import datetime

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def _deep_merge_dicts(defaults: dict, overrides: dict) -> dict:
    merged = {}
    for k, v in defaults.items():
        if isinstance(v, dict):
            override_val = overrides.get(k) if isinstance(overrides, dict) else None
            merged[k] = _deep_merge_dicts(v, override_val if isinstance(override_val, dict) else {})
        else:
            merged[k] = overrides.get(k, v) if isinstance(overrides, dict) else v
    if isinstance(overrides, dict):
        for k, v in overrides.items():
            if k not in merged:
                merged[k] = v
    return merged


class RDRSConfig:
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.config_loaded = False
        self.config_error = None
        self._data = self._load_config()

    def _warn(self, message: str):
        self.config_error = message
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sys.stderr.write(f"{ts} | WARNING  | RDRSConfig - {message}\n")

    def _load_config(self) -> dict:
        defaults = self._default_config()
        if not os.path.exists(self.config_path):
            self._warn(f"Configuration file not found at '{self.config_path}'. Using safe default configuration.")
            return defaults

        try:
            if HAS_YAML:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f)
                if loaded is None:
                    self._warn(f"Configuration file '{self.config_path}' is empty. Using default configuration.")
                    return defaults
                if not isinstance(loaded, dict):
                    self._warn(f"Configuration file '{self.config_path}' did not parse to a mapping. Using default configuration.")
                    return defaults
                self.config_loaded = True
                return _deep_merge_dicts(defaults, loaded)
            else:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    raw_text = f.read()
                if not raw_text.strip():
                    self._warn(f"Configuration file '{self.config_path}' is empty. Using default configuration.")
                    return defaults
                parsed = self._fallback_parse_yaml(self.config_path)
                if self.config_error is not None:
                    return defaults
                self.config_loaded = True
                return _deep_merge_dicts(defaults, parsed)
        except Exception as ex:
            self._warn(f"Failed to load configuration '{self.config_path}': {ex}. Using default configuration.")
            return defaults

    def _fallback_parse_yaml(self, path: str) -> dict:
        config = self._default_config()
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            if content.count("[") != content.count("]") or content.lstrip().startswith(":"):
                self._warn(f"Malformed configuration syntax in '{path}'. Using default configuration.")
                return config
            # Parse key numerical and boolean values
            if "simulation_mode: false" in content.lower():
                config["system"]["simulation_mode"] = False
            if "entropy_threshold:" in content:
                m = re.search(r"entropy_threshold:\s*([0-9.]+)", content)
                if m:
                    config["detection"]["entropy_threshold"] = float(m.group(1))
            if "time_window_seconds:" in content:
                m = re.search(r"time_window_seconds:\s*([0-9]+)", content)
                if m:
                    config["detection"]["time_window_seconds"] = int(m.group(1))
        except Exception as ex:
            self._warn(f"Fallback YAML parser error for '{path}': {ex}")
        return config


    def _default_config(self) -> dict:
        return {
            "system": {"environment": "development", "debug": True, "simulation_mode": True},
            "monitoring": {
                "watch_paths": ["./data/sandbox"],
                "ignored_extensions": [".tmp", ".log"],
                "sample_size_bytes": 65536
            },
            "detection": {
                "time_window_seconds": 60,
                "entropy_threshold": 7.2,
                "rapid_mods_threshold": 15,
                "mass_rename_threshold": 8,
                "cpu_spike_threshold": 75.0
            },
            "threat_scoring": {
                "weights": {
                    "rapid_encryption": 40,
                    "mass_rename": 30,
                    "high_entropy": 25,
                    "cpu_spike": 15,
                    "unknown_program": 10
                },
                "severity_levels": {
                    "normal": [0, 40],
                    "warning": [40, 70],
                    "critical": [70, 100]
                }
            },
            "quarantine": {"storage_dir": "./quarantine", "preserve_metadata": True},
            "database": {"db_url": "sqlite:///./data/rdrs.db"},
            "api": {"host": "0.0.0.0", "port": 8000}
        }

    @property
    def simulation_mode(self) -> bool:
        return self._data.get("system", {}).get("simulation_mode", True)

    @property
    def watch_paths(self) -> list:
        return self._data.get("monitoring", {}).get("watch_paths", ["./data/sandbox"])

    @property
    def entropy_threshold(self) -> float:
        return float(self._data.get("detection", {}).get("entropy_threshold", 7.2))

    @property
    def time_window_seconds(self) -> int:
        return int(self._data.get("detection", {}).get("time_window_seconds", 60))

    @property
    def weights(self) -> dict:
        return self._data.get("threat_scoring", {}).get("weights", {
            "rapid_encryption": 40,
            "mass_rename": 30,
            "high_entropy": 25,
            "cpu_spike": 15,
            "unknown_program": 10
        })

    def get(self, section: str, default=None):
        return self._data.get(section, default)


config = RDRSConfig()
