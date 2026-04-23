"""
Utilities to resolve the Dynatrace environment API base URL from ActiveGate config.

Used when the extension runs on an ActiveGate so ``platform/ingest/v1/security.events``
can be reached without hard-coding the tenant URL.
"""

import os
import sys
from pathlib import Path

from dynatrace_extension.sdk.extension import extension_logger as default_log

from .urlutil import join_urls


class DynatraceEnvironmentUtils:
    """
    Read Dynatrace server endpoint and tenant (environment) id from local config files.

    Responsibility:
        Locate ``remotepluginuserconfig.ini`` / gateway config under the extension runtime
        path and parse ``Server`` and ``Tenant`` lines to build ``https://.../e/{tenant}``.
    """

    def __init__(self, log=default_log) -> None:
        """
        Args:
            log: Optional logger override; defaults to Dynatrace ``extension_logger``.
        """
        self.log = log

    def find_install_directory(self) -> Path | None:
        """
        Resolve the Dynatrace install root from gateway ``rootDir`` in config properties.

        Returns:
            Install directory path, or ``None`` if ``rootDir`` cannot be determined.
        """
        config_dir = self.find_config_directory()
        try:
            with open(config_dir / "gateway" / "config" / "custom.properties") as f:
                for line in f:
                    if line.startswith("rootDir"):
                        install_dir = line.split("=")[1].strip()
                        install_dir = install_dir.split("gateway")[0].rstrip("/").rstrip("\\").split("[")[0]
                        return Path(install_dir)
        except Exception:
            pass

        with open(config_dir / "gateway" / "config" / "config.properties") as f:
            for line in f:
                if line.startswith("rootDir"):
                    install_dir = line.split("=")[1].strip()
                    install_dir = install_dir.split("gateway")[0].rstrip("/").rstrip("\\").split("[")[0]
                    return Path(install_dir)
            return None

    def find_config_directory(self) -> Path:
        """
        Derive the Dynatrace ``configs`` directory from ``sys.executable``.

        The Python venv path under ActiveGate contains ``remotepluginmodule``; the
        parent segment before it is treated as the config root.

        Returns:
            Path to the directory containing ``remotepluginmodule``.

        Raises:
            Exception: If ``remotepluginmodule`` is not present in the executable path.
        """
        executable_path = sys.executable
        if "remotepluginmodule" not in f"{executable_path}":
            raise Exception(f"Could not find remotepluginmodule in executable path: {executable_path}")

        config_dir = executable_path.split("remotepluginmodule")[0].rstrip("/").rstrip("\\")
        self.log.info(f"Config directory: {config_dir}")
        return Path(config_dir)

    def get_remotepluginuserconfig_conf_file(self) -> Path:
        """
        Returns:
            Path to ``remotepluginuserconfig.ini`` next to the resolved config directory.
        """
        config_dir = self.find_config_directory()
        return config_dir / "remotepluginmodule/agent/conf/remotepluginuserconfig.ini"

    def get_hardcoded_config_file(self) -> Path:
        """
        Fallback path to ``remotepluginuserconfig.ini`` for typical Windows/Linux installs.

        Returns:
            Standard OS-specific path (may or may not exist on the current host).
        """
        windows_path = "C:/ProgramData/dynatrace/remotepluginmodule/agent/conf/remotepluginuserconfig.ini"
        linux_path = "/var/lib/dynatrace/remotepluginmodule/agent/conf/remotepluginuserconfig.ini"

        return Path(windows_path if os.name == "nt" else linux_path)

    def get_installation_config_files(self) -> list[Path]:
        """
        Returns:
            Paths to ``extensions.conf`` and ``ruxitagent.conf`` under the install tree,
            or an empty list if the install directory cannot be resolved.
        """
        install_dir = self.find_install_directory()
        if install_dir is None:
            return []
        paths_to_check = []
        for file in ["extensions.conf", "ruxitagent.conf"]:
            path_to_check = install_dir / "remotepluginmodule" / "agent" / "conf" / file
            paths_to_check.append(path_to_check)
        return paths_to_check

    def get_api_url(self) -> str:
        """
        Build the environment API base URL ``{endpoint}/e/{environment_id}``.

        Reads candidate files in order: remoteplugin user config, installation conf files,
        then the hardcoded fallback path. Parses first ``Server`` and ``Tenant`` lines found.

        Returns:
            Base URL string used to append API paths (e.g. ``platform/ingest/v1/security.events``).

        Raises:
            Exception: If endpoint or tenant cannot be determined from any file.
        """
        endpoint = ""
        environment = ""

        files_to_check = [
            self.get_remotepluginuserconfig_conf_file(),
            *self.get_installation_config_files(),
            self.get_hardcoded_config_file(),
        ]
        for file in files_to_check:
            if not file.exists():
                self.log.info(f"File '{file}' does not exist, skipping")
                continue
            self.log.info(f"Looking for endpoint URL from file '{file}'")
            with open(file, errors="replace") as f:
                for line in f:
                    if line.startswith("Server") and not endpoint:
                        endpoint = line.split("=")[1].strip() if "=" in line else line.split(" ")[1].strip()
                        endpoint = endpoint.replace("/communication", "")
                        self.log.info(f"Found endpoint URL: '{endpoint}' in '{file}'")
                    if line.startswith("Tenant ") and not environment:
                        environment = (
                            line.split("=")[1].strip() if "=" in line else line.split(" ")[1].strip()
                        )
                        self.log.info(f"Found environment: '{environment}' in '{file}'")
        if endpoint and environment:
            api_url = join_urls(endpoint, "e", environment)
            self.log.info(f"API URL: {api_url}")
            return api_url
        raise Exception(f"Could not find API URL after reading {files_to_check}")
