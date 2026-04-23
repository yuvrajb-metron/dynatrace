# ruff: noqa: E501
import logging
import os
import re
import sys
from pathlib import Path

default_log = logging.getLogger(__name__)

tenant_regex = re.compile(r"\[(.*)\]")


class DynatraceEnvironmentUtils:
    def __init__(self, log: logging.Logger = default_log):
        self.log = log

    def find_install_directory(self) -> Path:
        # /var/lib/dynatrace/gateway/config/config.properties
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
        # This path:
        # /applis/dynatrace/configs/remotepluginmodule/agent/runtime/extensions/python_venvs/com.dynatrace.salesforce-extension_2.0.7/bin/python3
        # Should return /applis/dynatrace/configs
        # Ie, split on the /remotepluginmodule/ and get the first part
        executable_path = sys.executable
        if "remotepluginmodule" not in f"{executable_path}":
            raise Exception(f"Could not find remotepluginmodule in executable path: {executable_path}")

        config_dir = executable_path.split("remotepluginmodule")[0].rstrip("/").rstrip("\\")
        self.log.debug(f"Config directory: {config_dir}")
        return Path(config_dir)

    def get_remotepluginuserconfig_conf_file(self) -> Path:
        config_dir = self.find_config_directory()
        return config_dir / "remotepluginmodule/agent/conf/remotepluginuserconfig.ini"

    def get_hardcoded_config_file(self) -> Path:
        """
        To modify the ActiveGate plugin module configuration, edit the remotepluginuserconfig.ini file, which is located at:

        Windows: %PROGRAMDATA%\\dynatrace\remotepluginmodule\agent\\conf\remotepluginuserconfig.ini
        Linux: /var/lib/dynatrace/remotepluginmodule/agent/conf/remotepluginuserconfig.ini
        """

        windows_path = "C:/ProgramData/dynatrace/remotepluginmodule/agent/conf/remotepluginuserconfig.ini"
        linux_path = "/var/lib/dynatrace/remotepluginmodule/agent/conf/remotepluginuserconfig.ini"

        return Path(windows_path if os.name == "nt" else linux_path)

    def get_installation_config_files(self) -> list[Path]:
        install_dir = self.find_install_directory()
        paths_to_check = []
        for file in ["extensions.conf", "ruxitagent.conf"]:
            path_to_check = install_dir / "remotepluginmodule" / "agent" / "conf" / file
            paths_to_check.append(path_to_check)
        return paths_to_check

    def get_api_url(self) -> str:
        endpoint = ""
        environment = ""

        files_to_check = [
            self.get_remotepluginuserconfig_conf_file(),
            *self.get_installation_config_files(),
            self.get_hardcoded_config_file(),
        ]
        for file in files_to_check:
            if not file.exists():
                self.log.debug(f"File '{file}' does not exist, skipping")
                continue
            self.log.debug(f"Looking for endpoint URL from file '{file}'")
            with open(file, errors="replace") as f:
                for line in f:
                    if line.startswith("Server") and not endpoint:
                        # it could be a space or an equals sign
                        endpoint = line.split("=")[1].strip() if "=" in line else line.split(" ")[1].strip()
                        endpoint = endpoint.replace("/communication", "")
                        self.log.debug(f"Found endpoint URL: '{endpoint}' in '{file}'")
                    if line.startswith("Tenant ") and not environment:
                        environment = (
                            line.split("=")[1].strip() if "=" in line else line.split(" ")[1].strip()
                        )
                        self.log.debug(f"Found environment: '{environment}' in '{file}'")
        if endpoint and environment:
            api_url = f"{endpoint}/e/{environment}"
            self.log.info(f"API URL: {api_url}")
            return api_url
        raise Exception(f"Could not find API URL after reading {files_to_check}")
