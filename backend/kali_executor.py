import json
import shlex
import subprocess
from typing import Dict, List


class KaliExecutor:
    def __init__(self, mode: str = "docker"):
        self.mode = mode.lower()

    def _prefix(self) -> List[str]:
        if self.mode == "wsl":
            return ["wsl", "-d", "kali-linux", "--"]
        return ["docker", "exec", "kali_scanner"]

    def run(self, cmd: List[str], timeout: int = 120) -> Dict[str, str]:
        full = self._prefix() + cmd
        try:
            proc = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
            return {
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "log": f"[tool-exit={proc.returncode}] {shlex.join(full)}",
            }
        except Exception as exc:  # safe fallback logging
            return {"stdout": "", "stderr": str(exc), "log": f"[tool-error] {exc}"}

    def read_file(self, path: str) -> str:
        if self.mode == "wsl":
            cmd = ["cat", path]
        else:
            cmd = ["cat", path]
        result = self.run(cmd, timeout=30)
        return result.get("stdout", "")

    def check_connectivity(self):
        checks = ["nmap", "nikto", "whatweb", "wapiti"]
        output = {}
        for tool in checks:
            res = self.run(["which", tool], timeout=20)
            output[tool] = "ok" if res.get("stdout", "").strip() else "missing"
        output["mode"] = self.mode
        output["healthy"] = all(v == "ok" for k, v in output.items() if k in checks)
        return output
