import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from nmapinterpreter import parse_nmap_output


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "nmapinterpreter.py"


class ParseNmapOutputTests(unittest.TestCase):
    def parse_text(self, text):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as file:
            file.write(text)
            file_path = file.name

        try:
            return parse_nmap_output(file_path)
        finally:
            Path(file_path).unlink()

    def test_parses_host_with_ip_and_tcp_ports(self):
        result = self.parse_text(
            "\n".join(
                [
                    "Nmap scan report for example.com (93.184.216.34)",
                    "Host is up (0.040s latency).",
                    "PORT     STATE SERVICE VERSION",
                    "80/tcp   open  http    nginx 1.22",
                    "OS details: Linux 5.4 - 5.10",
                ]
            )
        )

        self.assertEqual(result["host"], "example.com")
        self.assertEqual(result["ip"], "93.184.216.34")
        self.assertEqual(result["state"], "up")
        self.assertEqual(result["os"], "Linux 5.4 - 5.10")
        self.assertEqual(
            result["ports"][0],
            {
                "port": "80",
                "protocol": "tcp",
                "state": "open",
                "service": "http",
                "version": "nginx 1.22",
            },
        )

    def test_parses_udp_ports(self):
        result = self.parse_text(
            "\n".join(
                [
                    "Nmap scan report for 192.168.1.10",
                    "Host is up.",
                    "PORT   STATE SERVICE VERSION",
                    "53/udp open  domain  dnsmasq 2.80",
                ]
            )
        )

        self.assertEqual(result["ports"][0]["protocol"], "udp")
        self.assertEqual(result["ports"][0]["service"], "domain")


class CliTests(unittest.TestCase):
    def test_missing_file_returns_friendly_error(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "-a", "/tmp/no-existe-nmap.txt"],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 1)
        self.assertIn("Error: no se encontro el archivo", completed.stderr)
        self.assertNotIn("Traceback", completed.stderr)

    def test_json_output(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as file:
            file.write(
                "\n".join(
                    [
                        "Nmap scan report for 127.0.0.1",
                        "Host is up.",
                        "22/tcp open ssh OpenSSH 9.6",
                    ]
                )
            )
            file_path = file.name

        try:
            completed = subprocess.run(
                [sys.executable, str(SCRIPT_PATH), "-a", file_path, "--json"],
                check=True,
                capture_output=True,
                text=True,
            )
        finally:
            Path(file_path).unlink()

        payload = json.loads(completed.stdout)
        self.assertEqual(payload["host"], "127.0.0.1")
        self.assertEqual(payload["ports"][0]["service"], "ssh")


if __name__ == "__main__":
    unittest.main()
