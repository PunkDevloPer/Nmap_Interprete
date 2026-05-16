import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from nmapinterpreter import (
    IMPORT_START,
    parse_nmap_output,
    parse_security_note_text,
    render_security_findings_markdown,
    update_note_with_security_findings,
)


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

    def test_active_note_import_updates_note_once(self):
        note_text = "\n".join(
            [
                "# Objetivo",
                "",
                "Nmap scan report for example.com (93.184.216.34)",
                "Host is up.",
                "80/tcp open http nginx 1.22",
                "",
                "admin [Status: 301, Size: 178, Words: 6, Lines: 8]",
                "200 GET 12l 33w 1234c http://example.com/login",
                "+ /admin: Admin login page",
                "IPC$ NO ACCESS Remote IPC",
                "user:[alice] rid:[0x3e8]",
                "group:[Domain Users] rid:[0x201]",
                "http://example.com [200 OK] HTTPServer[nginx]",
            ]
        )

        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as file:
            file.write(note_text)
            file_path = file.name

        try:
            first_run = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "--nota-activa",
                    file_path,
                    "--actualizar-nota",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            second_run = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "--nota-activa",
                    file_path,
                    "--actualizar-nota",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            updated_note = Path(file_path).read_text(encoding="utf-8")
        finally:
            Path(file_path).unlink()

        self.assertIn("Nota actualizada:", first_run.stdout)
        self.assertIn("Nota actualizada:", second_run.stdout)
        self.assertEqual(updated_note.count(IMPORT_START), 1)
        self.assertIn("### Nmap", updated_note)
        self.assertIn("### ffuf", updated_note)
        self.assertIn("### feroxbuster", updated_note)
        self.assertIn("### nikto", updated_note)
        self.assertIn("### smbmap", updated_note)
        self.assertIn("### enum4linux", updated_note)
        self.assertIn("### whatweb", updated_note)


class SecurityNoteImportTests(unittest.TestCase):
    def test_parse_security_note_text_detects_supported_tools(self):
        note_text = "\n".join(
            [
                "Nmap scan report for 10.10.10.10",
                "445/tcp open microsoft-ds Samba smbd",
                "uploads [Status: 200, Size: 42, Words: 5, Lines: 2]",
                "[301] GET http://target.local/assets",
                "+ Server: Apache",
                "public READ ONLY Public files",
                "user:[bob] rid:[0x3e9]",
                "group:[admins] rid:[0x220]",
                "http://target.local [200 OK] Title[Test]",
            ]
        )

        findings = parse_security_note_text(note_text)

        self.assertEqual(findings["nmap"]["ports"][0]["port"], "445")
        self.assertEqual(findings["ffuf"][0]["path"], "uploads")
        self.assertEqual(findings["feroxbuster"][0]["status"], "301")
        self.assertEqual(findings["nikto"][0], "Server: Apache")
        self.assertEqual(findings["smbmap"][0]["share"], "public")
        self.assertEqual(findings["enum4linux"]["users"][0]["user"], "bob")
        self.assertEqual(findings["whatweb"][0]["target"], "http://target.local")

    def test_render_and_update_note_block(self):
        findings = parse_security_note_text(
            "\n".join(
                [
                    "Nmap scan report for 127.0.0.1",
                    "22/tcp open ssh OpenSSH 9.6",
                ]
            )
        )
        rendered = render_security_findings_markdown(findings)
        note = update_note_with_security_findings("# Nota\n", rendered)
        note = update_note_with_security_findings(note, rendered)

        self.assertEqual(note.count(IMPORT_START), 1)
        self.assertIn("22/tcp open - ssh (OpenSSH 9.6)", note)


if __name__ == "__main__":
    unittest.main()
