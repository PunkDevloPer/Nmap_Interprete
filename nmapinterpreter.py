import argparse
import json
import re
import sys

import chardet


__version__ = "0.2.1"

PORT_LINE_RE = re.compile(
    r"^(?P<port>\d+)/(?P<protocol>tcp|udp|sctp)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<service>\S+)"
    r"(?:\s+(?P<version>.*))?$"
)
HOST_LINE_RE = re.compile(
    r"^Nmap scan report for (?P<target>.+?)(?: \((?P<ip>[^)]+)\))?$"
)
FFUF_LINE_RE = re.compile(
    r"^\s*(?P<path>\S+)\s+\[Status:\s*(?P<status>\d+),\s*"
    r"Size:\s*(?P<size>\d+),.*\]$"
)
FEROX_LINE_RE = re.compile(
    r"^\s*(?:\[(?P<bracket_status>\d{3})\]|(?P<status>\d{3}))\s+"
    r"(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+"
    r"(?:(?P<lines>\d+)l\s+)?(?:(?P<words>\d+)w\s+)?"
    r"(?:(?P<size>\d+)c\s+)?(?P<url>https?://\S+)"
)
NIKTO_LINE_RE = re.compile(r"^\s*\+\s+(?P<finding>.+)$")
SMBMAP_LINE_RE = re.compile(
    r"^\s*(?P<share>[A-Za-z0-9_$.-]+)\s+"
    r"(?P<permissions>READ ONLY|READ, WRITE|NO ACCESS|READ|WRITE|NO_ACCESS)"
    r"\s*(?P<comment>.*)$"
)
ENUM4LINUX_USER_RE = re.compile(r"user:\[(?P<user>[^\]]+)\]\s+rid:\[(?P<rid>[^\]]+)\]")
ENUM4LINUX_GROUP_RE = re.compile(r"group:\[(?P<group>[^\]]+)\]\s+rid:\[(?P<rid>[^\]]+)\]")
WHATWEB_LINE_RE = re.compile(
    r"^\s*(?P<target>https?://\S+|\d{1,3}(?:\.\d{1,3}){3}|\S+\.\S+)"
    r"\s+\[(?P<status>[^\]]+)\]\s*(?P<details>.*)$"
)
IMPORT_START = "<!-- security-imports:start -->"
IMPORT_END = "<!-- security-imports:end -->"


def detect_encoding(file_path):
    """Detecta el encoding del archivo para evitar errores de decodificación."""
    with open(file_path, "rb") as f:
        result = chardet.detect(f.read())
    return result.get("encoding") or "utf-8"


def read_text_file(file_path):
    """Lee un archivo detectando su encoding."""
    file_encoding = detect_encoding(file_path)
    with open(file_path, "r", encoding=file_encoding, errors="ignore") as file:
        return file.read()


def parse_nmap_text(text):
    """Parsea texto de Nmap y extrae información clave."""
    result = {
        "host": None,
        "ip": None,
        "state": None,
        "os": None,
        "ports": []
    }

    for line in text.splitlines():
        # Detectar el host escaneado
        host_match = HOST_LINE_RE.match(line.strip())
        if host_match:
            result["host"] = host_match.group("target")
            result["ip"] = host_match.group("ip")
            continue

        # Detectar el estado del host
        if "Host is up" in line:
            result["state"] = "up"
            continue
        if "Host seems down" in line:
            result["state"] = "down"
            continue

        # Detectar sistema operativo estimado
        if "OS details:" in line:
            result["os"] = line.split("OS details:")[1].strip()
            continue
        if "|   OS: " in line and result["os"] is None:
            result["os"] = line.split("|   OS: ")[1].strip()
            continue
        if "Running: " in line and result["os"] is None:
            result["os"] = line.split("Running: ")[1].strip()
            continue

        # Detectar puertos abiertos y servicios
        port_match = PORT_LINE_RE.match(line.strip())
        if port_match:
            port_data = port_match.groupdict()
            port_data["version"] = port_data["version"] or "Desconocido"
            result["ports"].append(port_data)

    return result


def parse_nmap_output(file_path):
    """Parsea la salida de Nmap desde un archivo."""
    return parse_nmap_text(read_text_file(file_path))


def parse_ffuf_text(text):
    """Extrae hallazgos de ffuf."""
    findings = []
    for line in text.splitlines():
        match = FFUF_LINE_RE.match(line)
        if match:
            findings.append(match.groupdict())
    return findings


def parse_feroxbuster_text(text):
    """Extrae hallazgos de feroxbuster."""
    findings = []
    for line in text.splitlines():
        match = FEROX_LINE_RE.match(line)
        if not match:
            continue

        data = match.groupdict()
        data["status"] = data["status"] or data["bracket_status"]
        del data["bracket_status"]
        findings.append(data)
    return findings


def parse_nikto_text(text):
    """Extrae hallazgos de Nikto."""
    findings = []
    for line in text.splitlines():
        match = NIKTO_LINE_RE.match(line)
        if match:
            finding = match.group("finding").strip()
            if finding and not finding.startswith("Target "):
                findings.append(finding)
    return findings


def parse_smbmap_text(text):
    """Extrae recursos compartidos de smbmap."""
    findings = []
    for line in text.splitlines():
        match = SMBMAP_LINE_RE.match(line)
        if match:
            findings.append(match.groupdict())
    return findings


def parse_enum4linux_text(text):
    """Extrae usuarios y grupos de enum4linux."""
    users = []
    groups = []
    for line in text.splitlines():
        user_match = ENUM4LINUX_USER_RE.search(line)
        if user_match:
            users.append(user_match.groupdict())

        group_match = ENUM4LINUX_GROUP_RE.search(line)
        if group_match:
            groups.append(group_match.groupdict())

    return {"users": users, "groups": groups}


def parse_whatweb_text(text):
    """Extrae hallazgos de WhatWeb."""
    findings = []
    for line in text.splitlines():
        match = WHATWEB_LINE_RE.match(line)
        if match and "[" in line and "]" in line:
            findings.append(match.groupdict())
    return findings


def parse_security_note_text(text):
    """Detecta hallazgos de varias herramientas en una nota."""
    return {
        "nmap": parse_nmap_text(text),
        "ffuf": parse_ffuf_text(text),
        "feroxbuster": parse_feroxbuster_text(text),
        "nikto": parse_nikto_text(text),
        "smbmap": parse_smbmap_text(text),
        "enum4linux": parse_enum4linux_text(text),
        "whatweb": parse_whatweb_text(text),
    }


def value_or_unknown(value):
    """Devuelve un texto legible cuando un campo no pudo detectarse."""
    return value or "No detectado"


def has_nmap_findings(result):
    """Indica si el bloque Nmap contiene datos detectados."""
    return any([result["host"], result["ip"], result["state"], result["os"], result["ports"]])


def render_security_findings_markdown(findings):
    """Convierte los hallazgos detectados en Markdown para insertar en una nota."""
    lines = [IMPORT_START, "## Hallazgos importados"]

    nmap = findings["nmap"]
    if has_nmap_findings(nmap):
        lines.extend([
            "",
            "### Nmap",
            f"- Host: {value_or_unknown(nmap['host'])}",
            f"- IP: {value_or_unknown(nmap['ip'])}",
            f"- Estado: {value_or_unknown(nmap['state'])}",
            f"- Sistema operativo: {value_or_unknown(nmap['os'])}",
        ])
        if nmap["ports"]:
            lines.append("- Puertos:")
            for port_info in nmap["ports"]:
                endpoint = f"{port_info['port']}/{port_info['protocol']}"
                lines.append(
                    f"  - {endpoint} {port_info['state']} - "
                    f"{port_info['service']} ({port_info['version']})"
                )

    if findings["ffuf"]:
        lines.extend(["", "### ffuf"])
        for item in findings["ffuf"]:
            lines.append(
                f"- {item['path']} - HTTP {item['status']} - "
                f"{item['size']} bytes"
            )

    if findings["feroxbuster"]:
        lines.extend(["", "### feroxbuster"])
        for item in findings["feroxbuster"]:
            size = item["size"] or "?"
            lines.append(
                f"- {item['method']} {item['url']} - HTTP {item['status']} - "
                f"{size} bytes"
            )

    if findings["nikto"]:
        lines.extend(["", "### nikto"])
        for item in findings["nikto"]:
            lines.append(f"- {item}")

    if findings["smbmap"]:
        lines.extend(["", "### smbmap"])
        for item in findings["smbmap"]:
            comment = f" - {item['comment']}" if item["comment"] else ""
            lines.append(f"- {item['share']}: {item['permissions']}{comment}")

    enum4linux = findings["enum4linux"]
    if enum4linux["users"] or enum4linux["groups"]:
        lines.extend(["", "### enum4linux"])
        if enum4linux["users"]:
            lines.append("- Usuarios:")
            for item in enum4linux["users"]:
                lines.append(f"  - {item['user']} ({item['rid']})")
        if enum4linux["groups"]:
            lines.append("- Grupos:")
            for item in enum4linux["groups"]:
                lines.append(f"  - {item['group']} ({item['rid']})")

    if findings["whatweb"]:
        lines.extend(["", "### whatweb"])
        for item in findings["whatweb"]:
            details = f" - {item['details']}" if item["details"] else ""
            lines.append(f"- {item['target']} [{item['status']}]{details}")

    if len(lines) == 2:
        lines.append("")
        lines.append("_No se detectaron hallazgos importables._")

    lines.extend([IMPORT_END, ""])
    return "\n".join(lines)


def update_note_with_security_findings(note_text, rendered_findings):
    """Inserta o reemplaza el bloque generado de hallazgos en una nota."""
    if IMPORT_START in note_text and IMPORT_END in note_text:
        pattern = re.compile(
            rf"{re.escape(IMPORT_START)}.*?{re.escape(IMPORT_END)}\n?",
            re.DOTALL,
        )
        return pattern.sub(rendered_findings, note_text)

    separator = "" if note_text.endswith("\n") else "\n"
    return f"{note_text}{separator}\n{rendered_findings}"


def display_summary(result):
    """Muestra un resumen del escaneo de Nmap."""
    print("\nResumen del escaneo")
    print(f"Host: {value_or_unknown(result['host'])}")
    print(f"IP: {value_or_unknown(result['ip'])}")
    print(f"Estado: {value_or_unknown(result['state'])}")
    print(f"Sistema operativo estimado: {value_or_unknown(result['os'])}")

    if result["ports"]:
        print("\nPuertos y servicios detectados:")
        for port_info in result["ports"]:
            endpoint = f"{port_info['port']}/{port_info['protocol']}"
            print(
                "  - "
                f"{endpoint} {port_info['state']} -> "
                f"{port_info['service']} ({port_info['version']})"
            )
    else:
        print("\nNo se encontraron puertos detectados.")


def main():
    """Punto de entrada de la CLI."""
    parser = argparse.ArgumentParser(description="Importador de hallazgos de seguridad")
    parser.add_argument("-a", "--archivo",
                        help="Archivo con la salida de Nmap")
    parser.add_argument("--nota-activa",
                        help="Archivo Markdown de la nota activa a importar")
    parser.add_argument("--actualizar-nota", action="store_true",
                        help="Reemplaza o inserta los hallazgos dentro de la nota activa")
    parser.add_argument("--json", action="store_true",
                        help="Muestra el resultado en formato JSON")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    if args.nota_activa:
        try:
            note_text = read_text_file(args.nota_activa)
        except FileNotFoundError:
            print(f"Error: no se encontro la nota {args.nota_activa}", file=sys.stderr)
            return 1
        except OSError as exc:
            print(f"Error al leer la nota {args.nota_activa}: {exc}", file=sys.stderr)
            return 1

        findings = parse_security_note_text(note_text)
        if args.json:
            print(json.dumps(findings, ensure_ascii=False, indent=2))
            return 0

        rendered_findings = render_security_findings_markdown(findings)
        if args.actualizar_nota:
            updated_note = update_note_with_security_findings(note_text, rendered_findings)
            with open(args.nota_activa, "w", encoding="utf-8") as file:
                file.write(updated_note)
            print(f"Nota actualizada: {args.nota_activa}")
        else:
            print(rendered_findings)
        return 0

    if not args.archivo:
        parser.error("debes indicar --archivo o --nota-activa")

    try:
        parsed_result = parse_nmap_output(args.archivo)
    except FileNotFoundError:
        print(f"Error: no se encontro el archivo {args.archivo}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error al leer el archivo {args.archivo}: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(parsed_result, ensure_ascii=False, indent=2))
    else:
        display_summary(parsed_result)

    return 0


if __name__ == "__main__":
    sys.exit(main())
