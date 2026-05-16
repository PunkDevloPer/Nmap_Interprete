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


def detect_encoding(file_path):
    """Detecta el encoding del archivo para evitar errores de decodificación."""
    with open(file_path, "rb") as f:
        result = chardet.detect(f.read())
    return result.get("encoding") or "utf-8"


def parse_nmap_output(file_path):
    """Parsea la salida de Nmap desde un archivo y extrae información clave."""
    result = {
        "host": None,
        "ip": None,
        "state": None,
        "os": None,
        "ports": []
    }

    # Detectar encoding del archivo
    file_encoding = detect_encoding(file_path)

    # Leer archivo con encoding detectado
    with open(file_path, "r", encoding=file_encoding, errors="ignore") as file:
        lines = file.readlines()

    for line in lines:
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


def value_or_unknown(value):
    """Devuelve un texto legible cuando un campo no pudo detectarse."""
    return value or "No detectado"


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
    parser = argparse.ArgumentParser(description="Analizador de salida Nmap")
    parser.add_argument("-a", "--archivo", required=True,
                        help="Archivo con la salida de Nmap")
    parser.add_argument("--json", action="store_true",
                        help="Muestra el resultado en formato JSON")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    args = parser.parse_args()

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
