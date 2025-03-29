import re
import chardet
import argparse


def detect_encoding(file_path):
    """Detecta el encoding del archivo para evitar errores de decodificación."""
    with open(file_path, "rb") as f:
        result = chardet.detect(f.read())
    return result["encoding"]


def parse_nmap_output(file_path):
    """Parsea la salida de Nmap desde un archivo y extrae información clave."""
    result = {
        "host": None,
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
        if "Nmap scan report for" in line:
            result["host"] = line.split()[-1]

        # Detectar el estado del host
        elif "Host is up" in line:
            result["state"] = "up"

        # Detectar sistema operativo estimado
        elif "OS details:" in line:
            result["os"] = line.split("OS details:")[1].strip()
        elif "|   OS: " in line and result["os"] is None:
            result["os"] = line.split("|   OS: ")[1].strip()
        # Detectar puertos abiertos y servicios
        elif re.match(r"\d+/tcp\s+open", line):
            parts = line.split()
            port = parts[0]
            service = parts[2]
            version = " ".join(parts[3:]) if len(parts) > 3 else "Desconocido"
            result["ports"].append(f"{port} -> {service} ({version})")

    return result


def display_summary(result):
    """Muestra un resumen del escaneo de Nmap."""
    print("\n🔍 **Resumen del escaneo**")
    print(f"✅ Host: {result['host']}")
    print(f"🖥  Estado: {result['state']}")
    print(f"🛠  Sistema operativo estimado: {result['os']}")

    if result["ports"]:
        print("\n📡 **Puertos y servicios detectados:**")
        for port_info in result["ports"]:
            print(f"  - {port_info}")
    else:
        print("\n🚫 No se encontraron puertos abiertos.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analizador de salida Nmap")
    parser.add_argument("-a", "--archivo", required=True,
                        help="Archivo con la salida de Nmap")
    args = parser.parse_args()

    parsed_result = parse_nmap_output(args.archivo)
    display_summary(parsed_result)
