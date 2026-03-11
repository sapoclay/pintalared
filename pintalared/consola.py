from __future__ import annotations

import argparse
import sys

from . import APP_NAME
from .modelos import OpcionesEscaneo
from .servicio import ejecutar_escaneo, formatear_resumen


def construir_parser_argumentos() -> argparse.ArgumentParser:
    """Define la interfaz de línea de comandos principal de PintalaRED."""
    parser = argparse.ArgumentParser(description=f"{APP_NAME}: descubre equipos de la red local, escanea puertos y genera una topologia HTML.")
    parser.add_argument("--interface", help="Interfaz concreta a analizar, por ejemplo eth0, wlan0, Ethernet o Wi-Fi")
    parser.add_argument("--ports", default="common", help="Puertos a escanear: 'common', '1-1024' o lista '22,80,443,3389'")
    parser.add_argument("--host-timeout", type=float, default=1.0, help="Timeout del ping por host en segundos")
    parser.add_argument("--port-timeout", type=float, default=0.35, help="Timeout por puerto TCP en segundos")
    parser.add_argument("--host-concurrency", type=int, default=128, help="Cantidad de pings concurrentes durante el descubrimiento")
    parser.add_argument("--port-concurrency", type=int, default=256, help="Cantidad de conexiones TCP concurrentes por host")
    parser.add_argument("--max-hosts", type=int, default=512, help="Cantidad maxima de hosts permitidos por subred para evitar barridos accidentales")
    parser.add_argument("--output-dir", default="output", help="Directorio donde se guardan el JSON y el HTML generados")
    parser.add_argument("--json", default="network_report.json", help="Nombre del archivo JSON de salida dentro de output-dir")
    parser.add_argument("--html", default="topologia_red.html", help="Nombre del archivo HTML de salida dentro de output-dir")
    parser.add_argument("--sin-nmap", action="store_true", help="Desactiva el uso de nmap aunque esté instalado")
    parser.add_argument("--instalar-nmap-si-falta", action="store_true", help="Intenta instalar nmap automáticamente si no está disponible")
    return parser


def opciones_desde_argumentos(argumentos: argparse.Namespace) -> OpcionesEscaneo:
    """Convierte la CLI en una estructura de opciones interna."""
    if argumentos.host_concurrency <= 0 or argumentos.port_concurrency <= 0 or argumentos.max_hosts <= 0:
        raise ValueError("Los valores de concurrencia y max-hosts deben ser mayores que cero.")
    return OpcionesEscaneo(
        interfaz=argumentos.interface,
        puertos=argumentos.ports,
        tiempo_espera_host=argumentos.host_timeout,
        tiempo_espera_puerto=argumentos.port_timeout,
        concurrencia_hosts=argumentos.host_concurrency,
        concurrencia_puertos=argumentos.port_concurrency,
        maximo_hosts=argumentos.max_hosts,
        directorio_salida=argumentos.output_dir,
        nombre_json=argumentos.json,
        nombre_html=argumentos.html,
        usar_nmap=not argumentos.sin_nmap,
        instalar_nmap_si_falta=argumentos.instalar_nmap_si_falta,
    )


def main(argv: list[str] | None = None) -> int:
    parser = construir_parser_argumentos()
    args = parser.parse_args(argv)
    try:
        artefactos = ejecutar_escaneo(opciones_desde_argumentos(args))
    except KeyboardInterrupt:
        print("Escaneo interrumpido por el usuario.", file=sys.stderr)
        return 130
    except Exception as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    print(formatear_resumen(artefactos))
    return 0


# Alias de compatibilidad.
build_argument_parser = construir_parser_argumentos
options_from_args = opciones_desde_argumentos
