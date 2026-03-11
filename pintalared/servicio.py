from __future__ import annotations

import asyncio
import ipaddress
import json
import platform
import socket
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from .descubrimiento import descubrir_dispositivos
from .modelos import ArtefactosEscaneo, FiltrosDispositivos, InterfazRed, InstantaneaEscaneo, OpcionesEscaneo
from .reporte import exportar_csv, filtrar_dispositivos
from .sistema import asegurar_entorno_compatible, cargar_datos_interfaces, instalar_nmap, nmap_disponible, parsear_puertos
from .topologia import construir_payload_topologia, renderizar_html_topologia, serializar_instantanea


def _resolver_ip_publica(timeout: float = 2.5) -> str | None:
    servicios = (
        ("https://api.ipify.org?format=json", "json"),
        ("https://ifconfig.me/ip", "text"),
        ("https://icanhazip.com", "text"),
    )
    for url, formato in servicios:
        try:
            peticion = Request(url, headers={"User-Agent": "PintalaRED/0.1"})
            with urlopen(peticion, timeout=timeout) as respuesta:
                cuerpo = respuesta.read().decode("utf-8", errors="replace").strip()
            candidato = json.loads(cuerpo).get("ip", "") if formato == "json" else cuerpo
            ip = str(ipaddress.ip_address(candidato))
            if "." in ip:
                return ip
        except (OSError, ValueError, json.JSONDecodeError, TimeoutError, URLError):
            continue
    return None


async def obtener_ip_publica() -> str | None:
    """Intenta resolver la IP pública sin interrumpir el escaneo si no hay salida a Internet."""
    return await asyncio.to_thread(_resolver_ip_publica)


def listar_interfaces() -> list[InterfazRed]:
    """Obtiene las interfaces activas visibles para PintalaRED."""
    asegurar_entorno_compatible()
    return cargar_datos_interfaces()


async def ejecutar_escaneo_asincrono(opciones: OpcionesEscaneo) -> tuple[InstantaneaEscaneo, dict[str, object]]:
    """Ejecuta el descubrimiento y devuelve una instantánea junto con la topología."""
    asegurar_entorno_compatible()
    usar_nmap_efectivo = opciones.usar_nmap
    if usar_nmap_efectivo and not nmap_disponible() and opciones.instalar_nmap_si_falta:
        instalado, mensaje = instalar_nmap()
        if not instalado:
            raise RuntimeError(mensaje)
    if usar_nmap_efectivo and not nmap_disponible():
        usar_nmap_efectivo = False

    interfaces = cargar_datos_interfaces()
    if opciones.interfaz:
        interfaces = [interfaz for interfaz in interfaces if interfaz.nombre == opciones.interfaz]
        if not interfaces:
            raise RuntimeError(f"No existe una interfaz activa llamada {opciones.interfaz}.")

    puertos = parsear_puertos(opciones.puertos)
    dispositivos_por_red: dict[str, list] = {}
    for interfaz in interfaces:
        red = ipaddress.ip_network(interfaz.red, strict=False)
        cantidad_hosts = max(0, red.num_addresses - 2)
        if cantidad_hosts > opciones.maximo_hosts:
            raise RuntimeError(
                f"La subred {red} contiene demasiados hosts para un barrido por defecto ({cantidad_hosts}). "
                "Usa una interfaz mas especifica o aumenta --max-hosts."
            )
        dispositivos = await descubrir_dispositivos(
            interfaz=interfaz,
            puertos=puertos,
            tiempo_espera_host=opciones.tiempo_espera_host,
            tiempo_espera_puerto=opciones.tiempo_espera_puerto,
            concurrencia_hosts=opciones.concurrencia_hosts,
            concurrencia_puertos=opciones.concurrencia_puertos,
            usar_nmap=usar_nmap_efectivo,
        )
        dispositivos_por_red[interfaz.red] = dispositivos

    host_analizador = socket.gethostname()
    ip_publica = await obtener_ip_publica()
    topologia = construir_payload_topologia(host_analizador, interfaces, dispositivos_por_red, ip_publica=ip_publica)
    instantanea = InstantaneaEscaneo(
        generado_en=time.strftime("%Y-%m-%d %H:%M:%S"),
        host_analizador=host_analizador,
        plataforma=platform.platform(),
        interfaces=interfaces,
        dispositivos_por_red=dispositivos_por_red,
        topologia_html=opciones.nombre_html,
        topologia_json=opciones.nombre_json,
        ip_publica=ip_publica,
    )
    return instantanea, topologia


def ejecutar_escaneo(opciones: OpcionesEscaneo) -> ArtefactosEscaneo:
    """Genera los artefactos persistidos del análisis: HTML, JSON y CSV."""
    directorio_salida = Path(opciones.directorio_salida)
    directorio_salida.mkdir(parents=True, exist_ok=True)
    ruta_html = directorio_salida / opciones.nombre_html
    ruta_json = directorio_salida / opciones.nombre_json
    ruta_csv = directorio_salida / "network_report.csv"

    instantanea, topologia = asyncio.run(ejecutar_escaneo_asincrono(opciones))
    ruta_html.write_text(renderizar_html_topologia(topologia, ruta_json.name), encoding="utf-8")
    ruta_json.write_text(json.dumps(serializar_instantanea(instantanea), indent=2, ensure_ascii=False), encoding="utf-8")

    artefactos = ArtefactosEscaneo(
        instantanea=instantanea,
        topologia=topologia,
        ruta_html=ruta_html,
        ruta_json=ruta_json,
        ruta_csv=ruta_csv,
    )
    exportar_csv(ruta_csv, filtrar_dispositivos(artefactos, FiltrosDispositivos()))
    return artefactos


def formatear_resumen(artefactos: ArtefactosEscaneo) -> str:
    """Genera un resumen legible del inventario detectado."""
    lineas = [
        f"Informe JSON: {artefactos.ruta_json}",
        f"Topologia HTML: {artefactos.ruta_html}",
        f"Informe CSV: {artefactos.ruta_csv}" if artefactos.ruta_csv else "",
        f"IP publica detectada: {artefactos.instantanea.ip_publica}" if artefactos.instantanea.ip_publica else "IP publica detectada: no disponible",
        "",
    ]
    for interfaz in artefactos.instantanea.interfaces:
        lineas.append(f"Interfaz {interfaz.nombre} ({interfaz.ip}/{interfaz.longitud_prefijo})")
        lineas.append(f"  Mascara: {interfaz.mascara_red}")
        lineas.append(f"  Red: {interfaz.red}")
        lineas.append(f"  Gateway: {interfaz.puerta_enlace or 'no detectado'}")
        lineas.append(f"  MAC local: {interfaz.mac or 'desconocida'}")
        dispositivos = artefactos.instantanea.dispositivos_por_red.get(interfaz.red, [])
        lineas.append(f"  Equipos detectados: {len(dispositivos)}")
        for dispositivo in dispositivos:
            lineas.append(
                f"    - {dispositivo.ip} | {dispositivo.nombre_host or 'sin hostname'} | {dispositivo.tipo_dispositivo} | "
                f"{dispositivo.fabricante or 'fabricante desconocido'} | {dispositivo.mac or 'MAC desconocida'} | "
                f"{', '.join(str(p) for p in dispositivo.puertos_abiertos) or 'sin puertos detectados en este escaneo'}"
            )
            notas_relevantes = [
                nota for nota in dispositivo.notas
                if nota.startswith("SO estimado por nmap:") or nota.startswith("Servicios nmap:")
            ]
            for nota in notas_relevantes:
                lineas.append(f"      {nota}")
        lineas.append("")
    return "\n".join(lineas)


# Alias de compatibilidad.
list_interfaces = listar_interfaces
run_scan = ejecutar_escaneo_asincrono
execute_scan = ejecutar_escaneo
format_summary = formatear_resumen
