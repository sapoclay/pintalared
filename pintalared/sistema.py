from __future__ import annotations

import ipaddress
import json
import os
import platform
import shutil
import subprocess
import ctypes
from typing import Any

from .modelos import InterfazRed


PUERTOS_COMUNES = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 135, 137, 138, 139,
    143, 161, 389, 443, 445, 465, 514, 587, 631, 993, 995, 1433, 1521, 1723,
    1883, 2049, 2375, 3306, 3389, 5060, 5432, 5900, 6379, 8080, 8443, 8888,
]


def asegurar_linux() -> None:
    """Valida que el entorno tenga las utilidades mínimas para el escaneo."""
    if platform.system().lower() != "linux":
        raise SystemExit("PintalaRED esta pensado para Linux porque depende del comando 'ip'.")

    if shutil.which("ip") is None:
        raise SystemExit("No se encontro el comando 'ip'. Instala iproute2 antes de continuar.")

    if shutil.which("ping") is None:
        raise SystemExit("No se encontro el comando 'ping'. Instala iputils-ping antes de continuar.")


def es_windows() -> bool:
    return platform.system().lower() == "windows"


def es_linux() -> bool:
    return platform.system().lower() == "linux"


def asegurar_entorno_compatible() -> None:
    """Valida que el entorno tenga las utilidades mínimas para el escaneo."""
    if es_linux():
        if shutil.which("ip") is None:
            raise SystemExit("No se encontro el comando 'ip'. Instala iproute2 antes de continuar.")
        if shutil.which("ping") is None:
            raise SystemExit("No se encontro el comando 'ping'. Instala iputils-ping antes de continuar.")
        return

    if es_windows():
        if shutil.which("ping") is None:
            raise SystemExit("No se encontro el comando 'ping'. Verifica que Windows tenga las utilidades de red disponibles.")
        if shutil.which("powershell") is None and shutil.which("pwsh") is None:
            raise SystemExit("No se encontro PowerShell. PintalaRED necesita PowerShell para inventariar la red en Windows.")
        return

    raise SystemExit("PintalaRED solo es compatible actualmente con Linux y Windows.")


def ejecutar_comando(command: list[str], timeout: float | None = None) -> str:
    """Ejecuta un comando del sistema y devuelve su salida estándar."""
    try:
        process = subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"Tiempo de espera agotado al ejecutar {' '.join(command)}.") from error
    if process.returncode != 0:
        error = process.stderr.strip() or process.stdout.strip() or "sin detalles"
        raise RuntimeError(f"Fallo al ejecutar {' '.join(command)}: {error}")
    return process.stdout


def nmap_disponible() -> bool:
    """Indica si el binario nmap está accesible en el sistema."""
    return shutil.which("nmap") is not None


def tiene_privilegios_elevados() -> bool:
    """Indica si el proceso actual tiene permisos elevados suficientes para técnicas avanzadas."""
    if es_linux():
        return hasattr(os, "geteuid") and os.geteuid() == 0
    if es_windows():
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return False


def _comando_instalacion_nmap() -> list[str] | None:
    if es_linux():
        if shutil.which("apt-get"):
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                return ["apt-get", "install", "-y", "nmap"]
            if shutil.which("sudo"):
                return ["sudo", "-n", "apt-get", "install", "-y", "nmap"]
        if shutil.which("dnf"):
            return ["dnf", "install", "-y", "nmap"]
        if shutil.which("yum"):
            return ["yum", "install", "-y", "nmap"]
        if shutil.which("pacman"):
            return ["pacman", "-Sy", "--noconfirm", "nmap"]
        if shutil.which("zypper"):
            return ["zypper", "--non-interactive", "install", "nmap"]
        if shutil.which("apk"):
            return ["apk", "add", "nmap"]
        return None

    if es_windows():
        if shutil.which("winget"):
            return ["winget", "install", "-e", "--id", "Insecure.Nmap", "--accept-package-agreements", "--accept-source-agreements"]
        if shutil.which("choco"):
            return ["choco", "install", "nmap", "-y"]
        return None

    return None


def instalar_nmap() -> tuple[bool, str]:
    """Intenta instalar nmap con el gestor disponible sin bloquear esperando contraseña."""
    if nmap_disponible():
        return True, "nmap ya está instalado."

    comando = _comando_instalacion_nmap()
    if comando is None:
        return False, "No se encontró un gestor compatible para instalar nmap automáticamente."

    proceso = subprocess.run(comando, capture_output=True, text=True, check=False)
    if proceso.returncode != 0:
        detalle = proceso.stderr.strip() or proceso.stdout.strip() or "sin detalles"
        return False, f"No se pudo instalar nmap automáticamente: {detalle}"

    if not nmap_disponible():
        return False, "La instalación terminó sin errores aparentes, pero nmap sigue sin estar disponible en PATH."
    return True, "nmap se instaló correctamente."


def _ejecutable_powershell() -> str:
    ejecutable = shutil.which("powershell") or shutil.which("pwsh")
    if ejecutable is None:
        raise RuntimeError("No se encontro PowerShell para consultar la configuracion de red en Windows.")
    return ejecutable


def ejecutar_powershell(script: str, timeout: float | None = None) -> str:
    """Ejecuta un script de PowerShell y devuelve su salida estándar."""
    try:
        proceso = subprocess.run(
            [_ejecutable_powershell(), "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Tiempo de espera agotado al ejecutar PowerShell.") from error
    if proceso.returncode != 0:
        error = proceso.stderr.strip() or proceso.stdout.strip() or "sin detalles"
        raise RuntimeError(f"Fallo al ejecutar PowerShell: {error}")
    return proceso.stdout


def cargar_json_powershell(script: str) -> Any:
    """Ejecuta PowerShell y convierte la salida JSON en objetos Python."""
    salida = ejecutar_powershell(script).strip()
    if not salida:
        return []
    return json.loads(salida)


def parsear_puertos(especificacion: str) -> list[int]:
    """Convierte una especificación de puertos en una lista ordenada."""
    if especificacion.lower() == "common":
        return PUERTOS_COMUNES

    puertos: set[int] = set()
    for item in especificacion.split(","):
        token = item.strip()
        if not token:
            continue
        if "-" in token:
            inicio_texto, fin_texto = token.split("-", 1)
            inicio = int(inicio_texto)
            fin = int(fin_texto)
            if inicio <= 0 or fin > 65535 or inicio > fin:
                raise ValueError(f"Rango de puertos invalido: {token}")
            puertos.update(range(inicio, fin + 1))
            continue
        puerto = int(token)
        if puerto <= 0 or puerto > 65535:
            raise ValueError(f"Puerto invalido: {token}")
        puertos.add(puerto)

    if not puertos:
        raise ValueError("No se definio ningun puerto valido para el escaneo.")
    return sorted(puertos)


def cargar_datos_interfaces() -> list[InterfazRed]:
    """Descubre las interfaces IPv4 activas y sus metadatos de red."""
    if es_windows():
        return cargar_datos_interfaces_windows()

    payload_direcciones = json.loads(ejecutar_comando(["ip", "-j", "address", "show"]))
    payload_rutas = json.loads(ejecutar_comando(["ip", "-j", "route", "show"]))

    puertas_enlace: dict[str, str] = {}
    for ruta in payload_rutas:
        if ruta.get("dst") == "default" and ruta.get("gateway") and ruta.get("dev"):
            puertas_enlace[ruta["dev"]] = ruta["gateway"]

    interfaces: list[InterfazRed] = []
    for entrada in payload_direcciones:
        nombre_interfaz = entrada.get("ifname")
        banderas = set(entrada.get("flags") or [])
        if nombre_interfaz == "lo" or "UP" not in banderas:
            continue

        mac = entrada.get("address")
        for direccion in entrada.get("addr_info") or []:
            if direccion.get("family") != "inet":
                continue
            ip_local = direccion.get("local")
            longitud_prefijo = int(direccion.get("prefixlen"))
            interfaz = ipaddress.ip_interface(f"{ip_local}/{longitud_prefijo}")
            red = interfaz.network
            interfaces.append(
                InterfazRed(
                    nombre=nombre_interfaz,
                    ip=str(ip_local),
                    longitud_prefijo=longitud_prefijo,
                    mascara_red=str(red.netmask),
                    red=str(red),
                    difusion=direccion.get("broadcast"),
                    mac=mac,
                    puerta_enlace=puertas_enlace.get(nombre_interfaz),
                )
            )

    if not interfaces:
        raise RuntimeError("No se encontraron interfaces IPv4 activas para analizar.")
    return interfaces


def cargar_datos_interfaces_windows() -> list[InterfazRed]:
    """Obtiene interfaces IPv4 activas en Windows usando PowerShell."""
    script = r"""
    Get-NetIPConfiguration |
      ForEach-Object {
        $ipv4 = $_.IPv4Address | Select-Object -First 1
        if ($null -eq $ipv4) { return }
        $gateway = $_.IPv4DefaultGateway | Select-Object -ExpandProperty NextHop -First 1
        [PSCustomObject]@{
          Nombre = $_.InterfaceAlias
          Descripcion = $_.InterfaceDescription
          IP = $ipv4.IPAddress
          Prefijo = $ipv4.PrefixLength
          Gateway = $gateway
          Mac = $_.NetAdapter.MacAddress
          Estado = $_.NetAdapter.Status
        }
      } |
      ConvertTo-Json -Depth 4
    """
    payload = cargar_json_powershell(script)
    if isinstance(payload, dict):
        payload = [payload]

    interfaces: list[InterfazRed] = []
    for entrada in payload or []:
        if str(entrada.get("Estado") or "").lower() not in {"up", "connected"}:
            continue
        ip_local = entrada.get("IP")
        prefijo = entrada.get("Prefijo")
        if not ip_local or prefijo is None:
            continue
        longitud_prefijo = int(prefijo)
        interfaz = ipaddress.ip_interface(f"{ip_local}/{longitud_prefijo}")
        red = interfaz.network
        mac = (entrada.get("Mac") or "").replace("-", ":") or None
        interfaces.append(
            InterfazRed(
                nombre=str(entrada.get("Nombre") or entrada.get("Descripcion") or ip_local),
                ip=str(ip_local),
                longitud_prefijo=longitud_prefijo,
                mascara_red=str(red.netmask),
                red=str(red),
                difusion=str(red.broadcast_address),
                mac=mac.lower() if mac else None,
                puerta_enlace=entrada.get("Gateway"),
            )
        )

    if not interfaces:
        raise RuntimeError("No se encontraron interfaces IPv4 activas para analizar en Windows.")
    return interfaces


# Alias de compatibilidad.
COMMON_PORTS = PUERTOS_COMUNES
ensure_linux = asegurar_linux
ensure_supported_environment = asegurar_entorno_compatible
is_windows = es_windows
is_linux = es_linux
run_command = ejecutar_comando
run_powershell = ejecutar_powershell
load_powershell_json = cargar_json_powershell
parse_ports = parsear_puertos
load_interface_data = cargar_datos_interfaces
