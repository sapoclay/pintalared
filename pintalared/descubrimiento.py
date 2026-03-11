from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import xml.etree.ElementTree as ET

from .enriquecimiento import clasificar_dispositivo, resolver_fabricante_mac
from .modelos import DispositivoRed, InterfazRed
from .sistema import cargar_json_powershell, ejecutar_comando, es_windows, nmap_disponible, tiene_privilegios_elevados


def _es_ipv4(texto_ip: str) -> bool:
    """Devuelve True si la cadena representa una dirección IPv4 válida."""
    try:
        return ipaddress.ip_address(texto_ip).version == 4
    except ValueError:
        return False


async def hacer_ping(ip: str, tiempo_espera: float) -> bool:
    """Lanza un ping unitario para estimular la tabla ARP y saber si el host respondió."""
    if es_windows():
        comando = ["ping", "-n", "1", "-w", str(max(100, int(tiempo_espera * 1000))), ip]
    else:
        comando = ["ping", "-c", "1", "-W", str(max(1, int(tiempo_espera))), ip]

    proceso = await asyncio.create_subprocess_exec(
        *comando,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proceso.communicate()
    return proceso.returncode == 0


async def cebar_cache_arp(red: ipaddress.IPv4Network, tiempo_espera: float, concurrencia: int) -> set[str]:
    """Realiza pings concurrentes sobre la subred y devuelve los hosts que respondieron."""
    semaforo = asyncio.Semaphore(concurrencia)
    respondedores: set[str] = set()

    async def trabajador(ip_objetivo: str) -> None:
        async with semaforo:
            if await hacer_ping(ip_objetivo, tiempo_espera):
                respondedores.add(ip_objetivo)

    tareas = [asyncio.create_task(trabajador(str(host))) for host in red.hosts()]
    if tareas:
        await asyncio.gather(*tareas)
    return respondedores


def cargar_vecinos(nombre_interfaz: str) -> dict[str, dict[str, str | None]]:
    """Lee los vecinos conocidos por el kernel para una interfaz concreta."""
    if es_windows():
        return cargar_vecinos_windows(nombre_interfaz)

    salida = ejecutar_comando(["ip", "neigh", "show", "dev", nombre_interfaz])
    vecinos: dict[str, dict[str, str | None]] = {}

    for linea_bruta in salida.splitlines():
        linea = linea_bruta.strip()
        if not linea:
            continue
        partes = linea.split()
        ip = partes[0]
        if not _es_ipv4(ip):
            continue
        mac_match = re.search(r"lladdr\s+([0-9a-f:]{17})", linea, re.IGNORECASE)
        mac = mac_match.group(1) if mac_match else None
        estado = partes[-1] if len(partes) > 1 else "UNKNOWN"
        vecinos[ip] = {"mac": mac, "state": estado}

    return vecinos


def _normalizar_mac_vecino(mac: str | None) -> str | None:
    if not mac:
        return None
    mac_normalizada = mac.replace("-", ":").strip().lower()
    if mac_normalizada == "00:00:00:00:00:00":
        return None
    return mac_normalizada


def cargar_vecinos_windows(nombre_interfaz: str) -> dict[str, dict[str, str | None]]:
    """Consulta la caché ARP de Windows para una interfaz concreta."""
    interfaz_escapada = nombre_interfaz.replace("'", "''")
    script = rf"""
    Get-NetNeighbor -AddressFamily IPv4 -InterfaceAlias '{interfaz_escapada}' |
      ForEach-Object {{
        [PSCustomObject]@{{
          IP = $_.IPAddress
          MAC = $_.LinkLayerAddress
                    Estado = $_.State.ToString()
        }}
      }} |
      ConvertTo-Json -Depth 3
    """
    payload = cargar_json_powershell(script)
    if isinstance(payload, dict):
        payload = [payload]

    vecinos: dict[str, dict[str, str | None]] = {}
    for entrada in payload or []:
        ip = str(entrada.get("IP") or "")
        if not ip or not _es_ipv4(ip):
            continue
        mac = _normalizar_mac_vecino(str(entrada.get("MAC") or ""))
        estado_valor = entrada.get("Estado")
        estado = str(estado_valor).strip() if estado_valor is not None else "UNKNOWN"
        if estado.upper() in {"UNREACHABLE", "INCOMPLETE", "FAILED"} and mac is None:
            continue
        vecinos[ip] = {
            "mac": mac,
            "state": estado,
        }
    return vecinos


def resolver_dns_inverso(ip: str) -> str | None:
    """Intenta resolver el hostname asociado a una IP descubierta."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except OSError:
        return None


def _resolver_hostname_por_sistema(ip: str) -> str | None:
    """Agota métodos del sistema para recuperar un nombre cuando no hay PTR utilizable."""
    if es_windows():
        try:
            salida = ejecutar_comando(["ping", "-a", "-n", "1", "-w", "400", ip], timeout=1.0)
        except Exception:
            return None
        primera_linea = next((linea.strip() for linea in salida.splitlines() if linea.strip()), "")
        coincidencia = re.search(r"\s([^\s\[]+)\s+\[" + re.escape(ip) + r"\]", primera_linea)
        if coincidencia:
            candidato = coincidencia.group(1).strip()
            return candidato if candidato and candidato != ip else None
        return None

    try:
        salida = ejecutar_comando(["getent", "hosts", ip])
    except Exception:
        return None
    for linea in salida.splitlines():
        partes = linea.split()
        if len(partes) >= 2 and partes[0] == ip:
            candidato = partes[1].strip()
            return candidato if candidato and candidato != ip else None
    return None


def resolver_nombre_host(ip: str) -> tuple[str | None, str | None]:
    """Intenta recuperar un hostname usando varios métodos y devuelve también su origen."""
    if es_windows():
        nombre_sistema = _resolver_hostname_por_sistema(ip)
        if nombre_sistema:
            return nombre_sistema, "resolución auxiliar del sistema"
        return None, None

    nombre_dns = resolver_dns_inverso(ip)
    if nombre_dns:
        return nombre_dns, "DNS inverso"

    nombre_fqdn = socket.getfqdn(ip)
    if nombre_fqdn and nombre_fqdn != ip:
        return nombre_fqdn, "FQDN del sistema"

    nombre_sistema = _resolver_hostname_por_sistema(ip)
    if nombre_sistema:
        return nombre_sistema, "resolución auxiliar del sistema"

    return None, None


def _extraer_host_nmap(host: ET.Element) -> dict[str, object] | None:
    direccion_ipv4 = None
    direccion_mac = None
    fabricante = None
    for address in host.findall("address"):
        tipo = address.attrib.get("addrtype")
        if tipo == "ipv4":
            direccion_ipv4 = address.attrib.get("addr")
        elif tipo == "mac":
            direccion_mac = address.attrib.get("addr")
            fabricante = address.attrib.get("vendor") or fabricante

    if not direccion_ipv4 or not _es_ipv4(direccion_ipv4):
        return None

    hostname = None
    hostnames = host.find("hostnames")
    if hostnames is not None:
        primer_hostname = hostnames.find("hostname")
        if primer_hostname is not None:
            hostname = primer_hostname.attrib.get("name")

    puertos_abiertos: list[int] = []
    servicios: dict[int, str] = {}
    puertos = host.find("ports")
    if puertos is not None:
        for puerto in puertos.findall("port"):
            estado = puerto.find("state")
            if estado is not None and estado.attrib.get("state") == "open":
                try:
                    numero_puerto = int(puerto.attrib.get("portid", "0"))
                except ValueError:
                    continue
                puertos_abiertos.append(numero_puerto)
                servicio = puerto.find("service")
                if servicio is not None:
                    partes_servicio = [
                        str(servicio.attrib.get("name") or "").strip(),
                        str(servicio.attrib.get("product") or "").strip(),
                        str(servicio.attrib.get("version") or "").strip(),
                        str(servicio.attrib.get("extrainfo") or "").strip(),
                    ]
                    descripcion = " ".join(parte for parte in partes_servicio if parte)
                    if descripcion:
                        servicios[numero_puerto] = descripcion

    estado_host = "UNKNOWN"
    estado = host.find("status")
    if estado is not None:
        estado_host = str(estado.attrib.get("state") or "UNKNOWN").upper()

    sistema_operativo = None
    os_element = host.find("os")
    if os_element is not None:
        mejor_coincidencia = os_element.find("osmatch")
        if mejor_coincidencia is not None:
            nombre_so = str(mejor_coincidencia.attrib.get("name") or "").strip()
            precision = str(mejor_coincidencia.attrib.get("accuracy") or "").strip()
            if nombre_so:
                sistema_operativo = f"{nombre_so} ({precision}%)" if precision else nombre_so

    return {
        "ip": direccion_ipv4,
        "mac": direccion_mac.lower() if direccion_mac else None,
        "fabricante": fabricante,
        "hostname": hostname,
        "puertos": sorted(puertos_abiertos),
        "servicios": servicios,
        "sistema_operativo": sistema_operativo,
        "state": estado_host,
    }


def _combinar_hallazgos_nmap(*colecciones: dict[str, dict[str, object]]) -> dict[str, dict[str, object]]:
    combinados: dict[str, dict[str, object]] = {}
    for coleccion in colecciones:
        for ip, datos in coleccion.items():
            actual = combinados.setdefault(ip, {})
            for clave, valor in datos.items():
                if valor in (None, "", [], {}):
                    continue
                if clave == "puertos":
                    anteriores = set(actual.get("puertos") or [])
                    actual["puertos"] = sorted(anteriores | set(valor))
                    continue
                if clave == "servicios":
                    servicios_actuales = dict(actual.get("servicios") or {})
                    servicios_actuales.update(valor)
                    actual["servicios"] = servicios_actuales
                    continue
                actual[clave] = valor
    return combinados


async def descubrir_hosts_con_nmap(red: str, tiempo_espera_host: float) -> dict[str, dict[str, object]]:
    """Usa nmap para descubrir hosts reales de la red y recuperar hostname, MAC y fabricante."""
    if not nmap_disponible():
        return {}

    temporizador_ms = str(max(100, int(tiempo_espera_host * 1000)))
    comando = [
        "nmap",
        "-sn",
        "-R",
        "-T4",
        "-oX",
        "-",
        "--host-timeout",
        temporizador_ms,
        red,
    ]

    proceso = await asyncio.create_subprocess_exec(
        *comando,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    salida, _ = await proceso.communicate()
    if proceso.returncode != 0:
        return {}

    try:
        raiz = ET.fromstring(salida.decode("utf-8", errors="replace"))
    except ET.ParseError:
        return {}

    resultados: dict[str, dict[str, object]] = {}
    for host in raiz.findall("host"):
        info = _extraer_host_nmap(host)
        if info is None:
            continue
        resultados[str(info["ip"])] = info
    return resultados


async def escanear_servicios_con_nmap(ips: list[str], puertos: list[int], tiempo_espera_host: float) -> dict[str, dict[str, object]]:
    """Usa nmap sobre hosts ya descubiertos para intentar detectar servicios y SO."""
    if not nmap_disponible() or not ips or not puertos:
        return {}

    especificacion_puertos = ",".join(str(puerto) for puerto in puertos)
    temporizador_ms = str(max(100, int(tiempo_espera_host * 1000)))
    comando = [
        "nmap",
        "-Pn",
        "-R",
        "-sV",
        "--version-light",
        "-T4",
        "-oX",
        "-",
        "--host-timeout",
        temporizador_ms,
        "-p",
        especificacion_puertos,
    ]
    if tiene_privilegios_elevados():
        comando.extend(["-O", "--osscan-limit"])
    comando.extend(ips)

    proceso = await asyncio.create_subprocess_exec(
        *comando,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    salida, _ = await proceso.communicate()
    if proceso.returncode != 0:
        return {}

    try:
        raiz = ET.fromstring(salida.decode("utf-8", errors="replace"))
    except ET.ParseError:
        return {}

    resultados: dict[str, dict[str, object]] = {}
    for host in raiz.findall("host"):
        info = _extraer_host_nmap(host)
        if info is None:
            continue
        resultados[str(info["ip"])] = info
    return resultados


async def escanear_puerto(ip: str, puerto: int, tiempo_espera: float) -> int | None:
    """Prueba una conexión TCP simple para detectar si un puerto está abierto."""
    try:
        _, escritor = await asyncio.wait_for(asyncio.open_connection(ip, puerto), timeout=tiempo_espera)
        escritor.close()
        await escritor.wait_closed()
        return puerto
    except Exception:
        return None


async def escanear_puertos(ip: str, puertos: list[int], tiempo_espera: float, concurrencia: int) -> list[int]:
    """Escanea una lista de puertos TCP con concurrencia controlada."""
    semaforo = asyncio.Semaphore(concurrencia)

    async def trabajador(puerto: int) -> int | None:
        async with semaforo:
            return await escanear_puerto(ip, puerto, tiempo_espera)

    tareas = [asyncio.create_task(trabajador(puerto)) for puerto in puertos]
    resultados = await asyncio.gather(*tareas)
    return sorted(puerto for puerto in resultados if puerto is not None)


async def descubrir_dispositivos(
    interfaz: InterfazRed,
    puertos: list[int],
    tiempo_espera_host: float,
    tiempo_espera_puerto: float,
    concurrencia_hosts: int,
    concurrencia_puertos: int,
    usar_nmap: bool = True,
) -> list[DispositivoRed]:
    """Descubre equipos visibles desde una interfaz y enriquece cada resultado."""
    red = ipaddress.ip_network(interfaz.red, strict=False)
    hosts_validos = {str(host) for host in red.hosts()}
    respondedores_ping = await cebar_cache_arp(red, tiempo_espera_host, concurrencia_hosts)
    vecinos = {
        ip: metadatos
        for ip, metadatos in cargar_vecinos(interfaz.nombre).items()
        if _es_ipv4(ip)
    }
    hallazgos_descubrimiento = await descubrir_hosts_con_nmap(interfaz.red, tiempo_espera_host) if usar_nmap else {}
    ips_para_servicios = sorted(set(hallazgos_descubrimiento.keys()) | respondedores_ping | set(vecinos.keys()), key=ipaddress.ip_address)
    ips_para_servicios = [ip for ip in ips_para_servicios if ip in hosts_validos or ip == interfaz.puerta_enlace]
    hallazgos_servicios = await escanear_servicios_con_nmap(ips_para_servicios, puertos, tiempo_espera_host) if usar_nmap else {}
    hallazgos_nmap = _combinar_hallazgos_nmap(hallazgos_descubrimiento, hallazgos_servicios)
    if interfaz.puerta_enlace and _es_ipv4(interfaz.puerta_enlace):
        vecinos.setdefault(interfaz.puerta_enlace, {"mac": None, "state": "GATEWAY"})

    ips_candidatas = set(vecinos.keys()) | respondedores_ping | set(hallazgos_nmap.keys())
    dispositivos: list[DispositivoRed] = []

    for ip in sorted(ips_candidatas, key=ipaddress.ip_address):
        if ip == interfaz.ip:
            continue
        if ip not in hosts_validos and ip != interfaz.puerta_enlace:
            continue
        metadatos = vecinos.get(ip, {"mac": None, "state": "REACHABLE" if ip in respondedores_ping else "UNKNOWN"})
        datos_nmap = hallazgos_nmap.get(ip, {})
        estado = str(metadatos.get("state") or "").upper()
        if estado in {"FAILED", "INCOMPLETE", "NOARP", "UNREACHABLE"}:
            continue

        nombre_host, fuente_hostname = resolver_nombre_host(ip)
        if not nombre_host and datos_nmap.get("hostname"):
            nombre_host = str(datos_nmap["hostname"])
            fuente_hostname = "nmap"

        puertos_abiertos = list(datos_nmap.get("puertos") or [])
        if not puertos_abiertos:
            puertos_abiertos = await escanear_puertos(ip, puertos, tiempo_espera_puerto, concurrencia_puertos)

        mac = metadatos.get("mac") or datos_nmap.get("mac")
        fabricante = resolver_fabricante_mac(mac) or (str(datos_nmap.get("fabricante")) if datos_nmap.get("fabricante") else None)
        notas: list[str] = []
        if ip == interfaz.puerta_enlace:
            notas.append("Puerta de enlace predeterminada")
        if ip in respondedores_ping:
            notas.append("Respondió a ping")
        if any(datos_nmap.get(clave) for clave in ("hostname", "mac", "fabricante", "puertos", "servicios", "sistema_operativo")):
            notas.append("Datos enriquecidos con nmap")
        if datos_nmap.get("sistema_operativo"):
            notas.append(f"SO estimado por nmap: {datos_nmap['sistema_operativo']}")
        servicios_nmap = datos_nmap.get("servicios") or {}
        if servicios_nmap:
            resumen_servicios = ", ".join(
                f"{puerto}/{descripcion}" for puerto, descripcion in sorted(servicios_nmap.items())[:4]
            )
            resto_servicios = max(0, len(servicios_nmap) - 4)
            if resto_servicios:
                resumen_servicios = f"{resumen_servicios} +{resto_servicios}"
            notas.append(f"Servicios nmap: {resumen_servicios}")
        if nombre_host:
            notas.append(f"Nombre resuelto por {fuente_hostname}: {nombre_host}")
        if fabricante:
            notas.append(f"Fabricante estimado: {fabricante}")
        elif not mac:
            notas.append("MAC no disponible en la caché de vecinos")

        dispositivo = DispositivoRed(
            ip=ip,
            nombre_host=nombre_host,
            mac=mac,
            fabricante=fabricante,
            tipo_dispositivo="unknown",
            estado=str(metadatos.get("state") or datos_nmap.get("state") or "UNKNOWN"),
            puertos_abiertos=puertos_abiertos,
            notas=notas,
        )
        dispositivo.tipo_dispositivo = clasificar_dispositivo(dispositivo, interfaz.puerta_enlace)
        dispositivo.notas.append(f"Tipo estimado: {dispositivo.tipo_dispositivo}")
        dispositivos.append(dispositivo)

    return dispositivos


# Alias de compatibilidad.
ping_host = hacer_ping
prime_arp_cache = cebar_cache_arp
load_neighbors = cargar_vecinos
reverse_dns = resolver_dns_inverso
scan_port = escanear_puerto
scan_ports = escanear_puertos
discover_devices = descubrir_dispositivos
