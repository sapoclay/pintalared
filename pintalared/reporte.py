from __future__ import annotations

import csv
from pathlib import Path

from .modelos import DeviceInfo, FiltrosDispositivos, ScanArtifacts


def describir_cobertura_dispositivo(dispositivo: DeviceInfo) -> str:
    """Resume la calidad del inventario visible para un dispositivo."""
    notas = list(dispositivo.notes)
    if any(
        nota.startswith(prefijo)
        for prefijo in (
            "Servicios nmap:",
            "SO estimado por nmap:",
            "Nombre resuelto por nmap:",
        )
        for nota in notas
    ):
        return "enriquecido"

    piezas_visibles = sum(
        1
        for valor in (
            dispositivo.hostname,
            dispositivo.vendor,
            dispositivo.mac,
            dispositivo.open_ports,
        )
        if valor
    )
    if dispositivo.device_type == "unknown" and piezas_visibles <= 1:
        return "limitado"
    if piezas_visibles <= 1:
        return "limitado"
    return "basico"


def iterar_filas_dispositivos(artefactos: ScanArtifacts):
    """Aplana el resultado del escaneo para reutilizarlo en la GUI y en CSV."""
    for red, dispositivos in artefactos.snapshot.devices_by_network.items():
        for dispositivo in dispositivos:
            yield {
                "red": red,
                "ip": dispositivo.ip,
                "hostname": dispositivo.hostname or "",
                "cobertura": describir_cobertura_dispositivo(dispositivo),
                "tipo": dispositivo.device_type,
                "fabricante": dispositivo.vendor or "",
                "mac": dispositivo.mac or "",
                "puertos": ", ".join(str(port) for port in dispositivo.open_ports),
                "puertos_lista": list(dispositivo.open_ports),
                "estado": dispositivo.state,
                "notas": " | ".join(dispositivo.notes),
            }


def _coincide_puertos(dispositivo: DeviceInfo, filtro_puertos: str) -> bool:
    if not filtro_puertos.strip():
        return True

    objetivos: set[int] = set()
    for token in filtro_puertos.split(","):
        texto = token.strip()
        if not texto:
            continue
        objetivos.add(int(texto))

    if not objetivos:
        return True

    return any(puerto in objetivos for puerto in dispositivo.open_ports)


def filtrar_dispositivos(artefactos: ScanArtifacts, filtros: FiltrosDispositivos) -> list[dict[str, str | list[int]]]:
    """Devuelve solo los equipos visibles según red, tipo y puertos solicitados."""
    filas: list[dict[str, str | list[int]]] = []

    for red, dispositivos in artefactos.snapshot.devices_by_network.items():
        if filtros.red != "Todas" and red != filtros.red:
            continue

        for dispositivo in dispositivos:
            if filtros.tipo != "Todos" and dispositivo.device_type != filtros.tipo:
                continue
            if not _coincide_puertos(dispositivo, filtros.puertos):
                continue

            filas.append(
                {
                    "red": red,
                    "ip": dispositivo.ip,
                    "hostname": dispositivo.hostname or "-",
                    "cobertura": describir_cobertura_dispositivo(dispositivo),
                    "tipo": dispositivo.device_type,
                    "fabricante": dispositivo.vendor or "-",
                    "mac": dispositivo.mac or "-",
                    "puertos": ", ".join(str(port) for port in dispositivo.open_ports) or "sin puertos detectados en este escaneo",
                    "estado": dispositivo.state,
                    "notas": " | ".join(dispositivo.notes) or "-",
                }
            )

    return filas


def exportar_csv(ruta_csv: Path, filas: list[dict[str, str | list[int]]]) -> Path:
    """Genera un CSV con las filas visibles en la interfaz o calculadas por la CLI."""
    ruta_csv.parent.mkdir(parents=True, exist_ok=True)
    columnas = ["red", "ip", "hostname", "cobertura", "tipo", "fabricante", "mac", "puertos", "estado", "notas"]

    with ruta_csv.open("w", newline="", encoding="utf-8") as descriptor:
        escritor = csv.DictWriter(descriptor, fieldnames=columnas)
        escritor.writeheader()
        for fila in filas:
            escritor.writerow({columna: fila.get(columna, "") for columna in columnas})

    return ruta_csv
