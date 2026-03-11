from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class FiltrosDispositivos:
    red: str = "Todas"
    tipo: str = "Todos"
    puertos: str = ""


@dataclass(slots=True)
class InterfazRed:
    nombre: str
    ip: str
    longitud_prefijo: int
    mascara_red: str
    red: str
    difusion: str | None
    mac: str | None
    puerta_enlace: str | None = None

    @property
    def name(self) -> str:
        return self.nombre

    @property
    def prefix_length(self) -> int:
        return self.longitud_prefijo

    @property
    def netmask(self) -> str:
        return self.mascara_red

    @property
    def network(self) -> str:
        return self.red

    @property
    def broadcast(self) -> str | None:
        return self.difusion

    @property
    def gateway(self) -> str | None:
        return self.puerta_enlace


@dataclass(slots=True)
class DispositivoRed:
    ip: str
    nombre_host: str | None
    mac: str | None
    fabricante: str | None
    tipo_dispositivo: str
    estado: str
    puertos_abiertos: list[int] = field(default_factory=list)
    notas: list[str] = field(default_factory=list)

    @property
    def hostname(self) -> str | None:
        return self.nombre_host

    @property
    def vendor(self) -> str | None:
        return self.fabricante

    @property
    def device_type(self) -> str:
        return self.tipo_dispositivo

    @device_type.setter
    def device_type(self, value: str) -> None:
        self.tipo_dispositivo = value

    @property
    def state(self) -> str:
        return self.estado

    @property
    def open_ports(self) -> list[int]:
        return self.puertos_abiertos

    @property
    def notes(self) -> list[str]:
        return self.notas


@dataclass(slots=True)
class OpcionesEscaneo:
    interfaz: str | None = None
    puertos: str = "common"
    tiempo_espera_host: float = 1.0
    tiempo_espera_puerto: float = 0.35
    concurrencia_hosts: int = 128
    concurrencia_puertos: int = 256
    maximo_hosts: int = 512
    directorio_salida: str = "output"
    nombre_json: str = "network_report.json"
    nombre_html: str = "topologia_red.html"
    usar_nmap: bool = True
    instalar_nmap_si_falta: bool = False

    @property
    def interface(self) -> str | None:
        return self.interfaz

    @property
    def ports(self) -> str:
        return self.puertos

    @property
    def host_timeout(self) -> float:
        return self.tiempo_espera_host

    @property
    def port_timeout(self) -> float:
        return self.tiempo_espera_puerto

    @property
    def host_concurrency(self) -> int:
        return self.concurrencia_hosts

    @property
    def port_concurrency(self) -> int:
        return self.concurrencia_puertos

    @property
    def max_hosts(self) -> int:
        return self.maximo_hosts

    @property
    def output_dir(self) -> str:
        return self.directorio_salida

    @property
    def json_name(self) -> str:
        return self.nombre_json

    @property
    def html_name(self) -> str:
        return self.nombre_html

    @property
    def use_nmap(self) -> bool:
        return self.usar_nmap

    @property
    def install_nmap_if_missing(self) -> bool:
        return self.instalar_nmap_si_falta


@dataclass(slots=True)
class InstantaneaEscaneo:
    generado_en: str
    host_analizador: str
    plataforma: str
    interfaces: list[InterfazRed]
    dispositivos_por_red: dict[str, list[DispositivoRed]]
    topologia_html: str
    topologia_json: str
    ip_publica: str | None = None

    @property
    def generated_at(self) -> str:
        return self.generado_en

    @property
    def scanner_host(self) -> str:
        return self.host_analizador

    @property
    def platform(self) -> str:
        return self.plataforma

    @property
    def devices_by_network(self) -> dict[str, list[DispositivoRed]]:
        return self.dispositivos_por_red

    @property
    def public_ip(self) -> str | None:
        return self.ip_publica


@dataclass(slots=True)
class ArtefactosEscaneo:
    instantanea: InstantaneaEscaneo
    topologia: dict[str, object]
    ruta_html: Path
    ruta_json: Path
    ruta_csv: Path | None = None

    @property
    def snapshot(self) -> InstantaneaEscaneo:
        return self.instantanea

    @property
    def html_path(self) -> Path:
        return self.ruta_html

    @property
    def json_path(self) -> Path:
        return self.ruta_json

    @property
    def csv_path(self) -> Path | None:
        return self.ruta_csv


# Alias de compatibilidad con nombres antiguos.
FiltrosEquipos = FiltrosDispositivos
InterfaceInfo = InterfazRed
DeviceInfo = DispositivoRed
ScanOptions = OpcionesEscaneo
ScanSnapshot = InstantaneaEscaneo
ScanArtifacts = ArtefactosEscaneo
InformacionInterfaz = InterfazRed
InformacionDispositivo = DispositivoRed
