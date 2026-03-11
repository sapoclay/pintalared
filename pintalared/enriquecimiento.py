from __future__ import annotations

from .modelos import DispositivoRed


PREFIJOS_POR_FABRICANTE = {
    "Apple": ["00:1B:63", "00:1C:B3", "00:1D:4F", "28:CF:E9", "3C:07:54", "40:A6:D9", "A4:5E:60", "F0:18:98"],
    "ASUSTek": ["00:1E:C2", "2C:56:DC", "30:85:A9", "50:46:5D", "74:D4:35", "AC:9E:17"],
    "AzureWave": ["18:03:73", "20:68:9D", "74:DA:38", "AC:1F:6B"],
    "Cisco": ["00:1D:A1", "00:25:45", "2C:54:2D", "58:97:1E", "84:B8:02", "C8:D7:19"],
    "Cisco Meraki": ["70:85:C2", "88:15:44", "E0:55:3D", "FC:FB:FB"],
    "Dell": ["00:14:22", "00:26:B9", "14:18:77", "64:00:6A", "B8:AC:6F", "F8:B1:56"],
    "Google": ["3C:5A:B4", "54:60:09", "94:EB:CD", "A4:BB:6D", "F4:F5:D8"],
    "Hewlett Packard": ["00:23:7D", "00:23:AE", "00:23:69", "3C:52:82", "9C:8E:99", "B4:99:BA"],
    "Huawei": ["48:4D:7E", "4C:54:99", "7C:B5:9B", "A4:2B:B0", "CC:96:A0"],
    "Intel": ["00:21:6A", "3C:A9:F4", "40:B0:34", "74:E5:43", "98:AF:65", "A0:36:BC"],
    "LCFC": ["28:D2:44", "60:6C:66", "6C:88:14", "C8:5B:76"],
    "Liteon": ["04:92:26", "34:23:87", "78:92:9C"],
    "Proxmox": ["BC:24:11"],
    "Raspberry Pi": ["28:CD:C1", "2C:CF:67", "B8:27:EB", "D8:3A:DD", "DC:A6:32", "E4:5F:01", "9C:B6:D0"],
    "Realtek": ["00:E0:4C", "52:54:00", "80:FA:5B", "B0:6E:BF"],
    "Ruckus": ["60:45:CB", "84:18:3A", "C0:C1:C0", "DC:A6:32"],
    "Samsung": ["08:FC:88", "34:BE:00", "8C:85:90", "B8:5A:73", "FC:C2:DE"],
    "Super Micro": ["00:25:90", "0C:C4:7A", "3C:EC:EF"],
    "TP-Link": ["10:FE:ED", "14:CC:20", "50:C7:BF", "D8:3A:DD", "E0:63:DA", "F4:F2:6D"],
    "Ubiquiti": ["00:15:6D", "00:1A:2B", "24:A4:3C", "68:D7:9A", "74:83:C2", "78:8A:20"],
    "VMware": ["00:05:69", "00:0C:29", "00:1C:14", "00:50:56"],
    "Xiaomi": ["28:6C:07", "34:CE:00", "64:09:80", "5C:51:4F", "78:11:DC", "F0:B4:29"],
}


def construir_mapa_oui() -> dict[str, str]:
    mapa: dict[str, str] = {}
    for fabricante, prefijos in PREFIJOS_POR_FABRICANTE.items():
        for prefijo in prefijos:
            mapa[prefijo] = fabricante
    return mapa


MAPA_OUI = construir_mapa_oui()


def normalizar_prefijo_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    saneada = mac.strip().upper().replace("-", ":")
    partes = saneada.split(":")
    if len(partes) < 3:
        return None
    return ":".join(partes[:3])


def resolver_fabricante_mac(mac: str | None) -> str | None:
    prefijo = normalizar_prefijo_mac(mac)
    if not prefijo:
        return None
    return MAPA_OUI.get(prefijo)


def clasificar_dispositivo(dispositivo: DispositivoRed, puerta_enlace: str | None = None) -> str:
    nombre_host = (dispositivo.nombre_host or "").lower()
    puertos = set(dispositivo.puertos_abiertos)

    if puerta_enlace and dispositivo.ip == puerta_enlace:
        return "router"
    if any(token in nombre_host for token in ("printer", "epson", "xerox", "canon")) or {515, 631, 9100} & puertos:
        return "printer"
    if any(token in nombre_host for token in ("switch", "router", "firewall", "gateway", "gw")) or {53, 67, 68, 161, 179} & puertos:
        return "network"
    if any(token in nombre_host for token in ("nas", "srv", "server", "db", "mail", "web")) or {22, 80, 443, 3306, 5432, 8080, 8443} & puertos:
        return "server"
    if any(token in nombre_host for token in ("cam", "camera", "cctv")) or {554, 8554} & puertos:
        return "camera"
    if any(token in nombre_host for token in ("phone", "android", "iphone", "ipad", "mobile")):
        return "mobile"
    if any(token in nombre_host for token in ("pc", "laptop", "desktop", "workstation", "notebook")) or {139, 445, 3389} & puertos:
        return "workstation"
    return "unknown"


# Alias de compatibilidad.
OUI_VENDOR_MAP = MAPA_OUI
normalize_mac_prefix = normalizar_prefijo_mac
resolve_mac_vendor = resolver_fabricante_mac
classify_device = clasificar_dispositivo
