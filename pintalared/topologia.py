from __future__ import annotations

import html
import json
import textwrap
from dataclasses import asdict
from typing import Any

from .modelos import InstantaneaEscaneo


def _resumir_puertos(puertos: list[int]) -> str:
    if not puertos:
        return "sin puertos detectados"
    if len(puertos) <= 4:
        return ", ".join(str(puerto) for puerto in puertos)
    visibles = ", ".join(str(puerto) for puerto in puertos[:4])
    return f"{visibles} +{len(puertos) - 4}"


def _extraer_nota_prefijo(dispositivo, prefijo: str) -> str | None:
    for nota in dispositivo.notas:
        if nota.startswith(prefijo):
            return nota[len(prefijo):].strip()
    return None


def _resumir_servicios_visibles(dispositivo) -> str | None:
    servicios = _extraer_nota_prefijo(dispositivo, "Servicios nmap:")
    if not servicios:
        return None
    if len(servicios) <= 28:
        return servicios
    return f"{servicios[:25].rstrip()}..."


def _etiqueta_dispositivo(dispositivo) -> str:
    lineas: list[str] = []
    nombre_principal = dispositivo.nombre_host if dispositivo.nombre_host and dispositivo.nombre_host != dispositivo.ip else dispositivo.ip
    lineas.append(nombre_principal)
    if nombre_principal != dispositivo.ip:
        lineas.append(dispositivo.ip)

    tipo = dispositivo.tipo_dispositivo if dispositivo.tipo_dispositivo != "unknown" else "equipo"
    resumen_puertos = _resumir_puertos(dispositivo.puertos_abiertos)
    lineas.append(f"{tipo} | {resumen_puertos}")
    resumen_servicios = _resumir_servicios_visibles(dispositivo)
    if resumen_servicios:
        lineas.append(f"srv: {resumen_servicios}")
    return "\n".join(lineas)


def construir_payload_topologia(host_analizador: str, interfaces, dispositivos_por_red, ip_publica: str | None = None) -> dict[str, Any]:
    """Construye nodos y aristas para representar la topología inferida."""
    nodos: list[dict[str, Any]] = []
    aristas: list[dict[str, Any]] = []

    nodos.append(
        {
            "id": "scanner",
            "label": host_analizador,
            "group": "scanner",
            "title": f"Equipo que ejecuta el analisis: {host_analizador}",
        }
    )

    id_nodo_ip_publica = f"public-ip:{ip_publica}" if ip_publica else None

    for interfaz in interfaces:
        id_red = f"network:{interfaz.red}"
        id_interfaz = f"interface:{interfaz.nombre}:{interfaz.ip}"
        dispositivos = dispositivos_por_red.get(interfaz.red, [])
        id_gateway_conectado: str | None = None

        nodos.append(
            {
                "id": id_interfaz,
                "label": f"{interfaz.nombre}\n{interfaz.ip}/{interfaz.longitud_prefijo}",
                "group": "interface",
                "title": textwrap.dedent(
                    f"""
                    Interfaz: {interfaz.nombre}
                    IP: {interfaz.ip}
                    Mascara: {interfaz.mascara_red}
                    Red: {interfaz.red}
                    MAC: {interfaz.mac or 'desconocida'}
                    Gateway: {interfaz.puerta_enlace or 'no detectado'}
                    """
                ).strip(),
            }
        )
        nodos.append({"id": id_red, "label": interfaz.red, "group": "network", "title": f"Segmento {interfaz.red}"})
        aristas.append({"from": "scanner", "to": id_interfaz})
        aristas.append({"from": id_interfaz, "to": id_red})

        for dispositivo in dispositivos:
            id_dispositivo = f"device:{dispositivo.ip}"
            texto_puertos = ", ".join(str(puerto) for puerto in dispositivo.puertos_abiertos) or "sin puertos detectados en este escaneo"
            texto_servicios = _extraer_nota_prefijo(dispositivo, "Servicios nmap:") or "sin identificar"
            texto_so = _extraer_nota_prefijo(dispositivo, "SO estimado por nmap:") or "sin identificar"
            texto_notas = "\n".join(dispositivo.notas) if dispositivo.notas else "Sin notas"
            es_gateway = interfaz.puerta_enlace and dispositivo.ip == interfaz.puerta_enlace
            grupo = dispositivo.tipo_dispositivo if dispositivo.tipo_dispositivo != "unknown" else ("gateway" if es_gateway else "device")
            if es_gateway:
                id_gateway_conectado = id_dispositivo
            nodos.append(
                {
                    "id": id_dispositivo,
                    "label": _etiqueta_dispositivo(dispositivo),
                    "group": grupo,
                    "title": textwrap.dedent(
                        f"""
                        IP: {dispositivo.ip}
                        Hostname: {dispositivo.nombre_host or 'desconocido'}
                        Tipo: {dispositivo.tipo_dispositivo}
                        Fabricante: {dispositivo.fabricante or 'desconocido'}
                        MAC: {dispositivo.mac or 'desconocida'}
                        Estado ARP: {dispositivo.estado}
                        Puertos abiertos: {texto_puertos}
                        Servicios detectados: {texto_servicios}
                        SO estimado: {texto_so}
                        Notas: {texto_notas}
                        """
                    ).strip(),
                }
            )
            aristas.append({"from": id_red, "to": id_dispositivo})

        if interfaz.puerta_enlace and not any(dispositivo.ip == interfaz.puerta_enlace for dispositivo in dispositivos):
            id_gateway = f"gateway:{interfaz.puerta_enlace}"
            id_gateway_conectado = id_gateway
            nodos.append(
                {
                    "id": id_gateway,
                    "label": f"Gateway\n{interfaz.puerta_enlace}",
                    "group": "gateway",
                    "title": f"Puerta de enlace predeterminada: {interfaz.puerta_enlace}",
                }
            )
            aristas.append({"from": id_red, "to": id_gateway})

        if id_nodo_ip_publica and id_gateway_conectado:
            nodos.append(
                {
                    "id": id_nodo_ip_publica,
                    "label": f"IP publica\n{ip_publica}",
                    "group": "internet",
                    "title": textwrap.dedent(
                        f"""
                        IP pública visible desde Internet: {ip_publica}
                        Esta dirección se consulta externamente y representa la salida pública de la red.
                        """
                    ).strip(),
                }
            )
            aristas.append({"from": id_gateway_conectado, "to": id_nodo_ip_publica})

    unicos_nodos = {nodo["id"]: nodo for nodo in nodos}
    unicas_aristas = {(arista["from"], arista["to"]): arista for arista in aristas}
    return {"nodes": list(unicos_nodos.values()), "edges": list(unicas_aristas.values())}


def renderizar_svg_topologia(topologia: dict[str, Any]) -> str:
    """Genera una vista SVG estática como respaldo sin dependencias externas."""
    nodos = topologia.get("nodes", [])
    aristas = topologia.get("edges", [])
    if not nodos:
        return "<p>No hay nodos disponibles para representar la topología.</p>"

    colores = {
        "scanner": "#0f766e",
        "interface": "#2563eb",
        "network": "#84cc16",
        "gateway": "#f59e0b",
        "router": "#f59e0b",
        "internet": "#1d4ed8",
        "device": "#ef4444",
        "server": "#a78bfa",
        "printer": "#2dd4bf",
        "camera": "#22c55e",
        "mobile": "#38bdf8",
        "workstation": "#fb7185",
        "unknown": "#ef4444",
    }

    indice_por_id = {nodo["id"]: nodo for nodo in nodos}
    scanner = next((nodo for nodo in nodos if nodo.get("group") == "scanner"), None)
    interfaces = [nodo for nodo in nodos if nodo.get("group") == "interface"]
    redes = [nodo for nodo in nodos if nodo.get("group") == "network"]
    publicas = [nodo for nodo in nodos if nodo.get("group") == "internet"]
    resto = [
        nodo for nodo in nodos
        if nodo.get("group") not in {"scanner", "interface", "network", "internet"}
    ]

    posiciones: dict[str, tuple[int, int]] = {}
    ancho = 1580
    margen_x = 70
    x_scanner = margen_x + 60
    x_interfaz = 280
    x_red = 560
    columnas_dispositivos = [860, 1120]
    x_publica = 1420
    separacion_bloque = 320
    base_y = 150

    if scanner is not None:
        posiciones[scanner["id"]] = (x_scanner, base_y)

    redes_por_id = {nodo["id"]: nodo for nodo in redes}
    interfaces_por_red: dict[str, list[dict[str, Any]]] = {nodo["id"]: [] for nodo in redes}
    dispositivos_por_red: dict[str, list[dict[str, Any]]] = {nodo["id"]: [] for nodo in redes}

    for arista in aristas:
        origen = arista.get("from")
        destino = arista.get("to")
        if origen in interfaces_por_red and destino in indice_por_id and indice_por_id[destino].get("group") == "interface":
            interfaces_por_red[origen].append(indice_por_id[destino])
        if destino in interfaces_por_red and origen in indice_por_id and indice_por_id[origen].get("group") == "interface":
            interfaces_por_red[destino].append(indice_por_id[origen])
        if origen in dispositivos_por_red and destino in indice_por_id and indice_por_id[destino].get("group") not in {"scanner", "interface", "network"}:
            dispositivos_por_red[origen].append(indice_por_id[destino])
        if destino in dispositivos_por_red and origen in indice_por_id and indice_por_id[origen].get("group") not in {"scanner", "interface", "network"}:
            dispositivos_por_red[destino].append(indice_por_id[origen])

    if not redes:
        redes = [{"id": "sin-red", "label": "Sin red", "group": "network", "title": "Sin red"}]
        interfaces_por_red = {"sin-red": interfaces}
        dispositivos_por_red = {"sin-red": resto}

    for indice_red, red in enumerate(redes):
        y_red = base_y + indice_red * separacion_bloque
        posiciones[red["id"]] = (x_red, y_red)

        interfaces_red = interfaces_por_red.get(red["id"], [])
        if interfaces_red:
            for desplazamiento, interfaz in enumerate(interfaces_red):
                y_interfaz = y_red + (desplazamiento - (len(interfaces_red) - 1) / 2) * 70
                posiciones[interfaz["id"]] = (x_interfaz, int(y_interfaz))

        dispositivos_red = dispositivos_por_red.get(red["id"], [])
        if dispositivos_red:
            for desplazamiento, dispositivo in enumerate(dispositivos_red):
                indice_columna = desplazamiento % len(columnas_dispositivos)
                indice_fila = desplazamiento // len(columnas_dispositivos)
                total_filas = (len(dispositivos_red) + len(columnas_dispositivos) - 1) // len(columnas_dispositivos)
                desplazamiento_vertical = (indice_fila - (total_filas - 1) / 2) * 112
                x_dispositivo = columnas_dispositivos[indice_columna]
                y_dispositivo = y_red + desplazamiento_vertical
                posiciones[dispositivo["id"]] = (x_dispositivo, int(y_dispositivo))

    for indice_interfaz, interfaz in enumerate(interfaces):
        posiciones.setdefault(interfaz["id"], (x_interfaz, base_y + indice_interfaz * 80))
    for indice_dispositivo, dispositivo in enumerate(resto):
        columna = columnas_dispositivos[indice_dispositivo % len(columnas_dispositivos)]
        fila = indice_dispositivo // len(columnas_dispositivos)
        posiciones.setdefault(dispositivo["id"], (columna, base_y + fila * 112))

    ids_publicas = {nodo["id"] for nodo in publicas}
    for arista in aristas:
        origen = arista.get("from")
        destino = arista.get("to")
        if origen in posiciones and destino in ids_publicas:
            posiciones[destino] = (x_publica, posiciones[origen][1])
        if destino in posiciones and origen in ids_publicas:
            posiciones[origen] = (x_publica, posiciones[destino][1])

    for indice_publica, nodo_publico in enumerate(publicas):
        posiciones.setdefault(nodo_publico["id"], (x_publica, base_y + indice_publica * 120))

    min_y = min(y for _, y in posiciones.values())
    if min_y < 90:
        desplazamiento_global = 90 - min_y
        posiciones = {identificador: (x, y + desplazamiento_global) for identificador, (x, y) in posiciones.items()}

    alto = max(y for _, y in posiciones.values()) + 150
    segmentos: list[str] = [
        f'<svg id="topologia-svg" viewBox="0 0 {ancho} {alto}" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">',
        '<rect width="100%" height="100%" fill="#ffffff" rx="24" ry="24"/>',
        '<g id="topologia-aristas">',
    ]

    for arista in aristas:
        origen = arista.get("from")
        destino = arista.get("to")
        if origen not in posiciones or destino not in posiciones:
            continue
        x1, y1 = posiciones[origen]
        x2, y2 = posiciones[destino]
        segmentos.append(
            f'<line data-from="{html.escape(str(origen))}" data-to="{html.escape(str(destino))}" '
            f'x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#7aa98f" stroke-width="2.5" opacity="0.9" />'
        )

    segmentos.append('</g><g id="topologia-nodos">')

    for nodo in nodos:
        if nodo["id"] not in posiciones:
            continue
        x, y = posiciones[nodo["id"]]
        grupo = str(nodo.get("group") or "device")
        color = colores.get(grupo, "#ef4444")
        etiqueta = html.escape(str(nodo.get("label") or nodo["id"]))
        titulo = html.escape(str(nodo.get("title") or nodo.get("label") or nodo["id"]))
        lineas = etiqueta.split("\n")
        radio = 34 if grupo in {"scanner", "router", "gateway", "internet"} else 26
        segmentos.append(
            f'<g class="topologia-nodo" data-node-id="{html.escape(str(nodo["id"]))}" '
            f'data-node-label="{html.escape(str(nodo.get("label") or nodo["id"]))}" '
            f'data-node-title="{html.escape(str(nodo.get("title") or nodo.get("label") or nodo["id"]))}" '
            f'data-x="{x}" data-y="{y}" transform="translate({x} {y})">'
            f'<title>{titulo}</title>'
        )
        segmentos.append(
            f'<circle cx="0" cy="0" r="{radio}" fill="{color}" stroke="#183026" stroke-width="2" />'
        )
        for indice_linea, linea in enumerate(lineas):
            desplazamiento = 10 + indice_linea * 18
            segmentos.append(
                f'<text x="0" y="{radio + desplazamiento}" text-anchor="middle" '
                f'font-family="IBM Plex Sans, Segoe UI, sans-serif" font-size="15" fill="#183026">{linea}</text>'
            )
        segmentos.append('</g>')

    segmentos.append("</g></svg>")
    return "".join(segmentos)


def renderizar_html_topologia(topologia: dict[str, Any], nombre_json_salida: str) -> str:
    """Genera la página HTML interactiva de la topología."""
    svg_respaldo = renderizar_svg_topologia(topologia)
    return f"""<!DOCTYPE html>
<html lang=\"es\">
<head>
  <meta charset=\"UTF-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />
  <title>PintalaRED</title>
  <style>
    :root {{ color-scheme: light; --bg: #eff6f2; --panel: rgba(255,255,255,0.9); --line: #7aa98f; --text: #183026; --accent: #1e6f50; --soft: #dcebe2; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; min-height: 100vh; font-family: \"IBM Plex Sans\", \"Segoe UI\", sans-serif; color: var(--text); background: radial-gradient(circle at top left, rgba(30,111,80,0.22), transparent 30%), radial-gradient(circle at right, rgba(77,166,124,0.18), transparent 22%), linear-gradient(135deg, #f6fbf8, var(--bg)); display: grid; grid-template-columns: minmax(280px, 360px) 1fr; gap: 18px; padding: 18px; }}
    aside {{ background: var(--panel); border: 1px solid rgba(24,48,38,0.08); border-radius: 20px; padding: 22px; backdrop-filter: blur(12px); box-shadow: 0 18px 40px rgba(24,48,38,0.08); }}
    h1 {{ margin: 0 0 10px; font-size: 1.7rem; line-height: 1.1; }}
    p {{ line-height: 1.5; font-size: 0.95rem; }}
    .pill {{ display: inline-block; padding: 6px 10px; border-radius: 999px; background: var(--soft); color: var(--accent); font-weight: 600; font-size: 0.82rem; margin-bottom: 14px; }}
    .legend {{ display: grid; gap: 8px; margin: 18px 0; }}
    .legend-item {{ display: flex; align-items: center; gap: 10px; }}
    .swatch {{ width: 14px; height: 14px; border-radius: 50%; box-shadow: inset 0 0 0 1px rgba(0,0,0,0.08); }}
                .network-panel {{ min-height: calc(100vh - 36px); border-radius: 24px; background: rgba(255,255,255,0.72); border: 1px solid rgba(24,48,38,0.08); box-shadow: inset 0 1px 0 rgba(255,255,255,0.65), 0 20px 45px rgba(24,48,38,0.09); padding: 18px; overflow: auto; display: grid; grid-template-columns: minmax(0, 1fr) 320px; gap: 16px; align-items: start; }}
                .topologia-canvas {{ min-width: 0; }}
        .network-panel svg {{ width: 100%; height: auto; display: block; }}
        .topologia-nodo {{ cursor: grab; user-select: none; }}
                .topologia-nodo.seleccionado circle {{ stroke: #0b3b2c; stroke-width: 4; }}
        .topologia-nodo.arrastrando {{ cursor: grabbing; }}
        .topologia-nodo text {{ pointer-events: none; font-weight: 600; }}
                .detalle-panel {{ position: sticky; top: 0; border-radius: 18px; background: rgba(247, 251, 248, 0.96); border: 1px solid rgba(24,48,38,0.08); padding: 16px; box-shadow: inset 0 1px 0 rgba(255,255,255,0.7); }}
                .detalle-panel h2 {{ margin: 0 0 8px; font-size: 1.05rem; }}
                .detalle-panel .detalle-subtitulo {{ margin: 0 0 12px; color: #416354; font-size: 0.9rem; }}
                .detalle-vacio {{ margin: 0; white-space: pre-wrap; word-break: break-word; font-family: "IBM Plex Mono", monospace; font-size: 0.84rem; line-height: 1.45; color: #173227; background: rgba(220,235,226,0.56); padding: 12px; border-radius: 12px; }}
                .detalle-secciones {{ display: grid; gap: 12px; }}
                .detalle-bloque {{ background: rgba(220,235,226,0.42); border-radius: 12px; padding: 12px; }}
                .detalle-bloque h3 {{ margin: 0 0 8px; font-size: 0.9rem; color: #0f3a2b; }}
                .detalle-linea {{ display: grid; grid-template-columns: 108px 1fr; gap: 8px; font-size: 0.84rem; line-height: 1.4; padding: 2px 0; }}
                .detalle-clave {{ color: #416354; font-weight: 700; }}
                .detalle-valor {{ color: #173227; word-break: break-word; }}
        .fallback-note {{ margin-top: 10px; font-size: 0.92rem; color: #365647; }}
    code {{ font-family: \"IBM Plex Mono\", monospace; font-size: 0.9rem; background: rgba(220,235,226,0.9); padding: 2px 6px; border-radius: 6px; }}
                @media (max-width: 960px) {{ body {{ grid-template-columns: 1fr; }} .network-panel {{ min-height: 70vh; grid-template-columns: 1fr; }} .detalle-panel {{ position: static; }} }}
  </style>
</head>
<body>
  <aside>
    <span class=\"pill\">PintalaRED</span>
    <h1>Topología detectada</h1>
    <p>El gráfico representa la red vista desde el equipo que ejecutó el escaneo. La topología es inferida a partir de interfaces locales, gateway, tabla ARP y puertos detectados.</p>
    <div class=\"legend\">
      <div class=\"legend-item\"><span class=\"swatch\" style=\"background:#0f766e\"></span>Equipo analizador</div>
      <div class=\"legend-item\"><span class=\"swatch\" style=\"background:#2563eb\"></span>Interfaz local</div>
      <div class=\"legend-item\"><span class=\"swatch\" style=\"background:#84cc16\"></span>Segmento de red</div>
    <div class=\"legend-item\"><span class=\"swatch\" style=\"background:#f59e0b\"></span>Gateway o router</div>
    <div class=\"legend-item\"><span class=\"swatch\" style=\"background:#1d4ed8\"></span>IP pública</div>
    <div class=\"legend-item\"><span class=\"swatch\" style=\"background:#ef4444\"></span>Equipo genérico</div>
      <div class=\"legend-item\"><span class=\"swatch\" style=\"background:#a78bfa\"></span>Servidor</div>
      <div class=\"legend-item\"><span class=\"swatch\" style=\"background:#2dd4bf\"></span>Impresora</div>
      <div class=\"legend-item\"><span class=\"swatch\" style=\"background:#22c55e\"></span>Cámara</div>
    </div>
        <p>La vista es completamente local y no depende de librerías externas. Coloca el cursor sobre cada nodo para ver más detalles del dispositivo y arrástralo para recolocarlo. Si hay conectividad a Internet, se intenta mostrar también la IP pública detrás del gateway.</p>
    <p>Los datos estructurados completos se guardaron en <code>{nombre_json_salida}</code>.</p>
  </aside>
    <main class=\"network-panel\">
        <section class=\"topologia-canvas\">{svg_respaldo}
                <p class=\"fallback-note\">Vista local de topología generada sin dependencias externas. Las etiquetas muestran nombre o IP, tipo estimado, puertos y, cuando nmap aporta datos, un resumen corto de servicios detectados. Puedes arrastrar los nodos para reorganizar la vista.</p>
        </section>
        <aside class=\"detalle-panel\" id=\"detalle-panel\">
            <h2>Detalle del nodo</h2>
            <p class=\"detalle-subtitulo\" id=\"detalle-subtitulo\">Haz clic en un nodo para ver su información completa.</p>
            <div class=\"detalle-vacio\" id=\"detalle-contenido\">Selecciona un equipo, interfaz, segmento o gateway para ver aquí sus detalles.</div>
        </aside>
    </main>
    <script>
        (() => {{
            const svg = document.getElementById('topologia-svg');
            if (!svg) return;

            const nodos = Array.from(svg.querySelectorAll('.topologia-nodo'));
            const aristas = Array.from(svg.querySelectorAll('#topologia-aristas line'));
            const posiciones = new Map();
            const detalleSubtitulo = document.getElementById('detalle-subtitulo');
            const detalleContenido = document.getElementById('detalle-contenido');
            let nodoSeleccionado = null;

            const escaparHtml = (texto) => String(texto)
                .replaceAll('&', '&amp;')
                .replaceAll('<', '&lt;')
                .replaceAll('>', '&gt;')
                .replaceAll('"', '&quot;')
                .replaceAll("'", '&#39;');

            const construirBloque = (titulo, entradas) => {{
                if (!entradas.length) return '';
                const filas = entradas.map(([clave, valor]) => `
                    <div class="detalle-linea">
                        <div class="detalle-clave">${{escaparHtml(clave)}}</div>
                        <div class="detalle-valor">${{escaparHtml(valor)}}</div>
                    </div>
                `).join('');
                return `
                    <section class="detalle-bloque">
                        <h3>${{escaparHtml(titulo)}}</h3>
                        ${{filas}}
                    </section>
                `;
            }};

            const renderizarDetalle = (textoPlano) => {{
                if (!detalleContenido) return;
                const lineas = String(textoPlano || '')
                    .split('\\n')
                    .map((linea) => linea.trim())
                    .filter(Boolean);
                if (!lineas.length) {{
                    detalleContenido.className = 'detalle-vacio';
                    detalleContenido.textContent = 'Sin detalles';
                    return;
                }}

                const grupos = {{
                    'Identidad': [],
                    'Red': [],
                    'Puertos': [],
                    'Servicios': [],
                    'Notas': [],
                    'Otros': [],
                }};

                for (const linea of lineas) {{
                    const separador = linea.indexOf(':');
                    if (separador === -1) {{
                        grupos['Otros'].push(['Detalle', linea]);
                        continue;
                    }}
                    const clave = linea.slice(0, separador).trim();
                    const valor = linea.slice(separador + 1).trim() || '-';
                    const claveNormalizada = clave.toLowerCase();

                    if (['hostname', 'tipo', 'fabricante', 'so estimado'].includes(claveNormalizada)) {{
                        grupos['Identidad'].push([clave, valor]);
                    }} else if (['ip', 'interfaz', 'red', 'mascara', 'gateway', 'mac', 'estado arp', 'puerta de enlace predeterminada'].includes(claveNormalizada)) {{
                        grupos['Red'].push([clave, valor]);
                    }} else if (claveNormalizada === 'puertos abiertos') {{
                        grupos['Puertos'].push([clave, valor]);
                    }} else if (claveNormalizada === 'servicios detectados') {{
                        grupos['Servicios'].push([clave, valor]);
                    }} else if (claveNormalizada === 'notas') {{
                        for (const nota of valor.split(/\\s*\\n\\s*/)) {{
                            if (nota.trim()) grupos['Notas'].push(['Nota', nota.trim()]);
                        }}
                    }} else {{
                        grupos['Otros'].push([clave, valor]);
                    }}
                }}

                const html = [
                    construirBloque('Identidad', grupos['Identidad']),
                    construirBloque('Red', grupos['Red']),
                    construirBloque('Puertos', grupos['Puertos']),
                    construirBloque('Servicios', grupos['Servicios']),
                    construirBloque('Notas', grupos['Notas']),
                    construirBloque('Otros', grupos['Otros']),
                ].filter(Boolean).join('');

                detalleContenido.className = 'detalle-secciones';
                detalleContenido.innerHTML = html || '<div class="detalle-vacio">Sin detalles estructurados.</div>';
            }};

            const seleccionarNodo = (nodo) => {{
                if (nodoSeleccionado) nodoSeleccionado.classList.remove('seleccionado');
                nodoSeleccionado = nodo;
                nodoSeleccionado.classList.add('seleccionado');
                if (detalleSubtitulo) detalleSubtitulo.textContent = nodo.dataset.nodeLabel || nodo.dataset.nodeId || 'Nodo';
                renderizarDetalle(nodo.dataset.nodeTitle || 'Sin detalles');
            }};

            for (const nodo of nodos) {{
                posiciones.set(nodo.dataset.nodeId, {{
                    x: Number(nodo.dataset.x || 0),
                    y: Number(nodo.dataset.y || 0),
                }});
            }}

            const actualizarAristas = () => {{
                for (const arista of aristas) {{
                    const desde = posiciones.get(arista.dataset.from);
                    const hasta = posiciones.get(arista.dataset.to);
                    if (!desde || !hasta) continue;
                    arista.setAttribute('x1', String(desde.x));
                    arista.setAttribute('y1', String(desde.y));
                    arista.setAttribute('x2', String(hasta.x));
                    arista.setAttribute('y2', String(hasta.y));
                }}
            }};

            const puntoSvg = (clientX, clientY) => {{
                const punto = svg.createSVGPoint();
                punto.x = clientX;
                punto.y = clientY;
                const matriz = svg.getScreenCTM();
                return matriz ? punto.matrixTransform(matriz.inverse()) : {{ x: clientX, y: clientY }};
            }};

            let arrastre = null;

            const mover = (evento) => {{
                if (!arrastre) return;
                evento.preventDefault();
                const punto = puntoSvg(evento.clientX, evento.clientY);
                const nuevaX = Math.max(60, Math.min(Number(svg.viewBox.baseVal.width) - 60, punto.x - arrastre.desfaseX));
                const nuevaY = Math.max(60, Math.min(Number(svg.viewBox.baseVal.height) - 60, punto.y - arrastre.desfaseY));
                posiciones.set(arrastre.id, {{ x: nuevaX, y: nuevaY }});
                arrastre.elemento.dataset.x = String(nuevaX);
                arrastre.elemento.dataset.y = String(nuevaY);
                arrastre.elemento.setAttribute('transform', `translate(${{nuevaX}} ${{nuevaY}})`);
                actualizarAristas();
            }};

            const terminar = () => {{
                if (!arrastre) return;
                arrastre.elemento.classList.remove('arrastrando');
                arrastre = null;
            }};

            for (const nodo of nodos) {{
                nodo.addEventListener('pointerdown', (evento) => {{
                    evento.preventDefault();
                    seleccionarNodo(nodo);
                    const posicion = posiciones.get(nodo.dataset.nodeId);
                    if (!posicion) return;
                    const punto = puntoSvg(evento.clientX, evento.clientY);
                    arrastre = {{
                        id: nodo.dataset.nodeId,
                        elemento: nodo,
                        desfaseX: punto.x - posicion.x,
                        desfaseY: punto.y - posicion.y,
                    }};
                    nodo.classList.add('arrastrando');
                    nodo.setPointerCapture(evento.pointerId);
                }});
            }}

            svg.addEventListener('pointermove', mover);
            svg.addEventListener('pointerup', terminar);
            svg.addEventListener('pointerleave', terminar);
            svg.addEventListener('pointercancel', terminar);
            actualizarAristas();
            if (nodos.length) seleccionarNodo(nodos[0]);
        }})();
    </script>
</body>
</html>
"""


def serializar_instantanea(instantanea: InstantaneaEscaneo) -> dict[str, Any]:
    """Convierte la instantánea en un diccionario serializable a JSON."""
    return {
        "generated_at": instantanea.generado_en,
        "scanner_host": instantanea.host_analizador,
        "platform": instantanea.plataforma,
        "interfaces": [asdict(interface) for interface in instantanea.interfaces],
        "devices_by_network": {
            red: [asdict(dispositivo) for dispositivo in dispositivos]
            for red, dispositivos in instantanea.dispositivos_por_red.items()
        },
        "topology_html": instantanea.topologia_html,
        "topology_json": instantanea.topologia_json,
        "public_ip": instantanea.ip_publica,
    }


# Alias de compatibilidad.
build_topology_payload = construir_payload_topologia
render_topology_html = renderizar_html_topologia
serialise_snapshot = serializar_instantanea
