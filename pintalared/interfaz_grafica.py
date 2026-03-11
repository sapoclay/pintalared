from __future__ import annotations

import queue
import shutil
import subprocess
import threading
import webbrowser
from pathlib import Path
import os

from . import NOMBRE_APLICACION, VERSION_APLICACION
from .menu_superior import MenuSuperiorPintalaRED
from .modelos import ArtefactosEscaneo, FiltrosDispositivos, OpcionesEscaneo
from .reporte import exportar_csv, filtrar_dispositivos
from .servicio import ejecutar_escaneo, formatear_resumen, listar_interfaces
from .sistema import instalar_nmap, nmap_disponible
from .tooltips import TooltipInformativo

try:
	import tkinter as tk
	from tkinter import filedialog, messagebox, ttk
except ImportError as error:
	raise RuntimeError(
		"Tkinter no esta disponible. Instala python3-tk para usar la interfaz grafica de PintalaRED."
	) from error


class AplicacionPintalaRED:
	"""Interfaz de escritorio para ejecutar escaneos, filtrar equipos y exportar CSV."""

	def __init__(self, raiz: tk.Tk) -> None:
		self.raiz = raiz
		self.raiz.title(f"{NOMBRE_APLICACION} {VERSION_APLICACION}")
		self.raiz.geometry("1320x820")
		self.raiz.minsize(1100, 720)
		self.raiz.configure(bg="#edf4ef")

		# La cola permite actualizar la GUI desde el hilo de trabajo sin bloquear Tkinter.
		self.cola_resultados: queue.Queue[tuple[str, object]] = queue.Queue()
		self.hilo_escaneo: threading.Thread | None = None
		self.ultimo_resultado: ArtefactosEscaneo | None = None
		self.filas_filtradas: list[dict[str, str | list[int]]] = []
		self._tooltips: list[TooltipInformativo] = []

		self.var_interfaz = tk.StringVar(value="Todas")
		self.var_puertos = tk.StringVar(value="common")
		self.var_timeout_host = tk.StringVar(value="1.0")
		self.var_timeout_puerto = tk.StringVar(value="0.35")
		self.var_max_hosts = tk.StringVar(value="512")
		self.var_directorio_salida = tk.StringVar(value="output")
		self.var_estado = tk.StringVar(value="Listo para analizar la red")
		self.var_ip_publica = tk.StringVar(value="IP pública: pendiente de detectar")
		self.var_usar_nmap = tk.BooleanVar(value=True)

		self.var_filtro_red = tk.StringVar(value="Todas")
		self.var_filtro_tipo = tk.StringVar(value="Todos")
		self.var_filtro_puertos = tk.StringVar(value="")
		self.menu_superior = MenuSuperiorPintalaRED(self.raiz, self._obtener_directorio_salida)

		self._configurar_estilo()
		self.menu_superior.instalar()
		self._construir_diseno()
		self.refrescar_interfaces(inicial=True)
		self.raiz.after(150, self._procesar_cola)

	def _configurar_estilo(self) -> None:
		estilo = ttk.Style(self.raiz)
		estilo.theme_use("clam")
		estilo.configure("Panel.TFrame", background="#ffffff")
		estilo.configure("Shell.TFrame", background="#edf4ef")
		estilo.configure("Title.TLabel", background="#ffffff", foreground="#173227", font=("Segoe UI", 20, "bold"))
		estilo.configure("Muted.TLabel", background="#ffffff", foreground="#4f6b5c", font=("Segoe UI", 10))
		estilo.configure("Section.TLabel", background="#ffffff", foreground="#173227", font=("Segoe UI", 11, "bold"))
		estilo.configure("Action.TButton", font=("Segoe UI", 10, "bold"))
		estilo.configure("Treeview", rowheight=28)

	def _construir_diseno(self) -> None:
		contenedor = ttk.Frame(self.raiz, style="Shell.TFrame", padding=18)
		contenedor.pack(fill="both", expand=True)
		contenedor.columnconfigure(0, weight=0)
		contenedor.columnconfigure(1, weight=1)
		contenedor.rowconfigure(0, weight=1)

		panel_izquierdo = ttk.Frame(contenedor, style="Panel.TFrame", padding=18)
		panel_derecho = ttk.Frame(contenedor, style="Panel.TFrame", padding=18)
		panel_izquierdo.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
		panel_derecho.grid(row=0, column=1, sticky="nsew")
		panel_derecho.rowconfigure(3, weight=1)
		panel_derecho.columnconfigure(0, weight=1)

		ttk.Label(panel_izquierdo, text=NOMBRE_APLICACION, style="Title.TLabel").pack(anchor="w")
		ttk.Label(
			panel_izquierdo,
			text="Descubre equipos, filtra resultados y exporta el inventario desde una GUI local.",
			style="Muted.TLabel",
		).pack(anchor="w", pady=(4, 18))

		self._construir_controles(panel_izquierdo)
		self._construir_resultados(panel_derecho)

	def _construir_controles(self, parent: ttk.Frame) -> None:
		formulario = ttk.Frame(parent, style="Panel.TFrame")
		formulario.pack(fill="x")
		formulario.columnconfigure(1, weight=1)

		self.combo_interfaz = self._crear_campo(formulario, 0, "Interfaz", self.var_interfaz, combo=True)
		self._registrar_tooltip(self.combo_interfaz, "Elige la interfaz de red desde la que se realizará el inventario. Si dejas 'Todas', PintalaRED analizará todas las interfaces IPv4 activas detectadas.")
		entrada_puertos = self._crear_campo(formulario, 1, "Puertos", self.var_puertos)
		self._registrar_tooltip(entrada_puertos, "Define qué puertos TCP se comprobarán en cada equipo. Usa 'common', una lista como 22,80,443 o un rango como 1-1024.")
		entrada_timeout_ping = self._crear_campo(formulario, 2, "Timeout ping", self.var_timeout_host)
		self._registrar_tooltip(entrada_timeout_ping, "Tiempo máximo de espera del ping por host. Valores más altos detectan mejor equipos lentos, pero alargan el escaneo.")
		entrada_timeout_puerto = self._crear_campo(formulario, 3, "Timeout puerto", self.var_timeout_puerto)
		self._registrar_tooltip(entrada_timeout_puerto, "Tiempo máximo de espera por intento de conexión TCP. Si es demasiado bajo, algunos servicios pueden no detectarse.")
		entrada_max_hosts = self._crear_campo(formulario, 4, "Max hosts", self.var_max_hosts)
		self._registrar_tooltip(entrada_max_hosts, "Límite de seguridad del tamaño de subred a escanear. Auméntalo solo si sabes que necesitas barrer una red más grande.")
		entrada_directorio = self._crear_campo(formulario, 5, "Directorio salida", self.var_directorio_salida, with_browse=True)
		self._registrar_tooltip(entrada_directorio, "Carpeta donde se guardarán los archivos generados: informe JSON, CSV y topología HTML.")

		opciones_avanzadas = ttk.Frame(parent, style="Panel.TFrame")
		opciones_avanzadas.pack(fill="x", pady=(8, 0))
		check_nmap = ttk.Checkbutton(opciones_avanzadas, text="Usar nmap si está disponible", variable=self.var_usar_nmap)
		check_nmap.pack(anchor="w")
		self._registrar_tooltip(check_nmap, "Si nmap está instalado, PintalaRED lo usará para enriquecer hostnames, fabricantes, MAC y puertos. Si no está instalado, la aplicación puede ofrecer instalarlo antes del escaneo.")

		acciones = ttk.Frame(parent, style="Panel.TFrame")
		acciones.pack(fill="x", pady=(18, 12))
		acciones.columnconfigure((0, 1), weight=1)
		boton_refrescar = ttk.Button(acciones, text="Refrescar interfaces", command=self.refrescar_interfaces)
		boton_refrescar.grid(row=0, column=0, sticky="ew", padx=(0, 6))
		self._registrar_tooltip(boton_refrescar, "Vuelve a leer las interfaces activas del sistema. Útil si has cambiado de red o has conectado una interfaz nueva.")
		self.boton_escanear = ttk.Button(acciones, text="Analizar red", style="Action.TButton", command=self.iniciar_escaneo)
		self.boton_escanear.grid(row=0, column=1, sticky="ew", padx=(6, 0))
		self._registrar_tooltip(self.boton_escanear, "Inicia el inventario de la red usando la configuración actual. Durante el análisis se detectan equipos, se revisan puertos y se generan los artefactos de salida.")

		accesos = ttk.LabelFrame(parent, text="Archivos generados", padding=12)
		accesos.pack(fill="x", pady=(6, 0))
		accesos.columnconfigure((0, 1), weight=1)
		boton_html = ttk.Button(accesos, text="Abrir topología HTML", command=self.abrir_html)
		boton_html.grid(row=0, column=0, sticky="ew", padx=(0, 6), pady=(0, 8))
		self._registrar_tooltip(boton_html, "Abre la topología generada del último escaneo en el navegador predeterminado.")
		boton_json = ttk.Button(accesos, text="Abrir informe JSON", command=self.abrir_json)
		boton_json.grid(row=0, column=1, sticky="ew", padx=(6, 0), pady=(0, 8))
		self._registrar_tooltip(boton_json, "Abre el informe estructurado en JSON con todos los datos recopilados del último análisis.")
		boton_csv = ttk.Button(accesos, text="Abrir CSV base", command=self.abrir_csv)
		boton_csv.grid(row=1, column=0, sticky="ew", padx=(0, 6))
		self._registrar_tooltip(boton_csv, "Abre el CSV completo generado por el último escaneo con los equipos visibles y sus datos principales.")
		boton_csv_filtrado = ttk.Button(accesos, text="Exportar CSV filtrado", command=self.exportar_csv_filtrado)
		boton_csv_filtrado.grid(row=1, column=1, sticky="ew", padx=(6, 0))
		self._registrar_tooltip(boton_csv_filtrado, "Exporta a CSV solo los equipos visibles tras aplicar los filtros actuales de red, tipo o puertos.")
		boton_carpeta = ttk.Button(accesos, text="Abrir carpeta salida", command=self.abrir_directorio_salida)
		boton_carpeta.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(8, 0))
		self._registrar_tooltip(boton_carpeta, "Abre la carpeta de salida donde se guardan los artefactos generados por la aplicación.")

		notas = ttk.LabelFrame(parent, text="Notas", padding=12)
		notas.pack(fill="both", expand=True, pady=(16, 0))
		ttk.Label(
			notas,
			text=(
				"La topología se infiere desde el host local. Para una vista física real de switches y enlaces "
				"haría falta integrar SNMP o LLDP en una siguiente iteración."
			),
			style="Muted.TLabel",
			wraplength=320,
			justify="left",
		).pack(anchor="w")

	def _construir_resultados(self, parent: ttk.Frame) -> None:
		cabecera = ttk.Frame(parent, style="Panel.TFrame")
		cabecera.grid(row=0, column=0, sticky="ew")
		cabecera.columnconfigure(0, weight=1)
		ttk.Label(cabecera, text="Resultados del último análisis", style="Title.TLabel").grid(row=0, column=0, sticky="w")
		ttk.Label(cabecera, textvariable=self.var_estado, style="Muted.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 0))
		etiqueta_ip_publica = ttk.Label(cabecera, textvariable=self.var_ip_publica, style="Section.TLabel")
		etiqueta_ip_publica.grid(row=2, column=0, sticky="w", pady=(8, 0))
		self._registrar_tooltip(etiqueta_ip_publica, "Muestra la IP pública detectada para la salida a Internet de la red analizada. Si no aparece, puede no haber conectividad externa o la consulta puede no haberse resuelto.")

		resumen = ttk.LabelFrame(parent, text="Resumen", padding=12)
		resumen.grid(row=1, column=0, sticky="ew", pady=(16, 14))
		resumen.columnconfigure(0, weight=1)
		self.texto_resumen = tk.Text(resumen, height=9, wrap="word", relief="flat", bg="#f7fbf8", fg="#173227")
		self.texto_resumen.pack(fill="x", expand=False)
		self.texto_resumen.insert("1.0", "Todavía no hay resultados. Ejecuta un análisis.")
		self.texto_resumen.configure(state="disabled")
		self._registrar_tooltip(self.texto_resumen, "Muestra un resumen textual del último escaneo: interfaz usada, gateway, equipos detectados y puertos encontrados.")

		filtros = ttk.LabelFrame(parent, text="Filtros", padding=12)
		filtros.grid(row=2, column=0, sticky="ew", pady=(0, 14))
		filtros.columnconfigure(1, weight=1)
		filtros.columnconfigure(3, weight=1)
		filtros.columnconfigure(5, weight=1)
		ttk.Label(filtros, text="Red", style="Section.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
		self.combo_filtro_red = ttk.Combobox(filtros, textvariable=self.var_filtro_red, state="readonly")
		self.combo_filtro_red.grid(row=0, column=1, sticky="ew", padx=(0, 12))
		self._registrar_tooltip(self.combo_filtro_red, "Filtra la tabla para mostrar solo los dispositivos de una red concreta detectada en el último escaneo.")
		ttk.Label(filtros, text="Tipo", style="Section.TLabel").grid(row=0, column=2, sticky="w", padx=(0, 8))
		self.combo_filtro_tipo = ttk.Combobox(filtros, textvariable=self.var_filtro_tipo, state="readonly")
		self.combo_filtro_tipo.grid(row=0, column=3, sticky="ew", padx=(0, 12))
		self._registrar_tooltip(self.combo_filtro_tipo, "Filtra por tipo estimado de dispositivo, por ejemplo router, server, network o unknown.")
		ttk.Label(filtros, text="Puertos", style="Section.TLabel").grid(row=0, column=4, sticky="w", padx=(0, 8))
		entrada_filtro_puertos = ttk.Entry(filtros, textvariable=self.var_filtro_puertos)
		entrada_filtro_puertos.grid(row=0, column=5, sticky="ew", padx=(0, 12))
		self._registrar_tooltip(entrada_filtro_puertos, "Muestra solo los equipos en los que se hayan detectado uno o varios puertos concretos, por ejemplo 22,80,443.")
		boton_aplicar = ttk.Button(filtros, text="Aplicar", command=self.aplicar_filtros)
		boton_aplicar.grid(row=0, column=6, padx=(0, 8))
		self._registrar_tooltip(boton_aplicar, "Aplica los filtros actuales sobre los resultados del último escaneo.")
		boton_limpiar = ttk.Button(filtros, text="Limpiar", command=self.limpiar_filtros)
		boton_limpiar.grid(row=0, column=7)
		self._registrar_tooltip(boton_limpiar, "Restablece todos los filtros y vuelve a mostrar todos los dispositivos detectados.")

		tabla = ttk.LabelFrame(parent, text="Equipos detectados", padding=12)
		tabla.grid(row=3, column=0, sticky="nsew")
		tabla.rowconfigure(0, weight=1)
		tabla.columnconfigure(0, weight=1)

		columnas = ("red", "ip", "hostname", "cobertura", "tipo", "fabricante", "mac", "puertos")
		self.tabla_dispositivos = ttk.Treeview(tabla, columns=columnas, show="headings")
		anchos = {"red": 130, "ip": 130, "hostname": 210, "cobertura": 120, "tipo": 110, "fabricante": 180, "mac": 150, "puertos": 220}
		for columna in columnas:
			texto = "Cobertura" if columna == "cobertura" else columna.capitalize()
			self.tabla_dispositivos.heading(columna, text=texto)
			self.tabla_dispositivos.column(columna, width=anchos[columna], anchor="w")

		barra = ttk.Scrollbar(tabla, orient="vertical", command=self.tabla_dispositivos.yview)
		self.tabla_dispositivos.configure(yscrollcommand=barra.set)
		self.tabla_dispositivos.grid(row=0, column=0, sticky="nsew")
		barra.grid(row=0, column=1, sticky="ns")
		self._registrar_tooltip(self.tabla_dispositivos, "Tabla principal con los dispositivos detectados. La columna Cobertura distingue entre inventario básico, enriquecido con nmap o limitado por falta de respuesta/datos del equipo.")

	def _crear_campo(self, parent: ttk.Frame, row: int, label: str, variable: tk.StringVar, combo: bool = False, with_browse: bool = False):
		ttk.Label(parent, text=label, style="Section.TLabel").grid(row=row, column=0, sticky="w", pady=(0, 10), padx=(0, 12))

		if combo:
			widget = ttk.Combobox(parent, textvariable=variable, state="readonly")
			widget.grid(row=row, column=1, sticky="ew", pady=(0, 10))
			return widget

		frame = ttk.Frame(parent, style="Panel.TFrame")
		frame.grid(row=row, column=1, sticky="ew", pady=(0, 10))
		frame.columnconfigure(0, weight=1)
		entry = ttk.Entry(frame, textvariable=variable)
		entry.grid(row=0, column=0, sticky="ew")
		if with_browse:
			boton_browse = ttk.Button(frame, text="...", width=3, command=self.elegir_directorio_salida)
			boton_browse.grid(row=0, column=1, padx=(8, 0))
			self._registrar_tooltip(boton_browse, "Abre un selector de carpetas para elegir dónde guardar los archivos generados.")
		return entry

	def _registrar_tooltip(self, widget: tk.Widget, texto: str) -> None:
		self._tooltips.append(TooltipInformativo(widget, texto))

	def elegir_directorio_salida(self) -> None:
		seleccionado = filedialog.askdirectory(initialdir=self.var_directorio_salida.get() or ".")
		if seleccionado:
			self.var_directorio_salida.set(seleccionado)

	def _obtener_directorio_salida(self) -> str:
		return self.var_directorio_salida.get().strip() or "output"

	def refrescar_interfaces(self, inicial: bool = False) -> None:
		try:
			interfaces = listar_interfaces()
		except Exception as error:
			self.combo_interfaz["values"] = ["Todas"]
			self.var_interfaz.set("Todas")
			if not inicial:
				messagebox.showerror(NOMBRE_APLICACION, str(error))
			self.var_estado.set(f"No se pudieron cargar las interfaces: {error}")
			return

		valores = ["Todas"] + [f"{interfaz.nombre} | {interfaz.ip}" for interfaz in interfaces]
		self.combo_interfaz["values"] = valores
		if self.var_interfaz.get() not in valores:
			self.var_interfaz.set("Todas")
		self.var_estado.set(f"Interfaces cargadas: {len(interfaces)}")

	def _nombre_interfaz_seleccionada(self) -> str | None:
		valor = self.var_interfaz.get().strip()
		if not valor or valor == "Todas":
			return None
		return valor.split(" | ", 1)[0]

	def _recoger_opciones(self) -> OpcionesEscaneo:
		return OpcionesEscaneo(
			interfaz=self._nombre_interfaz_seleccionada(),
			puertos=self.var_puertos.get().strip() or "common",
			tiempo_espera_host=float(self.var_timeout_host.get().strip()),
			tiempo_espera_puerto=float(self.var_timeout_puerto.get().strip()),
			maximo_hosts=int(self.var_max_hosts.get().strip()),
			directorio_salida=self.var_directorio_salida.get().strip() or "output",
			usar_nmap=bool(self.var_usar_nmap.get()),
		)

	def _preparar_nmap(self, opciones: OpcionesEscaneo) -> OpcionesEscaneo | None:
		if not opciones.usar_nmap or nmap_disponible():
			return opciones

		respuesta = messagebox.askyesnocancel(
			NOMBRE_APLICACION,
			"nmap no está instalado.\n\n"
			"PintalaRED puede intentar instalarlo automáticamente para enriquecer el inventario. "
			"¿Quieres intentarlo ahora?\n\n"
			"Sí: intentar instalar nmap\n"
			"No: continuar sin nmap\n"
			"Cancelar: no iniciar el escaneo",
		)
		if respuesta is None:
			return None
		if respuesta is False:
			opciones.usar_nmap = False
			return opciones

		self.var_estado.set("Intentando instalar nmap antes del escaneo...")
		instalado, mensaje = instalar_nmap()
		if not instalado:
			continuar = messagebox.askyesno(
				NOMBRE_APLICACION,
				f"{mensaje}\n\n¿Quieres continuar el escaneo sin nmap?",
			)
			if not continuar:
				return None
			opciones.usar_nmap = False
			return opciones

		messagebox.showinfo(NOMBRE_APLICACION, mensaje)
		return opciones

	def _recoger_filtros(self) -> FiltrosDispositivos:
		return FiltrosDispositivos(
			red=self.var_filtro_red.get().strip() or "Todas",
			tipo=self.var_filtro_tipo.get().strip() or "Todos",
			puertos=self.var_filtro_puertos.get().strip(),
		)

	def iniciar_escaneo(self) -> None:
		if self.hilo_escaneo and self.hilo_escaneo.is_alive():
			return

		try:
			opciones = self._recoger_opciones()
		except ValueError as error:
			messagebox.showerror(NOMBRE_APLICACION, f"Configuración no válida: {error}")
			return

		opciones = self._preparar_nmap(opciones)
		if opciones is None:
			self.var_estado.set("Escaneo cancelado")
			return

		self.boton_escanear.configure(state="disabled")
		self.var_estado.set("Escaneando red. Esto puede tardar en función del tamaño de la subred y los puertos.")
		self.var_ip_publica.set("IP pública: detectando...")
		self._set_resumen("Analizando red...\n\nNo cierres la ventana hasta que termine el escaneo.")
		self._limpiar_tabla()
		self.hilo_escaneo = threading.Thread(target=self._trabajador_escaneo, args=(opciones,), daemon=True)
		self.hilo_escaneo.start()

	def _trabajador_escaneo(self, opciones: OpcionesEscaneo) -> None:
		try:
			artefactos = ejecutar_escaneo(opciones)
		except Exception as error:
			self.cola_resultados.put(("error", error))
			return
		self.cola_resultados.put(("success", artefactos))

	def _procesar_cola(self) -> None:
		try:
			while True:
				tipo_evento, payload = self.cola_resultados.get_nowait()
				if tipo_evento == "error":
					self.boton_escanear.configure(state="normal")
					self.var_estado.set("El análisis terminó con errores")
					self._set_resumen(str(payload))
					messagebox.showerror(NOMBRE_APLICACION, str(payload))
					continue

				self.ultimo_resultado = payload
				self.boton_escanear.configure(state="normal")
				self.var_estado.set("Análisis completado")
				self._mostrar_resultados(payload)
		except queue.Empty:
			pass
		finally:
			self.raiz.after(150, self._procesar_cola)

	def _mostrar_resultados(self, artefactos: ArtefactosEscaneo) -> None:
		self.var_ip_publica.set(
			f"IP pública: {artefactos.instantanea.ip_publica}"
			if artefactos.instantanea.ip_publica
			else "IP pública: no disponible"
		)
		self._set_resumen(formatear_resumen(artefactos))
		self._actualizar_opciones_filtros(artefactos)
		self.aplicar_filtros()

	def _actualizar_opciones_filtros(self, artefactos: ArtefactosEscaneo) -> None:
		redes = ["Todas"] + sorted(artefactos.snapshot.devices_by_network.keys())
		tipos_detectados = sorted(
			{
				dispositivo.device_type
				for dispositivos in artefactos.snapshot.devices_by_network.values()
				for dispositivo in dispositivos
			}
		)
		tipos = ["Todos"] + tipos_detectados

		self.combo_filtro_red["values"] = redes
		self.combo_filtro_tipo["values"] = tipos
		if self.var_filtro_red.get() not in redes:
			self.var_filtro_red.set("Todas")
		if self.var_filtro_tipo.get() not in tipos:
			self.var_filtro_tipo.set("Todos")

	def aplicar_filtros(self) -> None:
		if not self.ultimo_resultado:
			return

		try:
			self.filas_filtradas = filtrar_dispositivos(self.ultimo_resultado, self._recoger_filtros())
		except ValueError as error:
			messagebox.showerror(NOMBRE_APLICACION, f"Filtro de puertos no válido: {error}")
			return

		self._limpiar_tabla()
		for fila in self.filas_filtradas:
			self.tabla_dispositivos.insert(
				"",
				"end",
				values=(
					fila["red"],
					fila["ip"],
					fila["hostname"],
					fila["cobertura"],
					fila["tipo"],
					fila["fabricante"],
					fila["mac"],
					fila["puertos"],
				),
			)
		self.var_estado.set(f"Análisis completado. Filas visibles: {len(self.filas_filtradas)}")

	def limpiar_filtros(self) -> None:
		self.var_filtro_red.set("Todas")
		self.var_filtro_tipo.set("Todos")
		self.var_filtro_puertos.set("")
		self.aplicar_filtros()

	def exportar_csv_filtrado(self) -> None:
		if not self.ultimo_resultado:
			messagebox.showinfo(NOMBRE_APLICACION, "Todavía no hay resultados para exportar.")
			return

		if not self.filas_filtradas:
			self.aplicar_filtros()

		ruta_sugerida = Path(self.var_directorio_salida.get().strip() or "output") / "dispositivos_filtrados.csv"
		destino = filedialog.asksaveasfilename(
			initialdir=str(ruta_sugerida.parent),
			initialfile=ruta_sugerida.name,
			defaultextension=".csv",
			filetypes=[("CSV", "*.csv")],
		)
		if not destino:
			return

		ruta = exportar_csv(Path(destino), self.filas_filtradas)
		messagebox.showinfo(NOMBRE_APLICACION, f"CSV exportado en:\n{ruta}")

	def _set_resumen(self, texto: str) -> None:
		self.texto_resumen.configure(state="normal")
		self.texto_resumen.delete("1.0", "end")
		self.texto_resumen.insert("1.0", texto)
		self.texto_resumen.configure(state="disabled")

	def _limpiar_tabla(self) -> None:
		for item in self.tabla_dispositivos.get_children():
			self.tabla_dispositivos.delete(item)

	def _abrir_ruta(self, ruta: Path) -> None:
		if not ruta.exists():
			messagebox.showwarning(NOMBRE_APLICACION, f"No existe el archivo: {ruta}")
			return
		webbrowser.open(ruta.resolve().as_uri())

	def abrir_html(self) -> None:
		if not self.ultimo_resultado:
			messagebox.showinfo(NOMBRE_APLICACION, "Todavía no hay una topología generada.")
			return
		self._abrir_ruta(self.ultimo_resultado.html_path)

	def abrir_json(self) -> None:
		if not self.ultimo_resultado:
			messagebox.showinfo(NOMBRE_APLICACION, "Todavía no hay un informe JSON generado.")
			return
		self._abrir_ruta(self.ultimo_resultado.json_path)

	def abrir_csv(self) -> None:
		if not self.ultimo_resultado or not self.ultimo_resultado.csv_path:
			messagebox.showinfo(NOMBRE_APLICACION, "Todavía no hay un informe CSV generado.")
			return
		self._abrir_ruta(self.ultimo_resultado.csv_path)

	def abrir_directorio_salida(self) -> None:
		destino = Path(self.var_directorio_salida.get().strip() or "output")
		destino.mkdir(parents=True, exist_ok=True)
		if os.name == "nt":
			os.startfile(destino)  # type: ignore[attr-defined]
			return
		if shutil.which("xdg-open"):
			subprocess.Popen(["xdg-open", str(destino)])
			return
		webbrowser.open(destino.resolve().as_uri())


def lanzar_interfaz_grafica() -> int:
	raiz = tk.Tk()
	AplicacionPintalaRED(raiz)
	raiz.mainloop()
	return 0


PintalaREDApp = AplicacionPintalaRED
launch_gui = lanzar_interfaz_grafica
