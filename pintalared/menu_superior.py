from __future__ import annotations

import math
import platform
import webbrowser
from pathlib import Path

import tkinter as tk
from tkinter import ttk

from . import NOMBRE_APLICACION, VERSION_APLICACION


URL_PROYECTO = "https://github.com/sapoclay/pintalared"
RUTA_LOGO = Path(__file__).resolve().parent.parent / "img" / "logo.png"


class MenuSuperiorPintalaRED:
    """Gestiona el menú superior principal y la ventana Acerca de."""

    def __init__(self, raiz: tk.Tk, obtener_directorio_salida=None) -> None:
        self.raiz = raiz
        self.obtener_directorio_salida = obtener_directorio_salida
        self._logo_sobre: tk.PhotoImage | None = None
        self._logo_icono: tk.PhotoImage | None = None
        self._ventana_sobre: tk.Toplevel | None = None
        self._ventana_documentacion: tk.Toplevel | None = None

    def instalar(self) -> None:
        barra = tk.Menu(self.raiz)

        menu_archivo = tk.Menu(barra, tearoff=False)
        menu_archivo.add_command(label="Salida", command=self.raiz.destroy)
        barra.add_cascade(label="Archivo", menu=menu_archivo)

        menu_ayuda = tk.Menu(barra, tearoff=False)
        menu_ayuda.add_command(label="Documentación", command=self.mostrar_documentacion)
        menu_ayuda.add_command(label="Sobre...", command=self.mostrar_sobre)
        barra.add_cascade(label="Ayuda", menu=menu_ayuda)

        self.raiz.configure(menu=barra)
        self._aplicar_icono(self.raiz)

    def mostrar_sobre(self) -> None:
        if self._ventana_sobre and self._ventana_sobre.winfo_exists():
            self._ventana_sobre.deiconify()
            self._ventana_sobre.lift()
            self._ventana_sobre.focus_force()
            return

        ventana = tk.Toplevel(self.raiz)
        ventana.title(f"Sobre {NOMBRE_APLICACION}")
        ventana.geometry("560x520")
        ventana.minsize(520, 500)
        ventana.transient(self.raiz)
        ventana.grab_set()
        ventana.configure(bg="#edf4ef")
        self._ventana_sobre = ventana
        self._aplicar_icono(ventana)

        marco = ttk.Frame(ventana, padding=20)
        marco.pack(fill="both", expand=True)

        logo = self._cargar_logo_ajustado(max_ancho=460, max_alto=180)
        if logo is not None:
            self._logo_sobre = logo
            etiqueta_logo = ttk.Label(marco, image=logo)
            etiqueta_logo.pack(anchor="center", pady=(0, 14))

        ttk.Label(
            marco,
            text=f"{NOMBRE_APLICACION} {VERSION_APLICACION}",
            font=("Segoe UI", 17, "bold"),
            justify="center",
        ).pack(anchor="center")

        descripcion = (
            "PintalaRED inventaría la red local desde Linux o Windows, detecta interfaces activas, "
            "descubre vecinos visibles, resuelve hostnames, identifica puertos TCP abiertos, estima el "
            "fabricante por MAC y genera una topología HTML junto con informes JSON y CSV filtrables desde la GUI."
        )
        ttk.Label(
            marco,
            text=descripcion,
            wraplength=470,
            justify="left",
        ).pack(fill="x", pady=(16, 18))

        marco_datos = ttk.LabelFrame(marco, text="Información de la sesión", padding=12)
        marco_datos.pack(fill="x", pady=(0, 18))
        ttk.Label(
            marco_datos,
            text=(
                f"Versión: {VERSION_APLICACION}\n"
                f"Sistema detectado: {platform.platform()}\n"
                f"Directorio de salida actual: {self._directorio_salida_actual()}"
            ),
            justify="left",
        ).pack(anchor="w")

        ttk.Button(
            marco,
            text="Abrir repositorio del proyecto",
            command=lambda: webbrowser.open(URL_PROYECTO),
        ).pack(anchor="center")

        ttk.Button(
            marco,
            text="Cerrar",
            command=ventana.destroy,
        ).pack(anchor="center", pady=(12, 0))

        ventana.protocol("WM_DELETE_WINDOW", ventana.destroy)

    def mostrar_documentacion(self) -> None:
        if self._ventana_documentacion and self._ventana_documentacion.winfo_exists():
            self._ventana_documentacion.deiconify()
            self._ventana_documentacion.lift()
            self._ventana_documentacion.focus_force()
            return

        ventana = tk.Toplevel(self.raiz)
        ventana.title(f"Documentación de {NOMBRE_APLICACION}")
        ventana.geometry("820x640")
        ventana.minsize(720, 540)
        ventana.transient(self.raiz)
        ventana.configure(bg="#edf4ef")
        self._ventana_documentacion = ventana
        self._aplicar_icono(ventana)

        contenedor = ttk.Frame(ventana, padding=18)
        contenedor.pack(fill="both", expand=True)
        contenedor.rowconfigure(1, weight=1)
        contenedor.columnconfigure(0, weight=1)

        ttk.Label(
            contenedor,
            text=f"Guía rápida de {NOMBRE_APLICACION}",
            font=("Segoe UI", 18, "bold"),
        ).grid(row=0, column=0, sticky="w", pady=(0, 12))

        marco_texto = ttk.Frame(contenedor)
        marco_texto.grid(row=1, column=0, sticky="nsew")
        marco_texto.rowconfigure(0, weight=1)
        marco_texto.columnconfigure(0, weight=1)

        texto = tk.Text(
            marco_texto,
            wrap="word",
            relief="flat",
            bg="#f7fbf8",
            fg="#173227",
            padx=14,
            pady=14,
            font=("Segoe UI", 10),
        )
        barra = ttk.Scrollbar(marco_texto, orient="vertical", command=texto.yview)
        texto.configure(yscrollcommand=barra.set)
        texto.grid(row=0, column=0, sticky="nsew")
        barra.grid(row=0, column=1, sticky="ns")

        texto.insert("1.0", self._texto_documentacion())
        texto.configure(state="disabled")

        ttk.Button(contenedor, text="Cerrar", command=ventana.destroy).grid(row=2, column=0, sticky="e", pady=(12, 0))
        ventana.protocol("WM_DELETE_WINDOW", ventana.destroy)

    def _texto_documentacion(self) -> str:
        return (
            "QUE ES CADA COSA\n"
            "\n"
            "Interfaz\n"
            "Es la tarjeta de red desde la que se realiza el inventario. En Linux suele verse como eth0, enp3s0 o wlan0. En Windows puede aparecer como Ethernet o Wi-Fi.\n"
            "\n"
            "Puertos\n"
            "Define qué puertos TCP se prueban en cada equipo detectado. El valor common revisa un conjunto habitual; también puedes escribir listas como 22,80,443 o rangos como 1-1024.\n"
            "\n"
            "nmap\n"
            "Si está disponible, la aplicación puede usar nmap para enriquecer hostnames, MAC, fabricante y puertos. Si falta, la GUI puede ofrecer instalarlo con tu confirmación antes del escaneo.\n"
            "\n"
            "Resumen\n"
            "Muestra una vista textual del último escaneo: interfaz usada, red, gateway, MAC local y equipos detectados. Cuando aparece 'sin puertos detectados en este escaneo' significa que no se encontraron puertos abiertos dentro del conjunto probado, no necesariamente que el equipo no tenga servicios abiertos.\n"
            "\n"
            "Cobertura\n"
            "La columna Cobertura de la tabla indica si el inventario del equipo es básico, enriquecido con nmap o limitado porque el dispositivo expone muy pocos datos a la red.\n"
            "\n"
            "Filtros\n"
            "Permiten ver solo los equipos de una red concreta, de un tipo determinado o con ciertos puertos abiertos detectados.\n"
            "\n"
            "Topología HTML\n"
            "Es una vista local generada en HTML y SVG. Cada nodo puede arrastrarse manualmente para reorganizar la representación. Al colocar el cursor encima de un nodo se muestran más detalles del dispositivo.\n"
            "\n"
            "POSIBLES PROBLEMAS\n"
            "\n"
            "No aparecen equipos esperados\n"
            "Puede deberse a que no respondan a ARP o ping, a que estén en otra subred, o a que el firewall del equipo destino bloquee las pruebas.\n"
            "\n"
            "Se detecta el equipo pero sale 'sin puertos detectados en este escaneo'\n"
            "Puede significar que el dispositivo no tiene puertos abiertos dentro del conjunto probado, que usa otros puertos, o que el firewall filtra la conexión.\n"
            "\n"
            "La interfaz no aparece\n"
            "En Windows puede hacer falta abrir la aplicación con permisos suficientes. En Linux conviene comprobar que la interfaz esté activa y tenga IPv4.\n"
            "\n"
            "La topología no representa la red física real\n"
            "La aplicación infiere la vista desde el equipo local. Sin SNMP, LLDP o acceso a switches no puede reconstruir conexiones físicas completas.\n"
            "\n"
            "POSIBLES SOLUCIONES\n"
            "\n"
            "Ampliar el escaneo de puertos\n"
            "Prueba con rangos mayores, por ejemplo 1-1024, o con los puertos concretos que te interese verificar.\n"
            "\n"
            "Forzar tráfico previo\n"
            "Haz ping a varios equipos antes de escanear para poblar la caché ARP del sistema operativo.\n"
            "\n"
            "Elegir una interfaz específica\n"
            "Si el equipo tiene varias redes activas, selecciona la interfaz correcta para evitar barrer una red distinta de la que buscas.\n"
            "\n"
            "Aumentar max-hosts\n"
            "Si la subred es grande y la aplicación lo bloquea por seguridad, incrementa ese límite de forma consciente.\n"
            "\n"
            "Revisar requisitos del sistema\n"
            "En Linux necesitas ip y ping. En Windows necesitas ping y PowerShell.\n"
        )

    def _cargar_logo_ajustado(self, max_ancho: int, max_alto: int) -> tk.PhotoImage | None:
        if not RUTA_LOGO.exists():
            return None

        try:
            logo = tk.PhotoImage(file=str(RUTA_LOGO))
        except tk.TclError:
            return None

        factor = max(
            1,
            math.ceil(max(logo.width() / max_ancho, logo.height() / max_alto)),
        )
        if factor > 1:
            logo = logo.subsample(factor, factor)
        return logo

    def _aplicar_icono(self, ventana: tk.Misc) -> None:
        icono = self._cargar_logo_ajustado(max_ancho=128, max_alto=128)
        if icono is None:
            return
        self._logo_icono = icono
        try:
            ventana.iconphoto(True, icono)
        except tk.TclError:
            return

    def _directorio_salida_actual(self) -> str:
        if callable(self.obtener_directorio_salida):
            try:
                return str(self.obtener_directorio_salida())
            except Exception:
                return "output"
        return "output"