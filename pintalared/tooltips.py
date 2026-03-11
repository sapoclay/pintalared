from __future__ import annotations

import tkinter as tk


class TooltipInformativo:
	"""Muestra una ayuda contextual flotante al pasar el cursor sobre un widget."""

	def __init__(self, widget: tk.Widget, texto: str, retardo_ms: int = 450) -> None:
		self.widget = widget
		self.texto = texto
		self.retardo_ms = retardo_ms
		self._identificador_after: str | None = None
		self._ventana: tk.Toplevel | None = None

		widget.bind("<Enter>", self._programar_mostrar, add="+")
		widget.bind("<Leave>", self._ocultar, add="+")
		widget.bind("<ButtonPress>", self._ocultar, add="+")

	def _programar_mostrar(self, _evento=None) -> None:
		self._cancelar_programacion()
		self._identificador_after = self.widget.after(self.retardo_ms, self._mostrar)

	def _cancelar_programacion(self) -> None:
		if self._identificador_after is not None:
			self.widget.after_cancel(self._identificador_after)
			self._identificador_after = None

	def _mostrar(self) -> None:
		self._identificador_after = None
		if self._ventana is not None or not self.texto.strip():
			return

		x = self.widget.winfo_rootx() + 18
		y = self.widget.winfo_rooty() + self.widget.winfo_height() + 10

		self._ventana = tk.Toplevel(self.widget)
		self._ventana.wm_overrideredirect(True)
		self._ventana.wm_geometry(f"+{x}+{y}")
		self._ventana.configure(bg="#173227")

		etiqueta = tk.Label(
			self._ventana,
			text=self.texto,
			justify="left",
			wraplength=320,
			bg="#173227",
			fg="#f6fbf8",
			padx=10,
			pady=8,
			font=("Segoe UI", 9),
			relief="solid",
			bd=1,
		)
		etiqueta.pack()

	def _ocultar(self, _evento=None) -> None:
		self._cancelar_programacion()
		if self._ventana is not None:
			self._ventana.destroy()
			self._ventana = None