#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from pintalared import NOMBRE_APLICACION
from pintalared.consola import construir_parser_argumentos as construir_parser_consola
from pintalared.consola import main as main_consola


def construir_parser_lanzador() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"Lanzador principal de {NOMBRE_APLICACION}",
        add_help=False,
    )
    parser.add_argument(
        "--modo",
        choices=["grafico", "consola"],
        default="grafico",
        help="Arranca la interfaz grafica o la interfaz de consola",
    )
    parser.add_argument("-h", "--help", action="store_true", help="Muestra esta ayuda")
    return parser


def main(argv: list[str] | None = None) -> int:
    # Ejecuta siempre desde la raíz del proyecto para mantener rutas relativas coherentes.
    os.chdir(Path(__file__).parent)
    argv = list(sys.argv[1:] if argv is None else argv)

    argumentos_normalizados: list[str] = []
    for argumento in argv:
        argumento_minusculas = argumento.lower()
        # Mantiene compatibilidad con alias antiguos y atajos más cómodos para el usuario.
        if argumento_minusculas in {"--gui", "--grafico"}:
            argumentos_normalizados.extend(["--modo", "grafico"])
            continue
        if argumento_minusculas in {"--cli", "--consola"}:
            argumentos_normalizados.extend(["--modo", "consola"])
            continue
        argumentos_normalizados.append(argumento)

    parser = construir_parser_lanzador()
    argumentos_lanzador, argumentos_restantes = parser.parse_known_args(argumentos_normalizados)

    if argumentos_lanzador.help:
        # Redirige la ayuda completa al parser de consola cuando ese es el modo solicitado.
        if argumentos_lanzador.modo == "consola":
            construir_parser_consola().print_help()
            return 0
        parser.print_help()
        print("\nUsa --modo consola --help para ver las opciones del escaneo por terminal.")
        return 0

    if argumentos_lanzador.modo == "consola":
        return main_consola(argumentos_restantes)

    try:
        # La GUI se importa solo cuando se necesita para no depender de Tkinter en modo consola.
        from pintalared.interfaz_grafica import lanzar_interfaz_grafica
    except Exception as error:
        # Si la GUI no puede arrancar, la aplicación sigue siendo utilizable desde terminal.
        print(f"No se pudo arrancar la interfaz grafica de {NOMBRE_APLICACION}: {error}", file=sys.stderr)
        print("Se ejecutara la interfaz de consola como alternativa.", file=sys.stderr)
        return main_consola(argumentos_restantes)

    return lanzar_interfaz_grafica()


if __name__ == "__main__":
    raise SystemExit(main())
