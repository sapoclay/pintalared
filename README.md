# PintalaRED

PintalaRED crea un mapa de la red local desde un equipo Linux o Windows. La aplicación está organizada en módulos para separar descubrimiento, escaneo, serialización, CLI y GUI. Detecta interfaces IPv4 activas, intenta descubrir equipos conectados en cada subred, recopila MAC, hostname por DNS inverso, puertos TCP abiertos y genera una visualización HTML de la topología.

## Qué hace

- Detecta IP local, máscara, gateway y MAC de cada interfaz activa.
- Intenta resolver la IP pública visible desde Internet para representarla detrás del router cuando sea posible.
- Recorre la subred visible desde la máquina para poblar la tabla ARP.
- Extrae vecinos detectados desde las utilidades nativas del sistema operativo.
- Escanea puertos TCP comunes o un rango configurable.
- Ofrece interfaz gráfica local lanzada desde `ejecutar_app.py`.
- Estima el fabricante por prefijo MAC y clasifica el tipo de equipo con heurísticas básicas.
- Exporta inventario a CSV y permite filtrar en la GUI por red, tipo o puertos abiertos.
- Añade un menú superior con salida rápida y una ventana de información del proyecto.
- Usa el logo del proyecto también como icono de ventana cuando Tkinter lo soporta.
- Genera:
  - un informe JSON con todos los datos.
  - un informe CSV con el inventario detectado.
  - un HTML con topología de red inferida, generado de forma local y sin dependencias visuales externas.

## Limitaciones reales

La topología no puede reconstruir con precisión toda una red física desde un único equipo sin SNMP, LLDP, acceso a switches o permisos avanzados. El gráfico que genera este proyecto representa la red vista desde el host que ejecuta el análisis: equipo local, interfaces, segmentos, gateway y equipos detectados.

La detección de fabricante y tipo de dispositivo es heurística. El fabricante se infiere a partir de un conjunto local de prefijos MAC comunes, y el tipo se estima con hostname, puertos y el rol de gateway.

Actualmente el inventario y el barrido de vecinos están centrados en IPv4. Las entradas IPv6 link-local, como las direcciones `fe80::/10`, se ignoran durante el descubrimiento para evitar mezclar direcciones de distintas versiones en el mismo escaneo.

## Requisitos

- Python 3.11 o superior
- Linux: `ip` disponible en el sistema, normalmente en el paquete `iproute2`, y `ping` en `iputils-ping`
- Windows: `ping` y PowerShell disponibles en el sistema
- `nmap` es opcional, pero recomendable para enriquecer hostname, MAC, fabricante y puertos detectados. Con permisos elevados, también puede estimar servicios y sistema operativo.

## Uso

### Interfaz gráfica

Arranque normal de la aplicación:

```bash
python3 ejecutar_app.py
```

También admite el alias:

```bash
python3 ejecutar_app.py --grafico
```

### Interfaz de consola

Puedes seguir usando la aplicación desde terminal:

```bash
python3 mapeador_red.py
python3 ejecutar_app.py --consola --interface eth0
python3 mapeador_red.py --ports 22,80,443
python3 mapeador_red.py --instalar-nmap-si-falta
```

En Windows, los ejemplos equivalentes serían:

```powershell
python ejecutar_app.py --consola --interface "Ethernet"
python mapeador_red.py --interface "Wi-Fi"
```

Ejemplo básico:

```bash
python3 mapeador_red.py
```

Escaneo de una interfaz concreta:

```bash
python3 mapeador_red.py --interface eth0
```

```powershell
python mapeador_red.py --interface "Ethernet"
```

Escaneo de puertos personalizados:

```bash
python3 mapeador_red.py --ports 1-1024
python3 mapeador_red.py --ports 22,80,443,3389
```

Cambiar la carpeta de salida:

```bash
python3 mapeador_red.py --output-dir resultados
```

Permitir una subred grande de forma explícita:

```bash
python3 mapeador_red.py --interface eth0 --max-hosts 4096
```

## Archivos generados

Después de ejecutar el script se crean dos archivos dentro de la carpeta de salida:

- `network_report.json`
- `network_report.csv`
- `topologia_red.html`

Abre el HTML en un navegador para explorar la topología.

La topología HTML actual es completamente local: no necesita cargar bibliotecas externas, muestra directamente nombre o IP, tipo estimado y un resumen de puertos abiertos por dispositivo, permite recolocar manualmente cada nodo arrastrándolo con el ratón y, si hay salida a Internet, añade la IP pública detectada detrás del gateway.

Desde la GUI también puedes exportar un CSV filtrado con solo los equipos visibles en ese momento.

## Menú de la interfaz

- Archivo > Salida: cierra la aplicación.
- Ayuda > Documentación: abre una ventana con una guía rápida sobre cada parte del programa, problemas habituales y posibles soluciones.
- Ayuda > Sobre...: abre una ventana con el logo del proyecto, un resumen funcional, la versión, el sistema detectado, el directorio de salida actual y un botón para abrir el repositorio oficial en el navegador.

## Estructura del proyecto

- `ejecutar_app.py`: lanzador principal de PintalaRED. Abre la GUI por defecto.
- `mapeador_red.py`: entrada de consola para el escaneo.
- `pintalared/modelos.py`: modelos y opciones de escaneo.
- `pintalared/sistema.py`: interacción con el sistema y carga de interfaces.
- `pintalared/descubrimiento.py`: descubrimiento de equipos y puertos.
- `pintalared/servicio.py`: orquestación del escaneo y escritura de resultados.
- `pintalared/reporte.py`: filtrado de dispositivos y exportación CSV.
- `pintalared/topologia.py`: construcción del grafo y render HTML.
- `pintalared/interfaz_grafica.py`: interfaz gráfica en Tkinter.
- `pintalared/menu_superior.py`: menú principal y ventana Acerca de.

## Detalles de la GUI

- La ventana principal intenta usar [img/logo.png](img/logo.png) como icono de la aplicación.
- La ventana Acerca de redimensiona el logo automáticamente para que encaje sin deformar la interfaz.
- La información de Ayuda > Sobre... muestra el sistema operativo detectado y la carpeta de salida activa en ese momento.
- Los campos, filtros y botones principales muestran tooltips al pasar el cursor para explicar qué hace cada elemento.
- La GUI puede intentar instalar `nmap` bajo demanda, con confirmación explícita, si detecta que falta y has dejado activada su integración.

## Recomendaciones de ejecución

- Ejecuta el análisis desde la misma red que quieres inventariar.
- Para resultados más completos, hazlo cuando los equipos estén activos y respondan a la resolución ARP o a `ping`.
- El descubrimiento actual prioriza IPv4 y omite vecinos IPv6 link-local durante el escaneo.
- En Windows, PintalaRED usa PowerShell para leer interfaces y vecinos IPv4; si una interfaz no aparece, prueba a abrir la terminal con permisos suficientes.
- Si quieres un barrido más profundo, aumenta el rango de puertos. Ten en cuenta que eso incrementa el tiempo de ejecución.
- Si `nmap` está disponible, PintalaRED lo usa para enriquecer más datos del inventario; si además se ejecuta con permisos elevados, puede intentar detectar servicios y una huella básica del sistema operativo.
- El script limita por defecto el tamaño de la subred que analiza para evitar barridos accidentales demasiado grandes. Si realmente lo necesitas, ajusta `--max-hosts`.

## Diagnóstico rápido en Windows

- Comprueba que PowerShell responde con `powershell -NoProfile -Command "Get-NetIPConfiguration"`.
- Si no aparecen vecinos, fuerza primero algo de tráfico con `ping` hacia varios hosts de la subred y vuelve a lanzar PintalaRED.
- Si una interfaz activa no aparece en la GUI, ejecuta la consola o la aplicación con permisos suficientes.
- Para abrir la GUI en Windows, puedes usar `python ejecutar_app.py` o `py ejecutar_app.py` según tu instalación de Python.
