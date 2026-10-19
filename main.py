# main.py
# Programa principal de CyberGuard Analyzer: muestra el menu, llama a los
# otros modulos y guarda el resultado en un reporte .txt dentro de la carpeta output.

import os
import sys
from datetime import datetime

import ingestion
import integrity
import network_analyzer
import validation

# ----- Configuracion -----
CARPETA_PROYECTO = os.path.dirname(os.path.abspath(__file__))
CARPETA_ENTRADA = os.path.join(CARPETA_PROYECTO, "input")
CARPETA_SALIDA = os.path.join(CARPETA_PROYECTO, "output")


def mostrar_titulo():
    print(
        r"""
  ____      _                ____                     _
 / ___|   _| |__   ___ _ __ / ___|_   _  __ _ _ __ __| |
| |  | | | | '_ \ / _ \ '__| |  _| | | |/ _` | '__/ _` |
| |__| |_| | |_) |  __/ |  | |_| | |_| | (_| | | | (_| |
 \____\__, |_.__/ \___|_|   \____|\__,_|\__,_|_|  \__,_|
      |___/

    _                _
   / \   _ __   __ _| |_   _ _______ _ __
  / _ \ | '_ \ / _` | | | | |_  / _ \ '__|
 / ___ \| | | | (_| | | |_| |/ /  __/ |
/_/   \_\_| |_|\__,_|_|\__, /___\___|_|
                       |___/
"""
    )


def pedir_archivo():
    """Pide la ruta del archivo. Si solo se escribe el nombre, se busca en la carpeta input"""
    ruta = input("[+] ingresa el path al archivo .txt o .csv: ")
    ruta = ruta.strip().strip('"').strip("'")

    if not os.path.exists(ruta) and os.path.exists(os.path.join(CARPETA_ENTRADA, ruta)):
        ruta = os.path.join(CARPETA_ENTRADA, ruta)

    return ruta


def mostrar_menu():
    print()
    print("[+] menu")
    print("[1] Ingesta: leer el archivo y controlar errores de entrada")
    print("[2] Validacion: sanitizar y validar los campos de cada registro")
    print("[3] Integridad: calcular y comparar el hash SHA-256")
    print("[4] Analisis TCP/HTTP y persistencia")
    print("[5] Analisis completo (todo lo anterior)")
    print("[6] Cambiar de archivo")
    print("[7] Salir")
    print()


def opcion_ingesta(ruta):
    registros, errores, avisos = ingestion.leer_eventos(ruta)
    return ingestion.crear_reporte(ruta, registros, errores, avisos)


def opcion_validacion(ruta):
    registros, errores, avisos = ingestion.leer_eventos(ruta)
    if len(registros) == 0:
        lineas = ["=== VALIDACION DE REGISTROS ===", "  [!] No hay registros para validar"]
        for error in errores:
            lineas.append("  [!] " + error)
        return lineas
    validos, errores_validacion = validation.validar_registros(registros)
    return validation.crear_reporte(validos, errores_validacion)


def opcion_integridad(ruta):
    return integrity.crear_reporte(ruta)


def opcion_red(ruta):
    registros, errores, avisos = ingestion.leer_eventos(ruta)
    validos, errores_validacion = validation.validar_registros(registros)
    if len(validos) == 0:
        return ["=== ANALISIS TCP/HTTP Y PERSISTENCIA ===", "  [!] No hay registros validos para analizar"]
    hallazgos = network_analyzer.analizar(validos)
    return network_analyzer.crear_reporte(validos, hallazgos)


def opcion_completa(ruta):
    lineas = []
    lineas = lineas + opcion_ingesta(ruta) + [""]
    lineas = lineas + opcion_validacion(ruta) + [""]
    lineas = lineas + opcion_integridad(ruta) + [""]
    lineas = lineas + opcion_red(ruta)
    return lineas


def guardar_reporte(ruta, lineas):
    """Guarda las lineas en output/reporte_<nombre del archivo>.txt y devuelve la ruta del reporte"""
    nombre = os.path.splitext(os.path.basename(ruta))[0]
    if nombre == "":
        nombre = "sin_nombre"
    ruta_reporte = os.path.join(CARPETA_SALIDA, "reporte_" + nombre + ".txt")
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        os.makedirs(CARPETA_SALIDA, exist_ok=True)
        archivo = open(ruta_reporte, "w", encoding="utf-8")
        archivo.write("CyberGuard Analyzer - Reporte de analisis\n")
        archivo.write("Fecha del analisis: " + fecha + "\n")
        archivo.write("Archivo analizado: " + ruta + "\n")
        archivo.write("=" * 50 + "\n\n")
        for linea in lineas:
            archivo.write(linea + "\n")
        archivo.close()
    except OSError as error:
        print("[!] No se pudo guardar el reporte: " + str(error))
        return ""

    return ruta_reporte


def main():
    mostrar_titulo()

    # tambien se puede pasar el archivo al ejecutar: python main.py input/eventos_prueba.txt
    if len(sys.argv) > 1:
        ruta = sys.argv[1]
    else:
        ruta = pedir_archivo()
    print("[+] archivo recibido: " + ruta)

    opciones = {
        "1": opcion_ingesta,
        "2": opcion_validacion,
        "3": opcion_integridad,
        "4": opcion_red,
        "5": opcion_completa,
    }

    while True:
        mostrar_menu()
        opcion = input("[+] elige una opcion: ").strip()

        if opcion == "7":
            print("[+] salida")
            break

        if opcion == "6":
            ruta = pedir_archivo()
            print("[+] archivo recibido: " + ruta)
            continue

        if opcion not in opciones:
            print("[!] opcion no valida")
            continue

        # el try evita que un error inesperado cierre todo el programa
        try:
            lineas = opciones[opcion](ruta)
        except Exception as error:
            lineas = ["  [!] Error inesperado: " + str(error)]

        print()
        for linea in lineas:
            print(linea)

        ruta_reporte = guardar_reporte(ruta, lineas)
        if ruta_reporte != "":
            print()
            print("[+] reporte guardado en: " + ruta_reporte)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\n[+] programa cerrado por el usuario")
