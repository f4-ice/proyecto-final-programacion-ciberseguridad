# integrity.py
# Calcula el hash SHA-256 de un archivo de evidencia y lo compara con
# el hash guardado la primera vez, para saber si el archivo fue modificado.

import hashlib
import os

# ----- Configuracion -----
TAMANO_BLOQUE = 65536
CARPETA_PROYECTO = os.path.dirname(os.path.abspath(__file__))
ARCHIVO_REFERENCIAS = os.path.join(CARPETA_PROYECTO, "output", "hashes_referencia.txt")


def calcular_sha256(ruta):
    """Lee el archivo por bloques y devuelve su hash SHA-256"""
    sha = hashlib.sha256()
    archivo = open(ruta, "rb")
    bloque = archivo.read(TAMANO_BLOQUE)
    while bloque != b"":
        sha.update(bloque)
        bloque = archivo.read(TAMANO_BLOQUE)
    archivo.close()
    return sha.hexdigest()


def cargar_referencias():
    """Lee los hashes guardados. Cada linea del archivo es: ruta|hash"""
    referencias = {}
    if not os.path.exists(ARCHIVO_REFERENCIAS):
        return referencias

    try:
        archivo = open(ARCHIVO_REFERENCIAS, "r", encoding="utf-8")
        for linea in archivo:
            partes = linea.strip().split("|")
            if len(partes) == 2:
                referencias[partes[0]] = partes[1]
        archivo.close()
    except OSError:
        print("[!] No se pudo leer el archivo de hashes de referencia")

    return referencias


def guardar_referencias(referencias):
    """Guarda todos los hashes de referencia en el archivo"""
    try:
        os.makedirs(os.path.dirname(ARCHIVO_REFERENCIAS), exist_ok=True)
        archivo = open(ARCHIVO_REFERENCIAS, "w", encoding="utf-8")
        for ruta in referencias:
            archivo.write(ruta + "|" + referencias[ruta] + "\n")
        archivo.close()
        return True
    except OSError:
        return False


def demostrar_cambio(ruta):
    """Muestra que si se cambia un solo byte del archivo, el hash es totalmente diferente.
    El cambio se hace solo en memoria, el archivo original no se toca."""
    archivo = open(ruta, "rb")
    contenido = archivo.read()
    archivo.close()

    contenido_modificado = contenido + b" "
    hash_original = hashlib.sha256(contenido).hexdigest()
    hash_modificado = hashlib.sha256(contenido_modificado).hexdigest()

    lineas = []
    lineas.append("Demostracion (se agrega 1 espacio al final, solo en memoria):")
    lineas.append("  Hash original:   " + hash_original)
    lineas.append("  Hash modificado: " + hash_modificado)
    if hash_original != hash_modificado:
        lineas.append("  Resultado: los hashes son diferentes, cualquier cambio se detecta")
    return lineas


def crear_reporte(ruta):
    """Calcula el hash del archivo, lo compara con la referencia y devuelve las lineas del reporte"""
    lineas = []
    lineas.append("=== INTEGRIDAD SHA-256 ===")
    lineas.append("Archivo: " + ruta)

    try:
        hash_actual = calcular_sha256(ruta)
    except FileNotFoundError:
        lineas.append("  [!] El archivo no existe: " + ruta)
        return lineas
    except IsADirectoryError:
        lineas.append("  [!] La ruta es una carpeta, no un archivo: " + ruta)
        return lineas
    except PermissionError:
        lineas.append("  [!] No hay permisos para leer el archivo: " + ruta)
        return lineas
    except OSError as error:
        lineas.append("  [!] No se pudo leer el archivo: " + str(error))
        return lineas

    lineas.append("SHA-256 actual: " + hash_actual)

    referencias = cargar_referencias()
    ruta_completa = os.path.abspath(ruta)

    if ruta_completa not in referencias:
        referencias[ruta_completa] = hash_actual
        if guardar_referencias(referencias):
            lineas.append("Estado: PRIMERA VEZ, el hash se guardo como referencia")
        else:
            lineas.append("  [!] No se pudo guardar el hash de referencia")
    elif referencias[ruta_completa] == hash_actual:
        lineas.append("Estado: OK, el archivo no fue modificado")
    else:
        lineas.append("Estado: ALERTA, el archivo fue MODIFICADO")
        lineas.append("  Hash esperado: " + referencias[ruta_completa])
        lineas.append("  Hash actual:   " + hash_actual)

    lineas = lineas + demostrar_cambio(ruta)
    return lineas
