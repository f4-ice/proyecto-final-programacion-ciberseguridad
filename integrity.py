import hashlib
import json
import logging
import os
from datetime import datetime
from pathlib import Path

from ingestion import configure_logging, log_security_event

TAMANO_BLOQUE = 65536
DIRECTORIO_SALIDA = Path("data/output")
ARCHIVO_BASE = DIRECTORIO_SALIDA / "hashes_base.json"
ARCHIVO_REPORTE = DIRECTORIO_SALIDA / "reporte_integridad.txt"
HEXADECIMALES = set("0123456789abcdef")


def calcular_sha256(ruta):
    sha = hashlib.sha256()
    with open(ruta, "rb") as archivo:
        for bloque in iter(lambda: archivo.read(TAMANO_BLOQUE), b""):
            sha.update(bloque)
    return sha.hexdigest()


def anotar_reporte(linea):
    marca = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        DIRECTORIO_SALIDA.mkdir(parents=True, exist_ok=True)
        with open(ARCHIVO_REPORTE, "a", encoding="utf-8") as archivo:
            archivo.write(f"[{marca}] {linea}\n")
    except OSError as error:
        print(f"[!] No se pudo escribir el reporte: {error}")


def obtener_hash(ruta, logger):
    try:
        return calcular_sha256(ruta)
    except FileNotFoundError:
        mensaje = f"Archivo no encontrado: {ruta}"
    except IsADirectoryError:
        mensaje = f"La ruta es un directorio, no un archivo: {ruta}"
    except PermissionError:
        mensaje = f"Sin permisos para leer: {ruta}"
    except OSError as error:
        mensaje = f"No se pudo leer {ruta}: {error}"
    print(f"[!] {mensaje}")
    anotar_reporte(f"[ERROR] {mensaje}")
    log_security_event(
        logger,
        "INTEGRITY_READ_FAIL",
        mensaje,
        level=logging.ERROR,
        archivo=ruta,
    )
    return None


def cargar_base():
    if not ARCHIVO_BASE.is_file():
        return {}
    try:
        with open(ARCHIVO_BASE, "r", encoding="utf-8") as archivo:
            base = json.load(archivo)
    except (OSError, json.JSONDecodeError):
        print("[!] La base de hashes esta danada, se ignora")
        return {}
    return base if isinstance(base, dict) else {}


def guardar_base(base):
    try:
        DIRECTORIO_SALIDA.mkdir(parents=True, exist_ok=True)
        with open(ARCHIVO_BASE, "w", encoding="utf-8") as archivo:
            json.dump(base, archivo, indent=2)
    except OSError as error:
        print(f"[!] No se pudo guardar la base de hashes: {error}")
        return False
    return True


def comparar(ruta, esperado, actual, logger):
    if esperado == actual:
        print("[+] INTEGRIDAD OK: el archivo no fue modificado")
        anotar_reporte(f"[OK] {ruta} integro ({actual})")
        log_security_event(
            logger,
            "INTEGRITY_OK",
            "Integridad verificada.",
            level=logging.INFO,
            archivo=ruta,
            sha256=actual,
        )
        return "integro"
    print("[!] FALLO DE INTEGRIDAD: el archivo fue modificado")
    print(f"    esperado: {esperado}")
    print(f"    actual:   {actual}")
    anotar_reporte(f"[FALLO] {ruta} modificado. Esperado {esperado}, actual {actual}")
    log_security_event(
        logger,
        "INTEGRITY_MISMATCH",
        "El hash no coincide con la referencia.",
        level=logging.WARNING,
        archivo=ruta,
        esperado=esperado,
        actual=actual,
    )
    return "modificado"


def registrar_base(ruta, logger):
    hash_actual = obtener_hash(ruta, logger)
    if hash_actual is None:
        return "error"
    base = cargar_base()
    base[os.path.abspath(ruta)] = hash_actual
    if not guardar_base(base):
        return "error"
    print(f"[+] SHA-256 guardado como referencia: {hash_actual}")
    anotar_reporte(f"[INFO] Hash base de {ruta}: {hash_actual}")
    log_security_event(
        logger,
        "INTEGRITY_BASELINE",
        "Hash de referencia registrado.",
        level=logging.INFO,
        archivo=ruta,
        sha256=hash_actual,
    )
    return "registrado"


def verificar_contra_base(ruta, logger):
    hash_actual = obtener_hash(ruta, logger)
    if hash_actual is None:
        return "error"
    hash_base = cargar_base().get(os.path.abspath(ruta))
    if hash_base is None:
        print("[!] No hay hash de referencia para este archivo. Usa la opcion 1 primero")
        return "sin_referencia"
    return comparar(ruta, hash_base, hash_actual, logger)


def verificar_manual(ruta, logger):
    esperado = input("[+] pega el hash SHA-256 esperado: ").strip().lower()
    if len(esperado) != 64 or not set(esperado) <= HEXADECIMALES:
        print("[!] El hash debe tener 64 caracteres hexadecimales")
        return "hash_invalido"
    hash_actual = obtener_hash(ruta, logger)
    if hash_actual is None:
        return "error"
    return comparar(ruta, esperado, hash_actual, logger)


def ejecutar(ruta):
    resultado = {"archivo": ruta, "estado": "error"}
    try:
        logger = configure_logging()
        acciones = {
            "1": registrar_base,
            "2": verificar_contra_base,
            "3": verificar_manual,
        }
        print("\n[+] modulo de integridad")
        print("[1] Calcular y guardar hash de referencia")
        print("[2] Verificar archivo contra el hash guardado")
        print("[3] Verificar contra un hash ingresado a mano")
        opcion = input("[+] elige una opcion: ").strip()
        accion = acciones.get(opcion)
        if accion is None:
            print("[!] opcion no valida")
            return resultado
        resultado["estado"] = accion(ruta, logger)
    except (EOFError, KeyboardInterrupt):
        print("\n[!] operacion cancelada")
    except Exception as error:
        print(f"[!] error inesperado en integrity: {error}")
        resultado["error"] = str(error)
    return resultado
