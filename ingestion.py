#!/usr/bin/env python3
"""
ingestion.py

Modulo de ingesta segura de archivos .txt y .csv para el proyecto final
de Programacion para Ciberseguridad.

Rol dentro del proyecto (ver README.md):
    main.py pide al usuario la ruta de un archivo .txt (o .csv) y, segun
    la opcion elegida en el menu, llama a `ejecutar(ruta)` del modulo
    correspondiente. Este modulo implementa la opcion 1: "lee el archivo,
    normaliza los datos y controla errores de entrada".

Responsabilidades de este modulo:
    - Validar la ruta recibida (existencia, tipo, extension, tamano).
    - Leer archivos .txt (delimitados) y .csv.
    - Normalizar texto, encabezados, fechas, numeros y correos.
    - Registrar eventos de seguridad y errores en logs/security_events.log.
    - Generar un archivo CSV normalizado y un reporte .txt de errores.

Uso como modulo (desde main.py):
    import ingestion
    resultado = ingestion.ejecutar(ruta)

Uso independiente desde linea de comandos:
    python ingestion.py data/input/clientes.csv
    python ingestion.py --input-dir data/input --output-dir data/output --batch
"""

from __future__ import annotations

import argparse
import csv
import logging
import re
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

EXTENSIONES_SOPORTADAS = {".txt", ".csv"}

TAMANO_MAXIMO_ARCHIVO_BYTES = 10 * 1024 * 1024
LONGITUD_MAXIMA_LINEA = 10_000
LONGITUD_MAXIMA_VALOR_LOG: int = 200
LONGITUD_MAXIMA_RUTA: int = 4096

DIRECTORIO_ENTRADA_PREDETERMINADO = Path("data/input")
DIRECTORIO_SALIDA_PREDETERMINADO = Path("data/output")
DIRECTORIO_LOG_PREDETERMINADO = Path("logs")
NOMBRE_ARCHIVO_LOG = "security_events.log"

CODIFICACION_ENTRADA: str = "utf-8"
CODIFICACION_SALIDA = "utf-8"
DELIMITADOR_CSV = ","
DELIMITADOR_CAMPO_TXT: str = "|"

VALORES_VACIOS: set[str] = {"", "-", "null", "none", "na", "n/a"}

FORMATOS_FECHA_ACEPTADOS: tuple[str, ...] = (
    "%Y-%m-%d",
    "%d/%m/%Y",
    "%m/%d/%Y",
    "%Y/%m/%d",
)
FORMATO_FECHA_ESTANDAR: str = "%Y-%m-%d"

# Campos obligatorios del esquema esperado. Ajustar segun los datos reales
# del proyecto (p. ej. agregar "fecha", "monto", etc. si son obligatorios).
CAMPOS_OBLIGATORIOS: tuple[str, ...] = ("id",)

PATRON_CARACTERES_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
PATRON_ESPACIOS_MULTIPLES = re.compile(r"\s+")
PATRON_NOMBRE_CAMPO_INVALIDO = re.compile(r"[^a-z0-9_]+")
PATRON_SALTO_DIRECTORIO = re.compile(r"\.\.(/|\\|$)")


# ---------------------------------------------------------------------------
# Excepciones personalizadas
# ---------------------------------------------------------------------------

class ErrorIngesta(Exception):
    """Error controlado durante el proceso de ingesta."""


class ErrorEventoSeguridad(ErrorIngesta):
    """Error que ademas debe registrarse como evento de seguridad."""


# ---------------------------------------------------------------------------
# Logging y eventos de seguridad
# ---------------------------------------------------------------------------

def configurar_logging(directorio_log: Path = DIRECTORIO_LOG_PREDETERMINADO) -> logging.Logger:
    """Configura (una sola vez) un registrador de archivo para eventos de seguridad."""
    directorio_log.mkdir(parents=True, exist_ok=True)
    ruta_log = directorio_log / NOMBRE_ARCHIVO_LOG

    registrador = logging.getLogger("ingestion")
    registrador.setLevel(logging.INFO)

    if registrador.handlers:
        return registrador

    manejador = logging.FileHandler(ruta_log, encoding="utf-8")
    formateador = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(evento)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    manejador.setFormatter(formateador)
    registrador.addHandler(manejador)
    return registrador


def sanear_para_log(valor: Any, longitud_maxima: int = LONGITUD_MAXIMA_VALOR_LOG) -> str:
    """Neutraliza datos no confiables antes de escribirlos en el log.

    Evita inyeccion de saltos de linea (log forging), caracteres de control
    y trunca valores excesivamente largos.
    """
    valor_seguro = str(valor)
    valor_seguro = valor_seguro.replace("\r", "\\r").replace("\n", "\\n")
    valor_seguro = PATRON_CARACTERES_CONTROL.sub("", valor_seguro)
    valor_seguro = valor_seguro.replace("|", "\\|")
    if len(valor_seguro) > longitud_maxima:
        valor_seguro = valor_seguro[:longitud_maxima] + "...[truncado]"
    return valor_seguro


def registrar_evento_seguridad(
    registrador: logging.Logger,
    evento: str,
    descripcion: str,
    nivel: int = logging.WARNING,
    **contexto: Any,
) -> None:
    """Registra un evento de seguridad estructurado y saneado."""
    try:
        contexto_seguro = {
            clave: sanear_para_log(valor) for clave, valor in contexto.items()
        }
        registrador.log(
            nivel,
            sanear_para_log(descripcion),
            extra={"evento": evento, **contexto_seguro},
        )
    except Exception as error_registro:  # el logging nunca debe tumbar el flujo
        print(
            f"No fue posible escribir el evento de seguridad '{evento}': {error_registro}",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# Normalizacion
# ---------------------------------------------------------------------------

def normalizar_texto(valor: Any) -> str:
    """Normaliza texto: Unicode NFC, caracteres de control y espacios."""
    if valor is None:
        return ""
    valor_normalizado = str(valor)
    valor_normalizado = unicodedata.normalize("NFC", valor_normalizado)
    valor_normalizado = valor_normalizado.replace("\r\n", " ")
    valor_normalizado = valor_normalizado.replace("\r", " ")
    valor_normalizado = valor_normalizado.replace("\n", " ")
    valor_normalizado = PATRON_CARACTERES_CONTROL.sub("", valor_normalizado)
    valor_normalizado = valor_normalizado.strip()
    valor_normalizado = PATRON_ESPACIOS_MULTIPLES.sub(" ", valor_normalizado)
    return valor_normalizado


def normalizar_nombre_campo(nombre_crudo: Any) -> str:
    """Convierte encabezados en nombres de campo consistentes (snake_case)."""
    nombre_normalizado = normalizar_texto(nombre_crudo).lower()
    nombre_normalizado = nombre_normalizado.replace(" ", "_").replace("-", "_")
    nombre_normalizado = PATRON_NOMBRE_CAMPO_INVALIDO.sub("", nombre_normalizado)
    return nombre_normalizado or "campo_sin_nombre"


def normalizar_valor_vacio(valor: str) -> str | None:
    """Convierte representaciones comunes de valor vacio en None."""
    if valor.strip().lower() in VALORES_VACIOS:
        return None
    return valor


def normalizar_numero(valor_crudo: Any, nombre_campo: str = "numero") -> float | None:
    """Normaliza un valor numerico y valida su conversion."""
    valor_normalizado = normalizar_texto(valor_crudo)
    if valor_normalizado == "":
        return None
    valor_limpio = valor_normalizado.replace("$", "").replace("\u20ac", "")
    valor_limpio = valor_limpio.replace(",", ".")
    try:
        valor_numerico = float(valor_limpio)
    except ValueError as error:
        raise ErrorIngesta(
            f"El campo '{nombre_campo}' no contiene un numero valido."
        ) from error
    return valor_numerico


def normalizar_fecha(valor_crudo: Any, nombre_campo: str = "fecha") -> str | None:
    """Normaliza fechas al formato estandar YYYY-MM-DD."""
    valor_normalizado = normalizar_texto(valor_crudo)
    if valor_normalizado == "":
        return None
    for formato_fecha in FORMATOS_FECHA_ACEPTADOS:
        try:
            fecha_parseada = datetime.strptime(valor_normalizado, formato_fecha)
            return fecha_parseada.strftime(FORMATO_FECHA_ESTANDAR)
        except ValueError:
            continue
    raise ErrorIngesta(
        f"El campo '{nombre_campo}' no tiene una fecha valida: "
        f"formatos aceptados: {', '.join(FORMATOS_FECHA_ACEPTADOS)}."
    )


def normalizar_correo(valor_crudo: Any, nombre_campo: str = "correo") -> str | None:
    """Normaliza y valida de forma basica un correo electronico."""
    valor_normalizado = normalizar_texto(valor_crudo)
    if valor_normalizado == "":
        return None
    if valor_normalizado.count("@") != 1:
        raise ErrorIngesta(
            f"El campo '{nombre_campo}' debe contener exactamente un '@'."
        )
    parte_local, parte_dominio = valor_normalizado.split("@", 1)
    if not parte_local or "." not in parte_dominio:
        raise ErrorIngesta(
            f"El campo '{nombre_campo}' no tiene un formato de correo valido."
        )
    if len(valor_normalizado) > 254:
        raise ErrorIngesta(
            f"El campo '{nombre_campo}' excede la longitud maxima permitida."
        )
    return f"{parte_local}@{parte_dominio.lower()}"


def normalizar_registro(
    registro_crudo: dict[str, Any],
    registrador: logging.Logger,
    archivo_origen: Path,
    numero_linea: int,
    registro_errores: list[str] | None = None,
) -> dict[str, Any] | None:
    """Normaliza un registro completo y aplica validaciones por campo.

    Si el registro no pasa las validaciones, se registra como evento de
    seguridad (INPUT_VALIDATION_FAIL), opcionalmente se agregan los errores
    a `registro_errores` (para el reporte .txt) y se devuelve None para descartarlo.
    """
    registro_normalizado: dict[str, Any] = {}
    errores_validacion: list[str] = []

    for clave_cruda, valor_crudo in registro_crudo.items():
        nombre_campo = normalizar_nombre_campo(clave_cruda)
        valor_normalizado: str | None = normalizar_texto(valor_crudo)
        valor_normalizado = normalizar_valor_vacio(valor_normalizado)
        registro_normalizado[nombre_campo] = valor_normalizado

    for campo_obligatorio in CAMPOS_OBLIGATORIOS:
        if registro_normalizado.get(campo_obligatorio) in (None, ""):
            errores_validacion.append(
                f"Campo obligatorio ausente o vacio: '{campo_obligatorio}'."
            )

    if "fecha" in registro_normalizado:
        try:
            registro_normalizado["fecha"] = normalizar_fecha(
                registro_normalizado["fecha"], nombre_campo="fecha"
            )
        except ErrorIngesta as error:
            errores_validacion.append(str(error))

    if "monto" in registro_normalizado:
        try:
            registro_normalizado["monto"] = normalizar_numero(
                registro_normalizado["monto"], nombre_campo="monto"
            )
        except ErrorIngesta as error:
            errores_validacion.append(str(error))

    if "correo" in registro_normalizado:
        try:
            registro_normalizado["correo"] = normalizar_correo(
                registro_normalizado["correo"], nombre_campo="correo"
            )
        except ErrorIngesta as error:
            errores_validacion.append(str(error))

    if errores_validacion:
        mensaje = f"Linea {numero_linea}: {' '.join(errores_validacion)}"
        registrar_evento_seguridad(
            registrador=registrador,
            evento="INPUT_VALIDATION_FAIL",
            descripcion="Registro rechazado por validacion de entrada.",
            nivel=logging.WARNING,
            archivo=archivo_origen.name,
            linea=numero_linea,
            errores="; ".join(errores_validacion),
        )
        if registro_errores is not None:
            registro_errores.append(mensaje)
        return None

    return registro_normalizado


# ---------------------------------------------------------------------------
# Validacion de archivos
# ---------------------------------------------------------------------------

def validar_ruta_entrada(
    ruta_entrada: Path,
    registrador: logging.Logger,
    raiz_permitida: Path | None = None,
) -> Path:
    """Valida existencia, tipo, extension, ubicacion y tamano del archivo.

    `raiz_permitida`, si se indica, obliga a que el archivo este contenido
    dentro de ese directorio (util en el modo por lotes). En el modo
    interactivo (`ejecutar`) no se restringe a un directorio fijo porque
    el usuario puede indicar cualquier ruta valida, pero se registran como
    evento de seguridad los intentos de path traversal (p. ej. "..").
    """
    texto_ruta_cruda = str(ruta_entrada)

    if "\x00" in texto_ruta_cruda:
        raise ErrorEventoSeguridad("La ruta contiene un byte nulo no permitido.")

    if len(texto_ruta_cruda) > LONGITUD_MAXIMA_RUTA:
        raise ErrorEventoSeguridad("La ruta excede la longitud maxima permitida.")

    if PATRON_SALTO_DIRECTORIO.search(texto_ruta_cruda):
        registrar_evento_seguridad(
            registrador=registrador,
            evento="PATH_TRAVERSAL_ATTEMPT",
            descripcion="Se detecto un patron de salida de directorio ('..') en la ruta.",
            nivel=logging.WARNING,
            ruta=texto_ruta_cruda,
        )

    ruta_resuelta = ruta_entrada.expanduser().resolve()

    if raiz_permitida is not None:
        raiz_permitida_resuelta = raiz_permitida.resolve()
        esta_contenida = False
        try:
            esta_contenida = ruta_resuelta.is_relative_to(raiz_permitida_resuelta)
        except AttributeError:  # Python < 3.9
            esta_contenida = str(ruta_resuelta).startswith(str(raiz_permitida_resuelta))
        if not esta_contenida:
            raise ErrorEventoSeguridad(
                f"La ruta '{ruta_entrada}' esta fuera del directorio autorizado."
            )

    if not ruta_resuelta.exists():
        raise ErrorIngesta(f"El archivo no existe: '{ruta_entrada}'.")

    if not ruta_resuelta.is_file():
        raise ErrorIngesta(f"La ruta no corresponde a un archivo: '{ruta_entrada}'.")

    extension_archivo = ruta_resuelta.suffix.lower()
    if extension_archivo not in EXTENSIONES_SOPORTADAS:
        raise ErrorEventoSeguridad(f"Extension no permitida: '{extension_archivo}'.")

    try:
        tamano_archivo = ruta_resuelta.stat().st_size
    except OSError as error:
        raise ErrorIngesta(
            f"No fue posible consultar el tamano del archivo '{ruta_entrada}'."
        ) from error

    if tamano_archivo > TAMANO_MAXIMO_ARCHIVO_BYTES:
        raise ErrorEventoSeguridad(
            f"El archivo excede el tamano maximo permitido "
            f"({TAMANO_MAXIMO_ARCHIVO_BYTES} bytes)."
        )

    if tamano_archivo == 0:
        raise ErrorIngesta(f"El archivo '{ruta_entrada}' esta vacio.")

    return ruta_resuelta


# ---------------------------------------------------------------------------
# Lectura de archivos
# ---------------------------------------------------------------------------

def leer_archivo_csv(ruta_archivo: Path) -> Iterator[dict[str, Any]]:
    """Lee un archivo CSV y entrega registros con encabezados normalizados."""
    try:
        with ruta_archivo.open(mode="r", encoding=CODIFICACION_ENTRADA, newline="") as manejador_archivo:
            lector = csv.DictReader(manejador_archivo, delimiter=DELIMITADOR_CSV)
            if not lector.fieldnames:
                raise ErrorIngesta(
                    f"El archivo CSV no contiene encabezados: '{ruta_archivo.name}'."
                )

            encabezados_normalizados = [normalizar_nombre_campo(header) for header in lector.fieldnames]

            for numero_fila, fila_cruda in enumerate(lector, start=2):
                try:
                    fila_normalizada = {
                        encabezados_normalizados[indice]: valor
                        for indice, valor in enumerate(fila_cruda.values())
                        if indice < len(encabezados_normalizados)
                    }
                except (TypeError, ValueError, IndexError) as error:
                    raise ErrorIngesta(
                        f"Fila {numero_fila} con estructura invalida."
                    ) from error
                yield fila_normalizada
    except UnicodeDecodeError as error:
        raise ErrorIngesta(
            f"Error de codificacion al leer '{ruta_archivo.name}': {error}"
        ) from error
    except csv.Error as error:
        raise ErrorIngesta(
            f"Error al analizar el archivo CSV '{ruta_archivo.name}': {error}"
        ) from error


def leer_archivo_txt(ruta_archivo: Path) -> Iterator[dict[str, Any]]:
    """Lee un archivo TXT delimitado por '|' y entrega registros crudos."""
    try:
        with ruta_archivo.open(mode="r", encoding=CODIFICACION_ENTRADA) as manejador_archivo:
            for numero_linea, linea_cruda in enumerate(manejador_archivo, start=1):
                if len(linea_cruda) > LONGITUD_MAXIMA_LINEA:
                    raise ErrorEventoSeguridad(
                        f"Linea {numero_linea} excede la longitud maxima permitida."
                    )
                linea_normalizada = normalizar_texto(linea_cruda)
                if not linea_normalizada:
                    continue
                campos = linea_normalizada.split(DELIMITADOR_CAMPO_TXT)
                yield {f"campo_{indice}": valor for indice, valor in enumerate(campos, start=1)}
    except UnicodeDecodeError as error:
        raise ErrorIngesta(
            f"Error de codificacion al leer '{ruta_archivo.name}': {error}"
        ) from error
    except OSError as error:
        raise ErrorIngesta(
            f"Error de acceso al archivo '{ruta_archivo.name}': {error}"
        ) from error


def leer_archivo(ruta_archivo: Path) -> Iterator[dict[str, Any]]:
    """Selecciona el lector adecuado segun la extension del archivo."""
    extension_archivo = ruta_archivo.suffix.lower()
    if extension_archivo == ".csv":
        return leer_archivo_csv(ruta_archivo)
    if extension_archivo == ".txt":
        return leer_archivo_txt(ruta_archivo)
    raise ErrorEventoSeguridad(f"Formato no soportado: '{extension_archivo}'.")


# ---------------------------------------------------------------------------
# Escritura de salida
# ---------------------------------------------------------------------------

def escribir_csv_normalizado(registros: Iterable[dict[str, Any]], ruta_salida: Path) -> int:
    """Escribe registros normalizados en un archivo CSV. Devuelve el total escrito."""
    ruta_salida.parent.mkdir(parents=True, exist_ok=True)
    conteo_escritos = 0
    nombres_campos: list[str] | None = None
    escritor: csv.DictWriter | None = None

    try:
        with ruta_salida.open(mode="w", encoding=CODIFICACION_SALIDA, newline="") as manejador_archivo:
            for registro in registros:
                if nombres_campos is None:
                    nombres_campos = list(registro.keys())
                    escritor = csv.DictWriter(
                        manejador_archivo,
                        fieldnames=nombres_campos,
                        delimiter=DELIMITADOR_CSV,
                        extrasaction="ignore",
                    )
                    escritor.writeheader()
                escritor.writerow(registro)
                conteo_escritos += 1
    except OSError as error:
        raise ErrorIngesta(
            f"Error al escribir el archivo de salida '{ruta_salida.name}': {error}"
        ) from error
    except csv.Error as error:
        raise ErrorIngesta(
            f"Error al escribir una fila en '{ruta_salida.name}': {error}"
        ) from error

    return conteo_escritos


def escribir_reporte_errores(
    archivo_origen: Path,
    ruta_salida: Path,
    total_leidos: int,
    total_validos: int,
    errores: list[str],
) -> None:
    """Genera el reporte .txt con los errores encontrados durante el analisis."""
    ruta_salida.parent.mkdir(parents=True, exist_ok=True)
    marca_tiempo = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z")

    lineas = [
        "REPORTE DE INGESTA DE DATOS",
        "=" * 40,
        f"Archivo analizado : {archivo_origen.name}",
        f"Fecha de analisis : {marca_tiempo}",
        f"Registros leidos  : {total_leidos}",
        f"Registros validos : {total_validos}",
        f"Registros con error: {len(errores)}",
        "",
    ]

    if errores:
        lineas.append("Detalle de errores:")
        lineas.append("-" * 40)
        lineas.extend(errores)
    else:
        lineas.append("No se encontraron errores durante el analisis.")

    try:
        ruta_salida.write_text("\n".join(lineas) + "\n", encoding=CODIFICACION_SALIDA)
    except OSError as error:
        raise ErrorIngesta(
            f"Error al escribir el reporte '{ruta_salida.name}': {error}"
        ) from error


# ---------------------------------------------------------------------------
# Procesamiento de un archivo
# ---------------------------------------------------------------------------

def procesar_archivo(
    registrador: logging.Logger,
    ruta_archivo: Path,
    directorio_salida: Path,
    raiz_permitida: Path | None = None,
) -> dict[str, Any]:
    """Valida, lee, normaliza y exporta un archivo individual.

    Devuelve un diccionario con el resultado del procesamiento, incluyendo
    las rutas del CSV normalizado y del reporte .txt de errores.
    """
    resultado: dict[str, Any] = {
        "archivo": ruta_archivo.name,
        "estado": "error",
        "registros_leidos": 0,
        "registros_validos": 0,
    }

    try:
        ruta_validada = validar_ruta_entrada(ruta_archivo, registrador=registrador, raiz_permitida=raiz_permitida)
        ruta_csv_salida = directorio_salida / f"{ruta_validada.stem}_normalized.csv"
        ruta_reporte = directorio_salida / f"{ruta_validada.stem}_report.txt"

        registros_crudos = leer_archivo(ruta_validada)
        registros_validos_lista: list[dict[str, Any]] = []
        errores: list[str] = []
        total_leidos = 0

        for numero_linea, registro_crudo in enumerate(registros_crudos, start=1):
            total_leidos += 1
            registro_normalizado = normalizar_registro(
                registro_crudo=registro_crudo,
                registrador=registrador,
                archivo_origen=ruta_validada,
                numero_linea=numero_linea,
                registro_errores=errores,
            )
            if registro_normalizado is not None:
                registros_validos_lista.append(registro_normalizado)

        conteo_escritos = escribir_csv_normalizado(registros_validos_lista, ruta_csv_salida)
        escribir_reporte_errores(
            archivo_origen=ruta_validada,
            ruta_salida=ruta_reporte,
            total_leidos=total_leidos,
            total_validos=conteo_escritos,
            errores=errores,
        )

        resultado["estado"] = "success"
        resultado["registros_leidos"] = total_leidos
        resultado["registros_validos"] = conteo_escritos
        resultado["salida_csv"] = str(ruta_csv_salida)
        resultado["reporte_errores"] = str(ruta_reporte)

        registrar_evento_seguridad(
            registrador=registrador,
            evento="INGESTION_SUCCESS",
            descripcion="Archivo procesado correctamente.",
            nivel=logging.INFO,
            archivo=ruta_validada.name,
            registros_leidos=total_leidos,
            registros_validos=conteo_escritos,
            salida=ruta_csv_salida.name,
        )

    except ErrorEventoSeguridad as error:
        resultado["error"] = str(error)
        registrar_evento_seguridad(
            registrador=registrador,
            evento="SECURITY_EVENT",
            descripcion=str(error),
            nivel=logging.ERROR,
            archivo=ruta_archivo.name,
        )

    except ErrorIngesta as error:
        resultado["error"] = str(error)
        registrar_evento_seguridad(
            registrador=registrador,
            evento="INGESTION_FAILURE",
            descripcion=str(error),
            nivel=logging.ERROR,
            archivo=ruta_archivo.name,
        )

    except Exception as error:  # ultima barrera: nunca dejar un error sin registrar
        resultado["error"] = f"Error inesperado: {error}"
        registrar_evento_seguridad(
            registrador=registrador,
            evento="UNEXPECTED_ERROR",
            descripcion=resultado["error"],
            nivel=logging.CRITICAL,
            archivo=ruta_archivo.name,
        )

    return resultado


# ---------------------------------------------------------------------------
# Punto de entrada usado por main.py (opcion 1 del menu)
# ---------------------------------------------------------------------------

def ejecutar(
    ruta: str,
    directorio_salida: Path = DIRECTORIO_SALIDA_PREDETERMINADO,
    directorio_log: Path = DIRECTORIO_LOG_PREDETERMINADO,
) -> dict[str, Any]:
    """Punto de entrada que main.py invoca para la opcion 'ingestion'.

    Lee el archivo .txt o .csv indicado en `ruta`, normaliza sus datos y
    controla los errores de entrada registrando eventos de seguridad.
    Genera un CSV normalizado y un reporte .txt de errores en `directorio_salida`,
    e imprime un resumen por consola para el usuario del menu.

    Devuelve el diccionario de resultado de `procesar_archivo`, por si en el
    futuro main.py quisiera usar el valor de retorno. Actualmente main.py
    llama `funcion(ruta)` sin capturar el resultado y sin ningun try/except
    alrededor de la llamada, por lo que esta funcion NUNCA debe propagar
    una excepcion: cualquier fallo inesperado se atrapa, se registra como
    evento de seguridad y se informa por consola, para no tumbar el menu.
    """
    resultado: dict[str, Any] = {"archivo": ruta, "estado": "error"}

    try:
        registrador = configurar_logging(directorio_log)
    except Exception as error:
        print("No fue posible inicializar el log de seguridad.")
        print(f"  Error: {error}")
        resultado["error"] = f"No fue posible inicializar el logging: {error}"
        return resultado

    try:
        registrar_evento_seguridad(
            registrador=registrador,
            evento="INGESTION_START",
            descripcion="Inicio del proceso de ingesta.",
            nivel=logging.INFO,
            archivo=ruta,
        )

        resultado = procesar_archivo(
            registrador=registrador,
            ruta_archivo=Path(ruta),
            directorio_salida=directorio_salida,
        )

        if resultado["estado"] == "success":
            print("Ingesta completada correctamente.")
            print(f"  Archivo analizado   : {resultado['archivo']}")
            print(f"  Registros leidos    : {resultado['registros_leidos']}")
            print(f"  Registros validos   : {resultado['registros_validos']}")
            print(f"  CSV normalizado     : {resultado['salida_csv']}")
            print(f"  Reporte de errores  : {resultado['reporte_errores']}")
        else:
            print("La ingesta no se pudo completar.")
            print(f"  Archivo  : {resultado['archivo']}")
            print(f"  Error    : {resultado.get('error', 'Error desconocido')}")

        registrar_evento_seguridad(
            registrador=registrador,
            evento="INGESTION_END",
            descripcion="Fin del proceso de ingesta.",
            nivel=logging.INFO,
            archivo=ruta,
            estado=resultado["estado"],
        )

    except Exception as error:
        # Barrera final: ejecutar(ruta) no debe nunca lanzar, porque
        # main.py la invoca sin try/except y eso detendria todo el menu.
        resultado["estado"] = "error"
        resultado["error"] = f"Error inesperado no controlado: {error}"
        registrar_evento_seguridad(
            registrador=registrador,
            evento="UNEXPECTED_ERROR",
            descripcion=resultado["error"],
            nivel=logging.CRITICAL,
            archivo=ruta,
        )
        print("Ocurrio un error inesperado durante la ingesta.")
        print(f"  Archivo  : {ruta}")
        print(f"  Error    : {error}")

    return resultado


# ---------------------------------------------------------------------------
# Modo por lotes (opcional, para pruebas fuera del menu de main.py)
# ---------------------------------------------------------------------------

def descubrir_archivos_entrada(directorio_entrada: Path) -> list[Path]:
    """Encuentra archivos .txt y .csv en el directorio de entrada."""
    if not directorio_entrada.exists():
        raise ErrorIngesta(f"El directorio de entrada no existe: '{directorio_entrada}'.")
    if not directorio_entrada.is_dir():
        raise ErrorIngesta(f"La ruta de entrada no es un directorio: '{directorio_entrada}'.")

    archivos_entrada = [
        candidato
        for candidato in directorio_entrada.iterdir()
        if candidato.is_file() and candidato.suffix.lower() in EXTENSIONES_SOPORTADAS
    ]
    return sorted(archivos_entrada)


def ejecutar_lote(directorio_entrada: Path, directorio_salida: Path, directorio_log: Path, fallo_rapido: bool) -> int:
    """Procesa todos los .txt/.csv de un directorio (modo utilitario de pruebas)."""
    registrador = configurar_logging(directorio_log)

    try:
        archivos_entrada = descubrir_archivos_entrada(directorio_entrada)
    except ErrorIngesta as error:
        registrar_evento_seguridad(registrador, "INGESTION_FAILURE", str(error), nivel=logging.ERROR)
        print(f"Error: {error}", file=sys.stderr)
        return 1

    if not archivos_entrada:
        registrar_evento_seguridad(
            registrador, "NO_INPUT_FILES",
            "No se encontraron archivos .txt o .csv para procesar.",
            nivel=logging.WARNING, directorio_entrada=str(directorio_entrada),
        )
        print("No se encontraron archivos .txt o .csv para procesar.")
        return 0

    procesados = fallidos = total_registros = 0

    for archivo_entrada in archivos_entrada:
        resultado = procesar_archivo(
            registrador=registrador,
            ruta_archivo=archivo_entrada,
            directorio_salida=directorio_salida,
            raiz_permitida=directorio_entrada,
        )
        if resultado["estado"] == "success":
            procesados += 1
            total_registros += resultado["registros_validos"]
        else:
            fallidos += 1
            print(f"  [ERROR] {archivo_entrada.name}: {resultado.get('error')}")
            if fallo_rapido:
                registrar_evento_seguridad(
                    registrador, "FAIL_FAST_ACTIVATED",
                    "Ejecucion detenida por --fail-fast tras un error.",
                    nivel=logging.ERROR, archivo=archivo_entrada.name,
                )
                return 1

    print(f"Archivos procesados: {procesados} | fallidos: {fallidos} | registros validos: {total_registros}")

    registrar_evento_seguridad(
        registrador, "INGESTION_SUMMARY", "Resumen final de ingesta por lotes.",
        nivel=logging.INFO,
        archivos_procesados=procesados, archivos_fallidos=fallidos,
        registros_totales=total_registros,
    )

    return 0 if fallidos == 0 else 1


def analizar_argumentos() -> argparse.Namespace:
    """Define y procesa los argumentos de linea de comandos del modo standalone."""
    analizador = argparse.ArgumentParser(description="Ingesta segura de archivos TXT y CSV.")
    analizador.add_argument(
        "ruta",
        nargs="?",
        default=None,
        help="Ruta de un archivo .txt o .csv a procesar (modo equivalente a ejecutar(ruta)).",
    )
    analizador.add_argument("--batch", dest="lote", action="store_true", help="Procesa todos los archivos de --input-dir.")
    analizador.add_argument("--input-dir", dest="directorio_entrada", type=Path, default=DIRECTORIO_ENTRADA_PREDETERMINADO, help="Directorio de entrada (modo --batch).")
    analizador.add_argument("--output-dir", dest="directorio_salida", type=Path, default=DIRECTORIO_SALIDA_PREDETERMINADO, help="Directorio de salida.")
    analizador.add_argument("--log-dir", dest="directorio_log", type=Path, default=DIRECTORIO_LOG_PREDETERMINADO, help="Directorio del log de seguridad.")
    analizador.add_argument("--fail-fast", dest="fallo_rapido", action="store_true", help="Detiene el lote ante el primer error.")
    return analizador.parse_args()


def principal() -> int:
    """Permite ejecutar este modulo de forma independiente para pruebas."""
    argumentos = analizar_argumentos()

    if argumentos.lote:
        return ejecutar_lote(
            directorio_entrada=argumentos.directorio_entrada,
            directorio_salida=argumentos.directorio_salida,
            directorio_log=argumentos.directorio_log,
            fallo_rapido=argumentos.fallo_rapido,
        )

    if not argumentos.ruta:
        print("Debe indicar la ruta de un archivo .txt o .csv, o usar --batch.", file=sys.stderr)
        return 1

    resultado = ejecutar(argumentos.ruta, directorio_salida=argumentos.directorio_salida, directorio_log=argumentos.directorio_log)
    return 0 if resultado["estado"] == "success" else 1


if __name__ == "__main__":
    sys.exit(principal())