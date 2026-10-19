# ingestion.py
# Lee el archivo de eventos (.txt o .csv), lo separa en registros
# y controla los errores de entrada (archivo inexistente, vacio, lineas malformadas...)

import os

import validation

# ----- Configuracion -----
EXTENSIONES_PERMITIDAS = [".txt", ".csv"]
TAMANO_MAXIMO = 5 * 1024 * 1024   # 5 MB
LARGO_MAXIMO_LINEA = 1000
SEPARADOR_TXT = "|"
SEPARADOR_CSV = ","
COLUMNAS = ["fecha", "ip_origen", "ip_destino", "puerto_origen", "puerto_destino",
            "protocolo", "flags", "metodo", "ruta", "bytes"]


def revisar_archivo(ruta):
    """Revisa el archivo antes de leerlo. Devuelve un mensaje de error o "" si esta bien"""
    if ruta == "":
        return "No se indico ningun archivo"

    if not os.path.exists(ruta):
        return "El archivo no existe: " + ruta

    if not os.path.isfile(ruta):
        return "La ruta no es un archivo: " + ruta

    extension = os.path.splitext(ruta)[1].lower()
    if extension not in EXTENSIONES_PERMITIDAS:
        return "Extension no permitida '" + extension + "'. Solo se aceptan archivos .txt o .csv"

    tamano = os.path.getsize(ruta)
    if tamano == 0:
        return "El archivo esta vacio: " + ruta
    if tamano > TAMANO_MAXIMO:
        return "El archivo es demasiado grande (maximo " + str(TAMANO_MAXIMO) + " bytes)"

    return ""


def obtener_separador(ruta):
    """Los .csv se separan con coma y los .txt con |"""
    if ruta.lower().endswith(".csv"):
        return SEPARADOR_CSV
    return SEPARADOR_TXT


def leer_eventos(ruta):
    """Lee el archivo y devuelve tres listas: registros, errores y avisos de sanitizacion"""
    registros = []
    errores = []
    avisos = []

    mensaje = revisar_archivo(ruta)
    if mensaje != "":
        errores.append(mensaje)
        return registros, errores, avisos

    try:
        archivo = open(ruta, "r", encoding="utf-8")
        lineas = archivo.readlines()
        archivo.close()
    except UnicodeDecodeError:
        errores.append("El archivo no es de texto (no se pudo leer como UTF-8)")
        return registros, errores, avisos
    except OSError as error:
        errores.append("No se pudo abrir el archivo: " + str(error))
        return registros, errores, avisos

    separador = obtener_separador(ruta)
    encabezado_leido = False
    numero_linea = 0

    for linea in lineas:
        numero_linea = numero_linea + 1
        linea = linea.strip()

        # se ignoran las lineas vacias y los comentarios
        if linea == "" or linea.startswith("#"):
            continue

        if len(linea) > LARGO_MAXIMO_LINEA:
            errores.append("Linea " + str(numero_linea) + ": la linea es demasiado larga")
            continue

        partes = linea.split(separador)

        # la primera linea con datos es el encabezado y tiene que ser igual a COLUMNAS
        if not encabezado_leido:
            encabezado = []
            for parte in partes:
                encabezado.append(parte.strip().lower())
            if encabezado != COLUMNAS:
                errores.append("Formato incorrecto: el encabezado tiene que ser "
                               + separador.join(COLUMNAS))
                return registros, errores, avisos
            encabezado_leido = True
            continue

        if len(partes) != len(COLUMNAS):
            errores.append("Linea " + str(numero_linea) + ": tiene " + str(len(partes))
                           + " campos y se esperaban " + str(len(COLUMNAS)))
            continue

        # armar el registro y limpiar cada campo
        registro = {"linea": numero_linea}
        for i in range(len(COLUMNAS)):
            original = partes[i].strip()
            limpio = validation.limpiar_texto(original)
            if limpio != original:
                avisos.append("Linea " + str(numero_linea) + ": se limpiaron caracteres no permitidos en '"
                              + COLUMNAS[i] + "' -> " + limpio)
            registro[COLUMNAS[i]] = limpio

        registros.append(registro)

    if not encabezado_leido:
        errores.append("El archivo no tiene datos, solo comentarios o lineas vacias")

    return registros, errores, avisos


def crear_reporte(ruta, registros, errores, avisos):
    """Devuelve las lineas de texto del reporte de ingesta"""
    lineas = []
    lineas.append("=== INGESTA DEL ARCHIVO ===")
    lineas.append("Archivo: " + ruta)
    lineas.append("Registros leidos: " + str(len(registros)))
    lineas.append("Errores de entrada: " + str(len(errores)))

    for error in errores:
        lineas.append("  [!] " + error)

    lineas.append("Campos sanitizados: " + str(len(avisos)))
    for aviso in avisos:
        lineas.append("  [*] " + aviso)

    return lineas
