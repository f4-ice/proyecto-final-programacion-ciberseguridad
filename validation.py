# validation.py
# Sanitiza (limpia) cadenas de texto y valida los campos de cada registro.

from datetime import datetime

# ----- Configuracion -----
LARGO_MAXIMO_CAMPO = 200
CARACTERES_PELIGROSOS = "<>;`'\""
CAMPOS_OBLIGATORIOS = ["fecha", "ip_origen", "ip_destino", "puerto_origen",
                       "puerto_destino", "protocolo", "bytes"]
FORMATO_FECHA = "%Y-%m-%d %H:%M:%S"
PROTOCOLOS_VALIDOS = ["TCP", "UDP", "HTTP", "HTTPS"]
METODOS_VALIDOS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS",
                   "PATCH", "TRACE", "CONNECT", "-"]


def limpiar_texto(texto):
    """Quita caracteres de control y caracteres peligrosos, y corta textos muy largos"""
    limpio = ""
    for letra in texto:
        # los caracteres con codigo menor a 32 (y el 127) son de control: \n, \t, \x00, etc.
        if ord(letra) < 32 or ord(letra) == 127:
            continue
        if letra in CARACTERES_PELIGROSOS:
            continue
        limpio = limpio + letra

    limpio = limpio.strip()

    if len(limpio) > LARGO_MAXIMO_CAMPO:
        limpio = limpio[:LARGO_MAXIMO_CAMPO]

    return limpio


def es_numero_entero(texto):
    """Revisa que el texto sea un numero entero positivo"""
    return texto.isdigit()


def es_ip_valida(ip):
    """Revisa que la IP tenga 4 numeros entre 0 y 255 separados por puntos"""
    partes = ip.split(".")
    if len(partes) != 4:
        return False
    for parte in partes:
        if not parte.isdigit():
            return False
        if int(parte) > 255:
            return False
    return True


def es_puerto_valido(puerto):
    """Revisa que el puerto sea un numero entre 0 y 65535"""
    if not es_numero_entero(puerto):
        return False
    return int(puerto) <= 65535


def es_fecha_valida(fecha):
    """Revisa que la fecha tenga el formato AAAA-MM-DD HH:MM:SS"""
    try:
        datetime.strptime(fecha, FORMATO_FECHA)
        return True
    except ValueError:
        return False


def validar_registro(registro):
    """Revisa un registro y devuelve una lista con los problemas encontrados"""
    problemas = []

    # 1. Los campos obligatorios no pueden estar vacios
    for campo in CAMPOS_OBLIGATORIOS:
        if registro[campo] == "":
            problemas.append("falta el campo '" + campo + "'")

    # si faltan campos no tiene sentido seguir revisando
    if len(problemas) > 0:
        return problemas

    # 2. Revisar el formato de cada campo
    if not es_fecha_valida(registro["fecha"]):
        problemas.append("fecha invalida '" + registro["fecha"] + "'")

    if not es_ip_valida(registro["ip_origen"]):
        problemas.append("IP de origen invalida '" + registro["ip_origen"] + "'")

    if not es_ip_valida(registro["ip_destino"]):
        problemas.append("IP de destino invalida '" + registro["ip_destino"] + "'")

    if not es_puerto_valido(registro["puerto_origen"]):
        problemas.append("puerto de origen invalido '" + registro["puerto_origen"] + "'")

    if not es_puerto_valido(registro["puerto_destino"]):
        problemas.append("puerto de destino invalido '" + registro["puerto_destino"] + "'")

    if registro["protocolo"].upper() not in PROTOCOLOS_VALIDOS:
        problemas.append("protocolo desconocido '" + registro["protocolo"] + "'")

    if registro["metodo"].upper() not in METODOS_VALIDOS:
        problemas.append("metodo HTTP desconocido '" + registro["metodo"] + "'")

    if not es_numero_entero(registro["bytes"]):
        problemas.append("bytes invalido '" + registro["bytes"] + "'")

    return problemas


def validar_registros(registros):
    """Separa los registros validos de los que tienen errores"""
    validos = []
    errores = []

    for registro in registros:
        problemas = validar_registro(registro)

        if len(problemas) > 0:
            errores.append("Linea " + str(registro["linea"]) + ": " + ", ".join(problemas))
            continue

        # el registro esta bien: pasamos los numeros a int y el texto a mayusculas
        registro["puerto_origen"] = int(registro["puerto_origen"])
        registro["puerto_destino"] = int(registro["puerto_destino"])
        registro["bytes"] = int(registro["bytes"])
        registro["protocolo"] = registro["protocolo"].upper()
        registro["flags"] = registro["flags"].upper()
        registro["metodo"] = registro["metodo"].upper()
        validos.append(registro)

    return validos, errores


def crear_reporte(validos, errores):
    """Devuelve las lineas de texto del reporte de validacion"""
    lineas = []
    lineas.append("=== VALIDACION DE REGISTROS ===")
    lineas.append("Registros revisados: " + str(len(validos) + len(errores)))
    lineas.append("Registros validos: " + str(len(validos)))
    lineas.append("Registros con errores: " + str(len(errores)))

    for error in errores:
        lineas.append("  [!] " + error)

    return lineas
