#network_analyzer
#Amalisis de un archivo de trafico de red sintentico, busqueda de sospechas

#----- Configuracion (valores variables) -----
PUERTOS_INSEGUROS = {21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP"}
PUERTOS_HTTP = [80, 8080]
METODOS_INSEGUROS = ["PUT", "DELETE", "TRACE", "CONNECT"]
UMBRAL_ESCANEO = 5     # puertos distintos con SYN desde una misma IP
UMBRAL_BYTES = 1000000    # bytes salientes que se consideran sospechosos 

def leer_archivo(ruta):
    """Leer archivo y regresa la lista de registros validos y errores"""
    registros = []
    errores = []

    try:
        archivo = open(ruta, "r", encoding="utf-8")
    except FileNotFoundError:
        errores.append("El archivo no existe: " + ruta)
        return registros, errores

    lineas = archivo.readlines()
    archivo.close()
    if len(lineas) = 0 or lineas[0].strip() == "":
        errores.append("El archivo esta vacio")
        return registros, errores

    #Si el encabezadp trae "|" el separador es "|", si no es la coma
    separador = ","
    if "|" in lineas[0]:
        separador = "|"

    for i in range(1, len(lineas)):
        numero_linea = i + 1
        if lineas[i].strip() == "":
            continue
        partes = lineas[i].strip().split(separador)

        if len(partes) != 9:
            errores.append("Linea " + str(numero_linea) + ": formato incorrecto")
            continue

        try:
            registro = {
                "linea": numero_linea,
                "origen": partes[1].strip(),
                "destino": partes[2].strip(),
                "puerto": int(partes[4]),
                "protocolo": partes[5].strip().upper(),
                "flags": partes[6].strip().upper(),
                "metodo": partes[7].strip().upper(),
                "bytes": int(partes[8]),
            }

        except ValueError:
            errores.append("Linea " + str(numero_linea) + ": numero invalido")
            continue

        if registro["puerto"] < 0 or registro["puerto"] > 65535:
            errores.append("Linea " + str(numero_linea) + ": puerto fuera de rango")
            continue

        registros.append(registro)

    return registros, errores

def crear_hallazgo(regla, severidad, evidencia):
    """Guardar un hallazgo con la regla que lo detecto y su evidencia"""
    return {"regla": regla, "severidad": severidad, "evidencia": evidencia}

def analizar(registros):
    """Aplica las reglas a los registros y devuelve los hallazgos"""
    hallazgos = []
    puertos_por_origen = {}   #IP origen -> lista de puertos con SYN

    for r in registros:
        texto = "Linea " + str(r["linea"]) + ": " + r["origen"] + " -> " + r["destino"] + ":" + str(r["puerto"])

        # Regla 1: puerto inseguro
        if r["puerto"] in PUERTOS_INSEGUROS:
            nombre = PUERTOS_INSEGUROS[r["puerto"]]
            hallazgos.append(crear_hallazgo("Puerto inseguro (" + nombre + ")", "ALTA", texto))

        # Regla 2: HTTP sin cifrar
        if r["protocolo"] == "HTTP" or r["puerto"] in PUERTOS_HTTP:
            hallazgos.append(crear_hallazgo("HTTP sin cifrar", "MEDIA", texto))

        # Regla 3: metodo HTTP inseguro 
        if r["metodo"] in METODOS_INSEGUROS:
            hallazgos.append(crear_hallazgo("Metodo HTTP inseguro (" + r["metodo"] + ")", "ALTA", texto))

        # Regla 4: primera parte, guardar los puertos a los que cada IP manda SYN
        if "S" in r["flags"] and "A" not in r["flags"]:
            if r["origen"] not in puertos_por_origen:
                puertos_por_origen[r["origen"]] = []
            if r["puerto"] not in puertos_por_origen[r["origen"]]:
                puertos_por_origen[r["origen"]].append(r["puerto"])

        # Regla 5: posible exfiltracion (exceso de trafico saliente)
        if r["bytes"] >= UMBRAL_BYTES:
            hallazgos.append(crear_hallazgo("Posible exfiltracion", "ALTA", texto + " (" + str(r["bytes"]) + " bytes"))

    # Regla 4: segunda parte revisa cuantos puertos toco cada IP 
    for ip in puertos_por_origen:
        cantidad = len(puertos_por_origen[ip])
        if cantidad >= UMBRAL_ESCANEO:
            evidencia = ip + " envio SYN a " + str(cantidad) + " puertos: " + str(puertos_por_origen[ip])
            hallazgos.append(crear_hallazgo("Posible escaneo de puertos", "ALTA", evidencia))

    return hallazgos

def analizar_trafico(ruta):
    """Funcion para usar los otros modulos del programa"""
    registros, errores = leer_archivo(ruta)
    hallazgos = analizar(registros)
    return {"registros": len(registros), "errores": errores, "hallazgos": hallazgos}

def mostrar(resultado):
    print("==== ANALISIS TCP/HTTP ===")
    print("Registros validos:", resultado["registros"])
    print("Errores:", len(resultado["errores"]))
    for e in resultado["errores"]:
        print(" [!]", e)
    print("Hallazgos:", len(resultado["hallazgos"]))
    for h in resultado["hallazgos"]:
        print("-", h["severidad"], "|", h["regla"])
        print("   Evidencia:", h["evidencia"])

def ejecutar(ruta):
    """Punto de entrada que llama main.py (opcion 4 del menu). Nunca lanza errores"""
    try:
        resultado = analizar_trafico(ruta)
        mostrar(resultado)
        if resultado["registros"] == 0:
            resultado["estado"] = "error"
        else:
            resultado["estado"] = "success"
    except Exception as error:
        print("[!] Error inesperado en programa de analisis:", error)
        resultado = {"estado": "error", "error": str(error)}
    return resultado

if __name__ == "__main__":
    ejecutar("data/trafico_sint.csv")
