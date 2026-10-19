# network_analyzer.py
# Analisis de un archivo de trafico de red sintetico, busqueda de sospechas
# (puertos inseguros, HTTP sin cifrar, metodos inseguros, escaneo de puertos,
# posible exfiltracion e indicadores de persistencia)

# ----- Configuracion (valores que se pueden cambiar) -----
PUERTOS_INSEGUROS = {21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP"}
PUERTOS_HTTP = [80, 8080]
METODOS_INSEGUROS = ["PUT", "DELETE", "TRACE", "CONNECT"]
UMBRAL_ESCANEO = 5        # puertos distintos con SYN desde una misma IP
UMBRAL_BYTES = 1000000    # bytes salientes que se consideran sospechosos
# rutas o archivos que se usan para que un atacante se quede en el sistema (persistencia)
INDICADORES_PERSISTENCIA = ["authorized_keys", "cron", ".bashrc", "rc.local",
                            "startup", "currentversion/run", "systemd", "launchagents"]


def crear_hallazgo(regla, severidad, evidencia):
    """Guarda un hallazgo con la regla que lo detecto y su evidencia"""
    return {"regla": regla, "severidad": severidad, "evidencia": evidencia}


def analizar(registros):
    """Aplica las reglas a los registros validos y devuelve los hallazgos"""
    hallazgos = []
    puertos_por_origen = {}   # IP origen -> lista de puertos con SYN

    for r in registros:
        puerto = r["puerto_destino"]
        texto = "Linea " + str(r["linea"]) + ": " + r["ip_origen"] + " -> " + r["ip_destino"] + ":" + str(puerto)

        # Regla 1: puerto inseguro
        if puerto in PUERTOS_INSEGUROS:
            nombre = PUERTOS_INSEGUROS[puerto]
            hallazgos.append(crear_hallazgo("Puerto inseguro (" + nombre + ")", "ALTA", texto))

        # Regla 2: HTTP sin cifrar
        if r["protocolo"] == "HTTP" or puerto in PUERTOS_HTTP:
            hallazgos.append(crear_hallazgo("HTTP sin cifrar", "MEDIA", texto))

        # Regla 3: metodo HTTP inseguro
        if r["metodo"] in METODOS_INSEGUROS:
            hallazgos.append(crear_hallazgo("Metodo HTTP inseguro (" + r["metodo"] + ")", "ALTA", texto))

        # Regla 4: primera parte, guardar los puertos a los que cada IP manda SYN (sin ACK)
        if "S" in r["flags"] and "A" not in r["flags"]:
            if r["ip_origen"] not in puertos_por_origen:
                puertos_por_origen[r["ip_origen"]] = []
            if puerto not in puertos_por_origen[r["ip_origen"]]:
                puertos_por_origen[r["ip_origen"]].append(puerto)

        # Regla 5: posible exfiltracion (exceso de trafico saliente)
        if r["bytes"] >= UMBRAL_BYTES:
            hallazgos.append(crear_hallazgo("Posible exfiltracion", "ALTA",
                                            texto + " (" + str(r["bytes"]) + " bytes)"))

        # Regla 6: indicador de persistencia en la ruta pedida
        ruta = r["ruta"].lower()
        for indicador in INDICADORES_PERSISTENCIA:
            if indicador in ruta:
                hallazgos.append(crear_hallazgo("Indicador de persistencia (" + indicador + ")", "ALTA",
                                                texto + " " + r["metodo"] + " " + r["ruta"]))
                break

    # Regla 4: segunda parte, revisa cuantos puertos toco cada IP
    for ip in puertos_por_origen:
        cantidad = len(puertos_por_origen[ip])
        if cantidad >= UMBRAL_ESCANEO:
            evidencia = ip + " envio SYN a " + str(cantidad) + " puertos: " + str(puertos_por_origen[ip])
            hallazgos.append(crear_hallazgo("Posible escaneo de puertos", "ALTA", evidencia))

    return hallazgos


def contar_por_severidad(hallazgos):
    """Cuenta cuantos hallazgos hay de cada severidad"""
    conteo = {}
    for h in hallazgos:
        if h["severidad"] not in conteo:
            conteo[h["severidad"]] = 0
        conteo[h["severidad"]] = conteo[h["severidad"]] + 1
    return conteo


def crear_reporte(registros, hallazgos):
    """Devuelve las lineas de texto del reporte del analisis de red"""
    lineas = []
    lineas.append("=== ANALISIS TCP/HTTP Y PERSISTENCIA ===")
    lineas.append("Registros analizados: " + str(len(registros)))
    lineas.append("Hallazgos: " + str(len(hallazgos)))

    conteo = contar_por_severidad(hallazgos)
    for severidad in conteo:
        lineas.append("  Severidad " + severidad + ": " + str(conteo[severidad]))

    for h in hallazgos:
        lineas.append("- [" + h["severidad"] + "] " + h["regla"])
        lineas.append("    Evidencia: " + h["evidencia"])

    return lineas
