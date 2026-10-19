```
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
```

**CyberGuard Analyzer** es un programa en Python por linea de comandos para el Proyecto Integrador de *Programacion para Ciberseguridad* (ULACIT). Recibe un archivo `.txt` o `.csv` con eventos de red **sinteticos**, lo lee, limpia y valida los datos, revisa la integridad del archivo con SHA-256, busca comportamientos sospechosos de TCP/HTTP e indicadores de persistencia, y guarda el resultado en un reporte `.txt`.

Esta version corresponde al **Avance 1 (semana 6)**.

## Estructura del proyecto

```
.
├── main.py               # menu principal, llama a los modulos y guarda el reporte
├── ingestion.py          # lee el archivo .txt/.csv y controla errores de entrada
├── validation.py         # sanitiza cadenas y valida los campos de cada registro
├── integrity.py          # calcula y compara el hash SHA-256 del archivo
├── network_analyzer.py   # analiza el trafico TCP/HTTP y busca persistencia
├── input/                # archivos de entrada (datos de prueba)
│   └── eventos_prueba.txt
├── output/               # aqui se guardan los reportes .txt
├── requirements.txt
└── README.md
```

## Requisitos

- Python 3.8 o superior.
- No se necesitan librerias externas, solo la libreria estandar de Python (`os`, `sys`, `hashlib`, `datetime`).

## Como ejecutar

Desde la carpeta del proyecto:

```bash
python3 main.py
```

El programa pide la ruta del archivo. Se puede escribir la ruta completa (`input/eventos_prueba.txt`) o solo el nombre (`eventos_prueba.txt`) y el programa lo busca en la carpeta `input`.

Tambien se puede pasar el archivo directamente:

```bash
python3 main.py input/eventos_prueba.txt
```

(Opcional) si se quiere usar un entorno virtual:

```bash
python3 -m venv venv
source venv/bin/activate
```

## Menu

```
[1] Ingesta: leer el archivo y controlar errores de entrada
[2] Validacion: sanitizar y validar los campos de cada registro
[3] Integridad: calcular y comparar el hash SHA-256
[4] Analisis TCP/HTTP y persistencia
[5] Analisis completo (todo lo anterior)
[6] Cambiar de archivo
[7] Salir
```

Cada opcion muestra el resultado en pantalla y lo guarda en `output/reporte_<nombre del archivo>.txt`. Por ejemplo, al analizar `eventos_prueba.txt` se crea `output/reporte_eventos_prueba.txt`. En la carpeta `output` hay un reporte de ejemplo generado con la opcion 5.

## Formato del archivo de entrada

- `.txt`: campos separados por `|`
- `.csv`: campos separados por `,`
- Las lineas que empiezan con `#` son comentarios y las lineas vacias se ignoran.
- La primera linea con datos tiene que ser el encabezado:

```
fecha|ip_origen|ip_destino|puerto_origen|puerto_destino|protocolo|flags|metodo|ruta|bytes
2026-10-16 14:01:02|10.0.0.15|10.0.0.8|51432|443|HTTPS|PA|GET|/index.html|1820
```

| Campo | Ejemplo | Regla de validacion |
|---|---|---|
| fecha | `2026-10-16 14:01:02` | formato `AAAA-MM-DD HH:MM:SS` |
| ip_origen / ip_destino | `10.0.0.15` | 4 numeros entre 0 y 255 |
| puerto_origen / puerto_destino | `443` | numero entre 0 y 65535 |
| protocolo | `TCP`, `UDP`, `HTTP`, `HTTPS` | tiene que estar en la lista |
| flags | `S`, `SA`, `PA` | banderas TCP (S = SYN, A = ACK, P = PUSH) |
| metodo | `GET`, `POST`, `PUT`... o `-` | `-` si no es HTTP |
| ruta | `/login` o `-` | ruta pedida en HTTP |
| bytes | `1820` | numero entero positivo |

## Que hace cada modulo

**ingestion.py**
- Revisa que el archivo exista, que sea un archivo, que tenga extension `.txt` o `.csv`, que no este vacio y que no pase de 5 MB.
- Revisa que el encabezado sea el correcto (si no, avisa de formato incorrecto).
- Separa cada linea en campos. Si una linea no tiene 10 campos se reporta como malformada y se sigue con la siguiente.
- Limpia cada campo con `validation.limpiar_texto` y avisa cuando un campo fue sanitizado.

**validation.py**
- `limpiar_texto`: quita caracteres de control (`\x00`, `\n`, `\t`...), quita caracteres peligrosos (`< > ; ' " `` ` ``), quita espacios al inicio/final y corta los textos de mas de 200 caracteres.
- Valida campos obligatorios, fechas, IPs, puertos, protocolo, metodo y bytes. Cada registro con error se reporta con su numero de linea.

**integrity.py**
- Calcula el SHA-256 del archivo de entrada.
- La primera vez guarda el hash como referencia en `output/hashes_referencia.txt`. Las siguientes veces lo compara: si es igual dice **OK**, si cambio dice **ALERTA, el archivo fue MODIFICADO**.
- Hace una demostracion: agrega un espacio al contenido (solo en memoria, sin tocar el archivo) y muestra que el hash sale totalmente diferente.

**network_analyzer.py** — reglas que aplica (los valores se pueden cambiar al inicio del archivo):

| # | Regla | Condicion | Severidad |
|---|---|---|---|
| 1 | Puerto inseguro | puerto destino 21 (FTP), 23 (Telnet), 110 (POP3), 143 (IMAP) | ALTA |
| 2 | HTTP sin cifrar | protocolo HTTP o puerto 80 / 8080 | MEDIA |
| 3 | Metodo HTTP inseguro | PUT, DELETE, TRACE, CONNECT | ALTA |
| 4 | Posible escaneo de puertos | una IP manda SYN (sin ACK) a 5 o mas puertos distintos | ALTA |
| 5 | Posible exfiltracion | 1 000 000 bytes o mas en una conexion | ALTA |
| 6 | Indicador de persistencia | la ruta contiene `authorized_keys`, `cron`, `.bashrc`, `rc.local`, `startup`, `currentversion/run`, `systemd` o `launchagents` | ALTA |

Cada hallazgo indica la regla que se aplico y la evidencia (numero de linea, IPs y puerto) para que se pueda rastrear.

## Casos de prueba

Pruebas hechas a mano ejecutando `main.py` con el archivo de prueba y con archivos creados para cada caso.

| ID | Tipo | Pasos / datos | Resultado esperado | Resultado obtenido | Estado |
|---|---|---|---|---|---|
| CP-01 | Positivo | Opcion 5 con `input/eventos_prueba.txt` | Se leen los registros, se detectan hallazgos y se crea `output/reporte_eventos_prueba.txt` | 22 registros leidos, 16 validos, 13 hallazgos (10 ALTA, 3 MEDIA), reporte creado | Aprobado |
| CP-02 | Positivo | Opcion 4 con el mismo contenido pero en `.csv` (separado por comas) | Mismos hallazgos que con el `.txt` | 16 registros analizados, 13 hallazgos | Aprobado |
| CP-03 | Negativo | Linea con solo 6 campos (linea 34 del archivo de prueba) | Se reporta como malformada y el programa sigue | `Linea 34: tiene 6 campos y se esperaban 10` | Aprobado |
| CP-04 | Negativo | Lineas con IP `999.1.1.1`, puerto `70000`, fecha `16/10/2026`, bytes `muchos`, IP vacia, protocolo `FTPX` | Cada linea se rechaza con su motivo | 6 registros con error, cada uno con linea y motivo | Aprobado |
| CP-05 | Sanitizacion | Ruta `/buscar?q=<script>alert(1)</script>` (linea 31) | Se quitan los caracteres `< >` y se avisa | `se limpiaron caracteres no permitidos en 'ruta' -> /buscar?q=scriptalert(1)/script` | Aprobado |
| CP-06 | Excepcion | Ruta a un archivo que no existe (`no_existe.txt`) | Mensaje de error, el programa no se cierra | `El archivo no existe: ...` y el menu sigue funcionando | Aprobado |
| CP-07 | Excepcion | Archivo con extension `.exe` | Se rechaza por extension | `Extension no permitida '.exe'. Solo se aceptan archivos .txt o .csv` | Aprobado |
| CP-08 | Excepcion | Archivo `.txt` vacio | Se rechaza por estar vacio | `El archivo esta vacio: ...` | Aprobado |
| CP-09 | Excepcion | `.csv` con encabezado diferente (`id,usuario`) | Error de formato incorrecto | `Formato incorrecto: el encabezado tiene que ser fecha,ip_origen,...` | Aprobado |
| CP-10 | Integridad | Opcion 3, se agrega una linea al archivo y se ejecuta la opcion 3 otra vez | La primera vez guarda el hash; la segunda dice que fue modificado | `PRIMERA VEZ...` y luego `ALERTA, el archivo fue MODIFICADO` con hash esperado y actual distintos | Aprobado |
| CP-11 | Deteccion | Opcion 4 con el archivo de prueba | Se detecta escaneo y persistencia | `10.0.0.66 envio SYN a 6 puertos`, `Indicador de persistencia (authorized_keys)` y `(cron)` | Aprobado |
| CP-12 | Negativo | Elegir la opcion `9` en el menu | Mensaje de opcion no valida | `[!] opcion no valida` y vuelve al menu | Aprobado |

Para repetir CP-10 sin cambiar el archivo de prueba original, se puede copiar `input/eventos_prueba.txt` a otro archivo y modificar la copia. Para empezar desde cero se borra `output/hashes_referencia.txt`.

## Alcance etico

- Todos los datos de `input/` son **sinteticos**: IPs privadas inventadas (`10.0.0.x`) y eventos creados para el laboratorio.
- El programa solo **lee y analiza** archivos locales. No escanea redes, no se conecta a internet y no ejecuta ningun ataque.
- El texto `<script>` del archivo de prueba es solo un ejemplo para probar la sanitizacion, nunca se ejecuta.
- No hay contrasenas, llaves ni datos personales en el repositorio.

## Uso de inteligencia artificial

Se uso un asistente de IA (Claude) como apoyo para revisar errores del codigo, simplificar los modulos y redactar este README. El equipo reviso y probo el resultado.
