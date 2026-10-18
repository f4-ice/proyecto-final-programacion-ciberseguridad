"""Pruebas del MVP - Avance 1 (CyberGuard Analyzer).

Ejecutar desde la raiz del repo:
    python -m unittest -v tests/test_mvp.py
"""
import hashlib
import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

import ingestion  # noqa: E402


def crear_archivo(directorio, nombre, contenido):
    ruta = Path(directorio) / nombre
    ruta.write_text(contenido, encoding="utf-8")
    return ruta


class PruebasIngesta(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.salida = self.dir / "output"
        self.logs = self.dir / "logs"

    def tearDown(self):
        self.tmp.cleanup()

    def ejecutar(self, ruta):
        return ingestion.ejecutar(str(ruta), directorio_salida=self.salida, directorio_log=self.logs)

    # CP-01 positivo
    def test_cp01_csv_valido(self):
        ruta = crear_archivo(self.dir, "eventos.csv",
                            "id,fecha,usuario\n1,2026-10-16,ana\n2,2026-10-16,luis\n")
        r = self.ejecutar(ruta)
        self.assertEqual(r["estado"], "success")
        self.assertEqual(r["registros_validos"], 2)

    # CP-02 negativo: lineas malformadas
    def test_cp02_csv_con_registros_invalidos(self):
        ruta = crear_archivo(self.dir, "mixto.csv",
                            "id,fecha\n1,2026-10-16\n,2026-10-16\n3,fecha-mala\n")
        r = self.ejecutar(ruta)
        self.assertEqual(r["estado"], "success")
        self.assertLess(r["registros_validos"], r["registros_leidos"])

    # CP-03 excepcion: archivo inexistente
    def test_cp03_archivo_inexistente(self):
        r = self.ejecutar(self.dir / "no_existe.csv")
        self.assertEqual(r["estado"], "error")
        self.assertIn("no existe", r["error"])

    # CP-04 excepcion: extension no permitida
    def test_cp04_extension_no_permitida(self):
        ruta = crear_archivo(self.dir, "malware.exe", "x")
        r = self.ejecutar(ruta)
        self.assertEqual(r["estado"], "error")
        self.assertIn("Extension no permitida", r["error"])

    # CP-05 excepcion: archivo vacio
    def test_cp05_archivo_vacio(self):
        ruta = crear_archivo(self.dir, "vacio.txt", "")
        r = self.ejecutar(ruta)
        self.assertEqual(r["estado"], "error")
        self.assertIn("vacio", r["error"])

    # CP-06 seguridad: sanitizacion de caracteres de control
    def test_cp06_sanitizacion(self):
        limpio = ingestion.normalizar_texto("ad\x00min\x1b[31m  root")
        self.assertNotIn("\x00", limpio)
        self.assertNotIn("\x1b", limpio)


class PruebasIntegridad(unittest.TestCase):
    # CP-07 integridad: archivo modificado produce otro SHA-256
    def test_cp07_hash_cambia_al_modificar(self):
        integrity = importlib.import_module("integrity")
        with tempfile.TemporaryDirectory() as tmp:
            ruta = crear_archivo(tmp, "evidencia.txt", "evento original\n")
            h1 = integrity.calcular_sha256(ruta)
            self.assertEqual(h1, hashlib.sha256(b"evento original\n").hexdigest())
            ruta.write_text("evento alterado\n", encoding="utf-8")
            self.assertNotEqual(h1, integrity.calcular_sha256(ruta))

    # CP-08 integracion: los modulos del menu cargan y tienen ejecutar(ruta)
    def test_cp08_modulos_del_menu(self):
        for nombre in ("ingestion", "validation", "integrity", "network_analyzer"):
            with self.subTest(modulo=nombre):
                modulo = importlib.import_module(nombre)
                self.assertTrue(hasattr(modulo, "ejecutar"), f"{nombre}.py no tiene ejecutar(ruta)")


if __name__ == "__main__":
    unittest.main(verbosity=2)