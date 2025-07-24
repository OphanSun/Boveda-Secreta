# diario_secreto.py

# 1. Importaciones
import base64
import json
import os
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass

# --- El código del motor (secciones 2 y 3) no cambia ---
NOMBRE_ARCHIVO = "diario.dat"

def generar_clave_desde_contrasena(contrasena_maestra, salt=b'salt_fijo_para_el_proyecto_'):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    return base64.urlsafe_b64encode(kdf.derive(contrasena_maestra.encode()))

def encriptar_datos(datos_json, clave):
    f = Fernet(clave)
    return f.encrypt(datos_json.encode())

def desencriptar_datos(datos_encriptados, clave):
    f = Fernet(clave)
    try:
        return f.decrypt(datos_encriptados).decode()
    except Exception:
        return None

def cargar_diario(clave):
    try:
        with open(NOMBRE_ARCHIVO, "rb") as f:
            datos_encriptados = f.read()
        datos_json = desencriptar_datos(datos_encriptados, clave)
        if datos_json is None: return None
        return json.loads(datos_json)
    except FileNotFoundError:
        return []

def guardar_diario(entradas, clave):
    datos_json = json.dumps(entradas, indent=2, ensure_ascii=False)
    datos_encriptados = encriptar_datos(datos_json, clave)
    with open(NOMBRE_ARCHIVO, "wb") as f:
        f.write(datos_encriptados)

# --- NUEVA SECCIÓN 4: FUNCIONES DE LA APLICACIÓN ---

def anadir_entrada(diario):
    """Pide al usuario una nueva entrada y la añade a la lista del diario."""
    print("\n--- Nueva Entrada ---")
    # input() permite escribir varias líneas hasta que se presiona Enter en una línea vacía.
    print("Escribe tu entrada. Presiona Enter dos veces para guardar.")
    
    texto_entrada = []
    while True:
        linea = input()
        if not linea:
            break
        texto_entrada.append(linea)
    
    texto_final = "\n".join(texto_entrada)
    
    if texto_final:
        fecha_hoy = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        nueva_entrada = {"fecha": fecha_hoy, "texto": texto_final}
        diario.append(nueva_entrada)
        print("\n✅ ¡Entrada guardada con éxito!")
    else:
        print("\n❌ Entrada vacía. No se guardó nada.")

def ver_entradas(diario):
    """Muestra todas las entradas del diario en orden cronológico."""
    print("\n--- Tus Entradas del Diario ---")
    if not diario:
        print("Aún no tienes ninguna entrada.")
    else:
        # Mostramos las entradas de la más reciente a la más antigua
        for entrada in reversed(diario):
            print(f"\n📅 Fecha: {entrada['fecha']}")
            print("-" * 20)
            print(entrada['texto'])
            print("-" * 20)
    print("\n")

# --- NUEVA SECCIÓN 5: EL BUCLE PRINCIPAL DE LA APLICACIÓN ---

def main():
    """Función principal que ejecuta la aplicación."""
    # Limpiar la consola para una mejor presentación
    os.system('cls' if os.name == 'nt' else 'clear')
    print("Bienvenido a tu Diario Secreto 🤫")
    
    contrasena = getpass.getpass("Por favor, introduce tu contraseña maestra: ")
    clave = generar_clave_desde_contrasena(contrasena)
    
    diario = cargar_diario(clave)
    
    if diario is None:
        print("\n❌ ¡Contraseña incorrecta o archivo dañado! El programa se cerrará.")
        return # Termina la ejecución

    # Bucle del menú principal
    while True:
        print("\n--- Menú Principal ---")
        print("1. Escribir una nueva entrada")
        print("2. Ver todas las entradas")
        print("3. Salir")
        opcion = input("Elige una opción (1, 2 o 3): ")
        
        if opcion == '1':
            anadir_entrada(diario)
            guardar_diario(diario, clave) # Guardamos después de cada nueva entrada
        elif opcion == '2':
            ver_entradas(diario)
        elif opcion == '3':
            print("¡Hasta pronto! Tu diario ha sido guardado de forma segura.")
            break
        else:
            print("Opción no válida. Por favor, elige 1, 2 o 3.")

# Esto asegura que la función main() se ejecute solo cuando corremos el script
if __name__ == "__main__":
    main()