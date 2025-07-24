# app_gui.py (Versión Final)

# 1. Importaciones
import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import base64
import json
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# 2. Motor de Encriptación
NOMBRE_ARCHIVO = "diario.dat"
CLAVE_ENCRIPTACION = None

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

# 3. Funciones de la Interfaz Gráfica
def guardar_entrada():
    contenido = cuadro_texto.get("1.0", "end-1c")
    if not contenido:
        messagebox.showwarning("Entrada Vacía", "No puedes guardar una entrada vacía.")
        return

    diario_actual = cargar_diario(CLAVE_ENCRIPTACION)
    fecha_hoy = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    nueva_entrada = {"fecha": fecha_hoy, "texto": contenido}
    diario_actual.append(nueva_entrada)
    guardar_diario(diario_actual, CLAVE_ENCRIPTACION)
    
    cuadro_texto.delete("1.0", "end")
    messagebox.showinfo("Guardado", "¡Tu entrada ha sido guardada de forma segura!")

def ver_entradas():
    """Crea una nueva ventana para mostrar todas las entradas del diario."""
    diario = cargar_diario(CLAVE_ENCRIPTACION)
    
    # Crea una nueva ventana (Toplevel) que aparecerá sobre la principal
    ventana_historial = tk.Toplevel(ventana)
    ventana_historial.title("Historial del Diario")
    ventana_historial.geometry("700x500")

    # Creamos un widget de texto para mostrar las entradas
    historial_texto = tk.Text(ventana_historial, font=("Calibri", 11), wrap="word", padx=10, pady=10)
    historial_texto.pack(fill="both", expand=True)

    if not diario:
        historial_texto.insert("1.0", "Aún no tienes ninguna entrada.")
    else:
        # Mostramos las entradas de la más reciente a la más antigua
        for entrada in reversed(diario):
            texto_formateado = f"📅 Fecha: {entrada['fecha']}\n"
            texto_formateado += ("-" * 30) + "\n"
            texto_formateado += f"{entrada['texto']}\n\n"
            historial_texto.insert("1.0", texto_formateado)
    
    # Hacemos que el texto no se pueda editar
    historial_texto.config(state="disabled")

def solicitar_contrasena_al_inicio():
    global CLAVE_ENCRIPTACION
    contrasena = simpledialog.askstring("Contraseña", "Introduce tu contraseña maestra:", show='*')
    if contrasena:
        CLAVE_ENCRIPTACION = generar_clave_desde_contrasena(contrasena)
        diario = cargar_diario(CLAVE_ENCRIPTACION)
        if diario is None:
            messagebox.showerror("Error", "Contraseña incorrecta.")
            ventana.destroy()
    else:
        ventana.destroy()

# 4. Construcción de la Interfaz Gráfica Principal
ventana = tk.Tk()
ventana.title("Mi Diario Secreto 🤫")
ventana.geometry("800x600")
ventana.minsize(600, 400)

# Frame para los botones
frame_botones = ttk.Frame(ventana)
frame_botones.pack(pady=10)

etiqueta_titulo = ttk.Label(ventana, text="¿Qué pasó hoy?", font=("Helvetica", 18, "bold"))
etiqueta_titulo.pack(pady=10)

cuadro_texto = tk.Text(ventana, font=("Calibri", 12), wrap="word", padx=15, pady=15, bd=0)
cuadro_texto.pack(padx=10, pady=5, fill="both", expand=True)

# Añadimos los dos botones al frame
boton_guardar = ttk.Button(frame_botones, text="Guardar Entrada", command=guardar_entrada)
boton_guardar.pack(side="left", padx=10)

boton_ver_historial = ttk.Button(frame_botones, text="Ver Entradas Anteriores", command=ver_entradas)
boton_ver_historial.pack(side="left", padx=10)

# 5. Iniciar la Aplicación
ventana.withdraw() 
solicitar_contrasena_al_inicio()
if CLAVE_ENCRIPTACION:
    ventana.deiconify()
    ventana.mainloop()