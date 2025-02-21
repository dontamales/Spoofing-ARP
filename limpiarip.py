import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
import re

def extraer_ips(texto):
    """
    Utiliza una expresión regular para extraer todas las direcciones IPv4 del texto.
    """
    patron = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return re.findall(patron, texto)

def procesar_texto():
    """
    Toma el contenido del área de texto de entrada, extrae las IPs y las muestra en el área de salida.
    """
    # Obtener el texto ingresado
    texto = input_text.get("1.0", tk.END)
    ips = extraer_ips(texto)
    # Limpiar el área de salida
    output_text.delete("1.0", tk.END)
    # Mostrar las IPs extraídas o un mensaje si no se encontraron
    if ips:
        output_text.insert(tk.END, "\n".join(ips))
    else:
        output_text.insert(tk.END, "No se encontraron direcciones IP.")

# Crear la ventana principal
root = tk.Tk()
root.title("Extractor de Direcciones IP")

# Configurar el layout de la ventana
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

# Crear un frame para los widgets con padding
frame = ttk.Frame(root, padding="10")
frame.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))

# Etiqueta para el texto de entrada
input_label = ttk.Label(frame, text="Ingresa o pega los datos:")
input_label.grid(row=0, column=0, sticky=tk.W)

# Área de texto de entrada (con scroll)
input_text = scrolledtext.ScrolledText(frame, width=80, height=15)
input_text.grid(row=1, column=0, pady=5)

# Botón para procesar el texto
process_button = ttk.Button(frame, text="Extraer IPs", command=procesar_texto)
process_button.grid(row=2, column=0, pady=5)

# Etiqueta para el área de salida
output_label = ttk.Label(frame, text="Direcciones IP extraídas:")
output_label.grid(row=3, column=0, sticky=tk.W)

# Área de texto de salida (con scroll)
output_text = scrolledtext.ScrolledText(frame, width=80, height=15)
output_text.grid(row=4, column=0, pady=5)

# Iniciar la aplicación
root.mainloop()
