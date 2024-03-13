import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import sys  # Asegúrate de importar sys
from main import main

def select_file():
    file_path = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, file_path)

def run_inspector():
    api_key = api_key_entry.get()
    file_path = file_entry.get()
    if not api_key or not file_path:
        messagebox.showwarning("Advertencia", "Por favor, proporciona tanto la clave de la API como el archivo Excel.")
        return
    results_text.delete(1.0, tk.END)
    # Asumiendo que main ahora devuelve los resultados en lugar de imprimirlos
    results = main(file_path, api_key, return_results=True)
    for result in results:
        results_text.insert(tk.END, result + '\n')

def on_close():
    sys.exit()

# Configura la ventana de Tkinter
root = tk.Tk()
root.title("Intrusion Inspector")

# Configura el manejo del cierre de la ventana
root.protocol("WM_DELETE_WINDOW", on_close)

# Configura el campo de entrada para la clave de la API
tk.Label(root, text="Clave de API de VirusTotal:").pack()
api_key_entry = tk.Entry(root)
api_key_entry.pack()

# Configura el campo de entrada y botón para seleccionar archivo
tk.Label(root, text="Archivo Excel con direcciones IP:").pack()
file_entry = tk.Entry(root)
file_entry.pack()
tk.Button(root, text="Seleccionar Archivo", command=select_file).pack()

# Botón para iniciar la inspección
tk.Button(root, text="Iniciar Inspección", command=run_inspector).pack()

# Área de texto para mostrar los resultados
results_text = scrolledtext.ScrolledText(root, width=70, height=20)
results_text.pack()

root.mainloop()
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from main import main  # Asegúrate de que main puede ser importado así, quizás necesites ajustar tu estructura de archivos o métodos

def select_file():
    file_path = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, file_path)

def run_inspector():
    api_key = api_key_entry.get()
    file_path = file_entry.get()
    if not api_key or not file_path:
        messagebox.showwarning("Advertencia", "Por favor, proporciona tanto la clave de la API como el archivo Excel.")
        return
    results_text.delete(1.0, tk.END)
    results = main(file_path, api_key, return_results=True)  # Modifica main para que pueda devolver resultados si es necesario
    for result in results:
        results_text.insert(tk.END, result + '\n')

# Configura la ventana de Tkinter
root = tk.Tk()
root.title("Intrusion Inspector")

# Configura el campo de entrada para la clave de la API
tk.Label(root, text="Clave de API de VirusTotal:").pack()
api_key_entry = tk.Entry(root)
api_key_entry.pack()

# Configura el campo de entrada y botón para seleccionar archivo
tk.Label(root, text="Archivo Excel con direcciones IP:").pack()
file_entry = tk.Entry(root)
file_entry.pack()
tk.Button(root, text="Seleccionar Archivo", command=select_file).pack()

# Botón para iniciar la inspección
tk.Button(root, text="Iniciar Inspección", command=run_inspector).pack()

# Área de texto para mostrar los resultados
results_text = scrolledtext.ScrolledText(root, width=70, height=20)
results_text.pack()

root.mainloop()
