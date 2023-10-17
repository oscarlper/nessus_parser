import xml.etree.ElementTree as ET
from openpyxl import Workbook
import sys
import os

# Comprobar que se ha proporcionado un archivo .nessus como argumento
if len(sys.argv) != 2:
    print("Por favor, proporcione un archivo .nessus como argumento.")
    print("Sintaxis: python3 script.py archivo.nessus")
    sys.exit()

archivo_nessus = sys.argv[1]

# Verificar si el archivo .nessus existe
if not os.path.isfile(archivo_nessus):
    print(f"El archivo '{archivo_nessus}' no existe. Verifique la ruta y el nombre del archivo.")
    sys.exit()

# Crear una lista para almacenar las entradas de la tabla
tabla_os = []

# Analizar el archivo .nessus
tree = ET.parse(archivo_nessus)
root = tree.getroot()

# Iterar a través de los elementos "ReportHost"
for report_host in root.findall('.//ReportHost'):
    host_properties = report_host.find('.//HostProperties')
    host_ip = host_properties.find(".//tag[@name='host-ip']").text

    # Obtener el nombre del sistema operativo reconocido por fingerprint
    host_os_element = host_properties.find(".//tag[@name='operating-system']")
    host_os = host_os_element.text if host_os_element is not None else ""

    # Obtener el nombre del host
    host_name_element = host_properties.find(".//tag[@name='host-fqdn']")
    host_name = host_name_element.text if host_name_element is not None else ""

    # Si el campo "Hostname" está vacío, repetir el valor de IP
    if not host_name:
        host_name = host_ip

    # Agregar la entrada a la tabla
    tabla_os.append([host_ip, host_name, host_os])

# Crear un libro de trabajo de Excel y una hoja de cálculo
libro = Workbook()
hoja = libro.active

# Configurar los nombres de las columnas
hoja.append(['IP', 'Hostname', 'OS'])

# Escribir los datos en la hoja de cálculo
for entrada in tabla_os:
    hoja.append(entrada)

# Guardar el archivo Excel con el nombre de salida
nombre_salida = f"recon_os_{os.path.basename(archivo_nessus)}.xlsx"
libro.save(nombre_salida)
print(f"El archivo '{nombre_salida}' se ha generado con éxito.")
