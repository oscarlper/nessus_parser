import xml.etree.ElementTree as ET
from openpyxl import Workbook
import sys

# Verificar si se proporciona el archivo .nessus como argumento
if len(sys.argv) <= 1:
    print('Falta el argumento que identifica el archivo .nessus a parsear')
    print('Sintaxis: python3 reconPorts.py archivo.nessus')
    sys.exit()
else:
    archivo_nessus = sys.argv[1]

# Crear un libro de trabajo de Excel y una hoja de cálculo
libro = Workbook()
hoja = libro.active

# Configurar los nombres de las columnas
hoja.append(['IP', 'Protocol', 'Port'])

# Conjunto para rastrear registros duplicados
registros_procesados = set()

# Analizar el archivo .nessus
tree = ET.parse(archivo_nessus)
root = tree.getroot()

# Iterar a través de los elementos "ReportHost"
for report_host in root.findall('.//ReportHost'):
    # Obtener la dirección IP del host actual
    host_ip = report_host.get('name')

    # Iterar a través de los elementos "ReportItem" para el host actual
    for report_item in report_host.findall('.//ReportItem'):
        # Obtener el protocolo y puerto
        protocol = report_item.get('protocol')
        port = int(report_item.get('port'))  # Convertir a entero

        # Omitir registros con el puerto igual a 0
        if port != 0:
            # Comprobar si el registro ya se ha procesado (duplicado)
            registro_actual = (host_ip, protocol, port)
            if registro_actual not in registros_procesados:
                # Agregar la información a la hoja de cálculo
                hoja.append([host_ip, protocol, port])
                registros_procesados.add(registro_actual)

# Guardar el archivo Excel
libro.save(f'recon_ports_{archivo_nessus}.xlsx')

print(f"Se ha creado el archivo Excel con los puertos a partir de {archivo_nessus}")
