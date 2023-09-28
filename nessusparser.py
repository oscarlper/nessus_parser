import xml.etree.ElementTree as ET
from openpyxl import Workbook
import sys


# Ruta al archivo .nessus
if len(sys.argv) <= 1:
	print('Falta el argumento que identifica el archivo .nessus a parsear')
	print('Sintaxis: python3 nessus_parser.py archivo.nessus')
	sys.exit()
else:
	archivo_nessus = sys.argv[1]

# Ruta para el archivo Excel de salida
archivo_excel_salida = archivo_nessus+'.xlsx'

# Crear un libro de trabajo de Excel y una hoja de cálculo
libro = Workbook()
hoja = libro.active

# Configurar los nombres de las columnas
hoja.append(['Vulnerabilidad', 'Severidad', 'CVSS 2.0', 'Port/Service', 'IPs Afectadas'])

# Analizar el archivo .nessus
tree = ET.parse(archivo_nessus)
root = tree.getroot()

# Crear un diccionario para rastrear las vulnerabilidades por nombre y puerto
vulnerabilidades_por_nombre_y_puerto = {}

# Iterar a través de los elementos "ReportHost"
for report_host in root.findall('.//ReportHost'):
    # Obtener la dirección IP del host actual
    host_properties = report_host.find('.//HostProperties')
    host_ip = host_properties.find(".//tag[@name='host-ip']").text

    # Iterar a través de los elementos "ReportItem" para el host actual
    for report_item in report_host.findall('.//ReportItem'):
        severity_element = report_item.find(".//cvss_base_score")
        if severity_element is not None:
            severity = severity_element.text
            if severity not in ('', '0') and severity != 'Info':
                # Obtener el nombre de la vulnerabilidad
                vulnerabilidad = report_item.get('pluginName')
                
                # Obtener la severidad de la vulnerabilidad (si está presente)
                severity_level_element = report_item.find('.//risk_factor')
                severity_level = severity_level_element.text if severity_level_element is not None else ''
                
                # Obtener el nivel de vulnerabilidad según CVSS 2.0 (si está presente)
                cvss_2_element = report_item.find('.//cvss_base_score')
                cvss_2 = cvss_2_element.text if cvss_2_element is not None else ''
                
                # Obtener el puerto/servicio en el formato deseado
                port_element = report_item.get('port')
                protocol_element = report_item.get('protocol')
                svc_name_element = report_item.get('svc_name')
                
                if port_element is not None and protocol_element is not None and svc_name_element is not None:
                    port_service = f"{port_element} / {protocol_element} / {svc_name_element}"
                else:
                    port_service = ''

                # Crear una clave única para identificar la vulnerabilidad por nombre y puerto
                clave_vulnerabilidad = f"{vulnerabilidad} - {port_service}"

                # Agregar la dirección IP al registro consolidado
                if clave_vulnerabilidad not in vulnerabilidades_por_nombre_y_puerto:
                    vulnerabilidades_por_nombre_y_puerto[clave_vulnerabilidad] = {
                        'Vulnerabilidad': vulnerabilidad,
                        'Severidad': severity_level,
                        'CVSS 2.0': cvss_2,
                        'Port/Service': port_service,
                        'IPs Afectadas': [host_ip]
                    }
                else:
                    vulnerabilidades_por_nombre_y_puerto[clave_vulnerabilidad]['IPs Afectadas'].append(host_ip)

# Escribir los registros consolidados en la hoja de cálculo
for registro in vulnerabilidades_por_nombre_y_puerto.values():
    registro['IPs Afectadas'] = ', '.join(registro['IPs Afectadas'])
    hoja.append(list(registro.values()))

# Guardar el archivo Excel
libro.save(archivo_excel_salida)

print(f"Se ha creado el archivo Excel con las vulnerabilidades, incluyendo la severidad, de severidad 'Critica', 'Alta', 'Media' y 'Baja' (excluyendo 'Info').")
