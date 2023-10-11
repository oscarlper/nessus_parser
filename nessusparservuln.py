import xml.etree.ElementTree as ET
import pandas as pd
import sys

# Ruta al archivo .nessus
if len(sys.argv) <= 1:
    print('Falta el argumento que identifica el archivo .nessus a parsear')
    print('Sintaxis: python3 nessus_parser.py archivo.nessus')
    sys.exit()
else:
    archivo_nessus = sys.argv[1]

# Ruta para el archivo Excel de salida
archivo_excel_salida = archivo_nessus + '_vulnerabilities.xlsx'

# Crear un conjunto para rastrear las vulnerabilidades únicas
vulnerabilidades_unicas = set()

# Configurar los nombres de las columnas en el DataFrame
columnas = ['pluginName', 'severity', 'pluginFamily', 'cvss_base_score', 'description', 'solution', 'see_also']

# Crear una lista para almacenar los registros de vulnerabilidades únicos
vulnerabilidades_registros = []

# Analizar el archivo .nessus
tree = ET.parse(archivo_nessus)
root = tree.getroot()

# Iterar a través de los elementos "ReportItem"
for report_item in root.findall('.//ReportItem'):
    # Obtener la información de la vulnerabilidad
    plugin_name = report_item.get('pluginName')
    severity = report_item.find('.//risk_factor').text

    # Filtrar por severidades "Critical", "High", "Medium", "Low"
    if severity in ('Critical', 'High', 'Medium', 'Low'):
        plugin_family = report_item.get('pluginFamily')
        
        # Verificar si el elemento 'cvss_base_score' existe antes de acceder a 'text'
        cvss_base_score_element = report_item.find('.//cvss_base_score')
        cvss_base_score = cvss_base_score_element.text if cvss_base_score_element is not None else ''
        
        description_element = report_item.find('.//description')
        description = description_element.text if description_element is not None else ''
        
        solution_element = report_item.find('.//solution')
        solution = solution_element.text if solution_element is not None else ''

        # Obtener la etiqueta see_also con los links de referencia
        see_also_element = report_item.find('.//see_also')
        see_also = see_also_element.text if see_also_element is not None else ''

        # Crear una clave única para la vulnerabilidad
        clave_vulnerabilidad = (plugin_name, severity, plugin_family, cvss_base_score, description, solution, see_also)

        # Verificar si la vulnerabilidad ya se ha registrado
        if clave_vulnerabilidad not in vulnerabilidades_unicas:
            vulnerabilidades_unicas.add(clave_vulnerabilidad)
            vulnerabilidades_registros.append(clave_vulnerabilidad)

# Crear un DataFrame de Pandas a partir de los registros
df = pd.DataFrame(vulnerabilidades_registros, columns=columnas)

# Guardar los registros en un archivo Excel
df.to_excel(archivo_excel_salida, index=False)

print(f'Se han recopilado y guardado las vulnerabilidades en {archivo_excel_salida}')
