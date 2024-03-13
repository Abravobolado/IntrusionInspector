import requests, time

VT_URL = 'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
results_cache = {}  # Diccionario que actúa como caché de resultados

def is_ip_malicious(response_json, ip):

    RED = '\033[91m'
    GREEN = '\033[92m'
    RESET = '\033[0m'

    # Verificar primero si 'data' y 'attributes' existen en la respuesta JSON
    if 'data' in response_json and 'attributes' in response_json['data']:
        last_analysis_results = response_json['data']['attributes']['last_analysis_results']
        
        # Filtrar los motores que detectaron la IP como maliciosa
        malicious_engines = {engine: details for engine, details in last_analysis_results.items() if details['category'] == 'malicious'}
        
        # Imprimir la cantidad de detecciones maliciosas
        if malicious_engines:
            print(f"\n{RED}{ip}{RESET} -> Total de detecciones maliciosas: {len(malicious_engines)}")
            for engine, details in malicious_engines.items():
                print(f"- {engine}: {details['result']}")
            return True
    else:
        print(f"No se encontraron datos completos para la IP: \n{GREEN}{ip}{RESET} en la respuesta de VirusTotal.")
    return False




def check_ip_maliciousness(ip_pair, api_key):
    """
    Consulta la API de Virustotal para cada IP en el par y devuelve True si alguna es maliciosa.
    """
    headers = {"x-apikey": api_key}
    for ip in ip_pair:

        if ip in results_cache:
            print(f"Usando resultado de caché para {ip}")
            if results_cache[ip]:
                return ip
            continue
        try:
            response = requests.get(VT_URL.format(ip=ip), headers=headers)
            
            # Manejo específico de errores comunes de la API
            if response.status_code == 429:
                print("Se ha excedido el límite de tasa de la API de VirusTotal. Intentando de nuevo...")
                time.sleep(60)  # Esperar 60 segundos antes de reintentar
                continue
            elif response.status_code >= 500:
                print("Error del servidor de VirusTotal. Intentando de nuevo...")
                time.sleep(10)  # Esperar antes de reintentar
                continue
            if is_ip_malicious(response.json(), ip):
                results_cache[ip] = True  # Almacenar resultado en caché
                return ip
        except requests.RequestException as e:
            print(f"Error al consultar la IP {ip} en VirusTotal: {e}")
            continue  # Continuar con la siguiente IP si hay un error
    return False  # Devuelve False si ninguna de las IPs es maliciosa

# Nota: Asegúrate de manejar adecuadamente los límites de la API de VirusTotal para evitar problemas.
