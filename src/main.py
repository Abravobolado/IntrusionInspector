import pandas as pd
import sys
import argparse
import ipaddress
from virustotal_api import check_ip_maliciousness
import json
import csv

def export_to_json(data, filename):
    with open(filename, 'w') as jsonfile:
        json.dump(data, jsonfile)

def export_to_csv(data, filename):
    with open(filename, mode='w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Report'])
        for report in data:
            writer.writerow([report])

def export_to_txt(data, filename):
    with open(filename, 'w') as txtfile:
        for report in data:
            txtfile.write(report + '\n')

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def read_excel_and_extract_ips(excel_path):
    try:
        df = pd.read_excel(excel_path)
        assert 'source ip' in df.columns and 'destination ip' in df.columns, "Las columnas 'source ip' y 'destination ip' son obligatorias."
        ip_pairs = [(src, dst) for src, dst in zip(df['source ip'], df['destination ip']) if is_valid_ip(src) and is_valid_ip(dst)]
        return ip_pairs
    except Exception as e:
        print(f"Error al leer el archivo Excel: {e}")
        sys.exit(1)

def main(excel_path, api_key, export_format=None, export_filename=None, gui_mode=False, return_results=False):
    ip_pairs = read_excel_and_extract_ips(excel_path)
    malicious_ips_reports = []

    for source_ip, destination_ip in ip_pairs:
        ip_maliciosa = check_ip_maliciousness((source_ip, destination_ip), api_key)
        if ip_maliciosa:
            report = f"Conexión de {source_ip} a {destination_ip}: IP maliciosa: {ip_maliciosa}"
            malicious_ips_reports.append(report)

    if return_results:
        return malicious_ips_reports
    elif gui_mode:
        # Asumiendo que gui_mode podría tener un manejo específico en el futuro
        return malicious_ips_reports
    else:
        if malicious_ips_reports:
            print("\n\nReporte de IPs maliciosas detectadas:")
            for report in malicious_ips_reports:
                print(f"    {report}")

            if export_format and export_filename:
                if export_format == 'json':
                    export_to_json(malicious_ips_reports, export_filename)
                elif export_format == 'csv':
                    export_to_csv(malicious_ips_reports, export_filename)
                elif export_format == 'txt':
                    export_to_txt(malicious_ips_reports, export_filename)
                print(f"\nResultados exportados a {export_filename} en formato {export_format}.")
        else:
            print("\n\nNo se ha encontrado ninguna IP maliciosa")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Intrusion Inspector Tool")
    parser.add_argument('--excel', required=True, help="Path to the Excel file with IP pairs")
    parser.add_argument('--api-key', required=True, help="VirusTotal API key")
    parser.add_argument('--export-format', choices=['csv', 'json', 'txt'], help="Format to export the results (csv, json, txt)")
    parser.add_argument('--export-filename', help="Filename to save the exported results")

    args = parser.parse_args()

    main(args.excel, args.api_key, args.export_format, args.export_filename)