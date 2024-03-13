# Intrusion Inspector

## Introduction
Intrusion Inspector is a cybersecurity tool designed to analyze and verify the security of IP addresses. It leverages the VirusTotal API to determine whether IP addresses are malicious, based on information collected from multiple security sources.

## Features
- Reads pairs of IP addresses from Excel files.
- Verifies the maliciousness of IP addresses using the VirusTotal API.
- Provides a graphical user interface for easy interaction.
- Exports results in CSV, JSON, and plain text formats.

## Installarion

To run Intrusion Inspector, you will need Python 3.6 or higher. Clone the repository or download the gui.py, main.py, and virustotal_api.py files.

### Dependencies

Install the required dependencies by running:

pip install -r requirements.txt

## Usage

### Initial Setup

Before running the tool, make sure you have a valid VirusTotal API key.

### GUI Execution

To start the graphical user interface, run:

python gui.py

Follow the instructions in the interface to load your Excel file, enter your VirusTotal API key, and view or export the results.

### Command Line Mode

Alternatively, you can use Intrusion Inspector from the command line:

python main.py --excel <path_to_excel_file> --api-key <your_virustotal_api_key> [--export-format <format>] [--export-filename <filename>]

## Contribution

Contributions to Intrusion Inspector are welcome. If you would like to contribute, please fork the repository and submit a pull request.