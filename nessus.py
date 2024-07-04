#!/usr/bin/env python

import argparse
import xmltodict
import yaml
import os

def valid_file(arg):
    if not os.path.exists(arg):
        raise argparse.ArgumentTypeError(f"The file {arg} does not exist.")
    return arg

def extract_vulnerabilities(nessus_data, custom_field_id):
    vulnerabilities = []
    processed_plugin_ids = set()  # Track processed plugin IDs

    for host in nessus_data['NessusClientData_v2']['Report']['ReportHost']:
        host_ip = host['HostProperties']['tag'][0]['#text']
        for item in host.get('ReportItem', []):
            if int(item['@severity']) > 1:
                plugin_id = item['@pluginID']
                if plugin_id not in processed_plugin_ids:  # Check if the plugin ID is already processed
                    processed_plugin_ids.add(plugin_id)  # Add the plugin ID to the set

                    cvss = ''
                    if 'cvss3_vector' in item.keys():
                        cvss = item['cvss3_vector']

                    references = []
                    if 'see_also' in item.keys():
                        references = item['see_also'].split('\n')

                    remediation = ''
                    if 'solution' in item.keys():
                        remediation = item['solution']

                    vuln_data = {
                        'cvssv3': '' + cvss,
                        'details': [
                            {
                                'references': references,
                                'title': item['@pluginName'],
                                'customFields': [
                                    {
                                        'customField': custom_field_id,
                                        'text': plugin_id
                                    }
                                ],
                                'locale': 'EN',
                                'description': item['description'],
                                'remediation': remediation
                            }
                        ]
                    }
                    vulnerabilities.append(vuln_data)

    return vulnerabilities

def convert_nessus_to_yaml(nessus_file_path, custom_field_id, yaml_output_path):
    with open(nessus_file_path, 'r') as file:
        nessus_data = xmltodict.parse(file.read())

    vulnerabilities = extract_vulnerabilities(nessus_data, custom_field_id)

    with open(yaml_output_path, 'w') as yaml_file:
        yaml.dump(vulnerabilities, yaml_file, default_flow_style=False)

    print(f"YAML file created at: {yaml_output_path}")

def main():
    parser = argparse.ArgumentParser(description='Extract vulnerabilities from Nessus file and output as YAML.')
    parser.add_argument('input_nessus', type=valid_file, help='Input Nessus file path')
    parser.add_argument('id_custom_field', type=str, help='The custom field ID to store the Plugin ID')
    parser.add_argument('-o', '--output', help='Optional: Output YAML file path')

    args = parser.parse_args()

    input_path = args.input_nessus
    field_id = args.id_custom_field
    output_path = args.output

    if not output_path:
        output_path = os.path.splitext(input_path)[0] + '_vulnerabilities.yml'

    convert_nessus_to_yaml(input_path, field_id, output_path)

if __name__ == "__main__":
    main()