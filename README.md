# scanners2pwndoc-ng
Populate PwnDoc-ng's Vulnerability Database with popular scanner tools output (e.g. Nessus, Burp...)

## Nessus
Usage: ./nessus.py <nessus_file.nessus> <pwndoc custom field ID> [-o result.yml]

This will parse a .nessus file and create a YAML file to be imported inside PwnDoc-ng

You must create a custom field tied to all vulnerabilities to hold the Plugin ID, to avoid getting duplicates on importing