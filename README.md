# scanners2pwndoc-ng
Populate PwnDoc-ng's Vulnerability Database with popular scanner tools output (e.g. Nessus, Burp...)

## Nessus
Usage: ./nessus.py <nessus_file.nessus> [-o result.yml]

This will parse a .nessus file and create a YAML file to be imported inside PwnDoc-ng