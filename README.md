
This is a plug-in for CIF that consists of a Python module. It parses 
STIX/Cybox documents into JSON CIF Feed files with corresponding configuration
files for each source document and feed it to CIF.



Installation
-------------------

To install CIF dependencies:
```
apt-get install automake libtool; 
sudo cpan Google::ProtocolBuffers; 
git clone https://github.com/collectiveintel/cif-v1.git;  
cd cif-v1
./rebuild.sh 
sudo useradd cif; 
./configure && make && sudo make install
```

To install python dependencies:
`pip install -r requirements.txt`


Usage
---------
This module requires configuration file ? stix2cif_config.cfg. You can pass the 
full path as input argument, or hard-code the path in the module.

The configuration file allows to set:
- Home directory of the Stix2Cif plug-in
- Home directory of the CIF
- Drop-off of STIX files directory
- CIF configuration file
- CIF call command
- Stix2Cif run directory (for temp files)
- CIF fields/parameters list, order and some defaults
- CIF Feed configuration file template
- Stix2Cif logger configuration


Stix2Cif is meant to be executed command line.

Usage:
  stix2cif [-c <config>]
  stix2cif [--version]
  stix2cif [-h | --help]

Options:
  --version            Show version.
                           [default: 1.0.0]
  -h --help            Show this screen.
  -c				Configuration file to use
					[default: ./stix2cif_config.cfg]

== OTHER ==

Contributor: Nataliya A. Shevchenko, SEI CERT
Date: May 15th, 2014

