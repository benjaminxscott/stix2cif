## Impetus
This tool converts STIX XML documents to CIF JSON files.


## Installation

To install Python dependencies:
`pip install -r requirements.txt`


*note*: This program expects an instance of CIF server installed locally

To install CIF server on Ubuntu:
```
apt-get install automake libtool; 
sudo cpan Google::ProtocolBuffers; 
git clone https://github.com/collectiveintel/cif-v1.git;  
cd cif-v1
./rebuild.sh 
sudo useradd cif; 
./configure && make && sudo make install
```

Point your  `cif_home` variable in the config to where CIF lives (for instance ~/cif-v1).

## Usage

```
 python stix2cif [-c <config>] [--version] [-h | --help]

Options:
  --version            Show version.
                           [default: 1.0.0]
  -h --help            Show this screen.
  -c			Configuration file to use
			[default: ./stix2cif_config.cfg]
```

Script configuration will be loaded by default from `stix2cif_config.cfg` 

Variables that are safe to modify:
- `home` = where this script lives
- `stix_dir` = dir where STIX documents will be loaded
- `stix_file_patern` = (sic) filetypes that will be parsed for STIX data
- `cif_home` =  dir where CIF is installed
- `cif_feed_config_file` = location of CIF configuration file
- `run_dir` = dir for temp files

Ingested STIX documents will be moved to a `stix_dir`/processed[$timestamp]/ folder
Output CIF files will be sent to the server instance at `cif_home/bin/cif_smrt`

## Original Authors
Nataliya A. Shevchenko, SEI CERT
@san, SEI CERT
