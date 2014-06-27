################################################################################
#Copyright (c) 2014 Carnegie Mellon University.
#All Rights Reserved.

#Redistribution and use in source and binary forms, with or without modification
#, are permitted provided that the following conditions are met:
#1. Redistributions of source code must retain the above copyright notice, this 
#list of conditions and the following acknowledgments and disclaimers.
#2. Redistributions in binary form must reproduce the above copyright notice, 
#this list of conditions and the following acknowledgments and disclaimers in 
#the documentation and/or other materials provided with the distribution.
#3. Products derived from this software may not include "Carnegie Mellon 
#University," "SEI" and/or "Software Engineering Institute" in the name of such 
#derived product, nor shall "Carnegie Mellon University," "SEI" and/or "Software
# Engineering Institute" be used to endorse or promote products derived from 
#this software without prior written permission. For written permission, please 
#contact permission@sei.cmu.edu.
#ACKNOWLEDMENTS AND DISCLAIMERS:
#Copyright 2014 Carnegie Mellon University
#
#This material is based upon work funded and supported by Department of Homeland
# Security under Contract No. FA8721-05-C-0003 with Carnegie Mellon University 
#for the operation of the Software Engineering Institute, a federally funded 
#research and development center sponsored by the United States Department of 
#Defense.
#
#Any opinions, findings and conclusions or recommendations expressed in this 
#material are those of the author(s) and do not necessarily reflect the views of
# Department of Homeland Security or the United States Department of Defense.
#
#References herein to any specific commercial product, process, or service by 
#trade name, trade mark, manufacturer, or otherwise, does not necessarily 
#constitute or imply its endorsement, recommendation, or favoring by Carnegie 
#Mellon University or its Software Engineering Institute.
#
#NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE
# MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO
# WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER 
#INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR 
#MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL.
#CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT
#TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
#This material has been approved for public release and unlimited distribution.
#
#Carnegie Mellon(R) is registered in the U.S. Patent and Trademark Office by 
#Carnegie Mellon University.
#
#DM-0001329
################################################################################
'''
Created on Mar 20, 2014

@author: san
'''
import os, logging, tempfile, json, string, glob
import ordereddict
from subprocess import Popen, PIPE, STDOUT
from contextlib import contextmanager        
from datetime import datetime

logger = logging.getLogger(__name__)

class CIF_Feed_Builder(object):
    '''
    This class handles building of CIF feed source file, which contains lines of 
    JSON objects one for each observable from STIX XML source file
    '''


    def __init__(self, config):
        '''
        Constructor
        '''
        self.config = config
        if self.config.has_option("CIF", "run_dir"):
            self._run_dir = self.config.get("CIF", "run_dir")
        else:
            self._run_dir = './stix2cif_run'
        
    def submit(self, parameters):
        '''
        Submit STIX data to CIF Smrt
        '''
        if not parameters:
            raise ValueError('No data to submit given')
        
        cif_smrt = str(self.config.get('CIF', 'smrt')).encode()
        cif_config = None
        if self.config.has_option('CIF', 'config'):
            cif_config = str(self.config.get('CIF', 'config')).encode()
        else:
            raise ValueError('Feed config filename is missing from config file')
        
	if self.config.has_option('CIF', 'goback'):
            cif_goback = str(self.config.get('CIF', 'goback')).encode()
        else:
	    cif_goback = '7000'.encode()
 
        cif_icf_feed = str(self.config.get('CIF', 'icf_feed')).encode()
        cif_threads = '4'.encode()
	if self.config.has_option('CIF', 'threads'):
            cif_threads = str(self.config.get('CIF', 'threads')).encode() 
        
        with self.stage(parameters) as rule_file:
            smrt_cmd = [ cif_smrt, '-d -t', cif_threads, '-f', cif_icf_feed,
			 '-g', cif_goback, '-r', rule_file.encode() ]
            if cif_config:
                smrt_cmd += [ '-C', cif_config ]

	    #smrt_cmd += [ '-P' ]
                
            logger.debug('Executing: {0}'.format(smrt_cmd))
            proc = Popen(smrt_cmd, stdout=PIPE, stderr=STDOUT, shell=False)
            (output,err) = proc.communicate()
            print "output: ", output
	    print "err: ", err
 
        if output:
            logger.debug('CIF Smrt output: {0}'.format(output))
        if proc.returncode:
            raise RuntimeError('CIF error code [{0}]'.format(proc.returncode))
        
        logger.debug('CIF Smrt  - submit finished')
        
    @contextmanager
    def stage(self, parameters):
        
        logger.debug('Staging CIF feed')

	if not os.path.exists(self._run_dir):
	    glob.os.mkdir(self._run_dir)
                
        #create tmp directory
        tmp_dir = tempfile.mkdtemp(dir=self._run_dir)
        logger.debug('Created temp.dir for CIF staging at {0}'.format(tmp_dir))
        cif_data_fp = tempfile.NamedTemporaryFile(dir=tmp_dir, 
						  delete=False, suffix='.json')
        with open(cif_data_fp.name, 'w') as outfile:#cif_data_fp.name
	    outfile.write('[')
            logger.debug('Spooling indicators at {0}'.format(cif_data_fp.name))
            i = 0
	    for row in parameters:
		i+=1
                try:
                    data = self.build_row(row)
                except Exception as ex:
                    logger.exception('Error building json row: {0}'.format(ex))
                if data.__len__() > 0:
                    json.dump(data, outfile)
		    if i < parameters.__len__():
                    	outfile.write(',\n')
	    outfile.write(']')
        
        rule_file = os.path.join(tmp_dir, 'smrt_rule.cfg')
        logger.debug('Spooling CIF Smrt rule file to {0}'.format(rule_file))
        stix_fields = self.config.get("CIF","cif_fields")
        cif_rule_template = self.config.get("CIF","smrt_rule_template")
        with open(rule_file, 'w') as fp:
            s = string.Template(cif_rule_template).substitute(
			    icf_file=cif_data_fp.name,stix_fields=stix_fields)
            fp.write(s)
        
        yield rule_file
        
        logger.debug('Removing staged CIF Smrt tree {0}'.format(tmp_dir))
        if os.path.exists(tmp_dir):
            glob.os.system("rm -rf " + tmp_dir)  
    
    def build_row(self, dict_row):
       
        assessment = 'suspicious'
        data = ordereddict.OrderedDict()
        fields_map = ''
        if self.config.has_option("CIF","cif_fields"):
            fields_map = str(self.config.get("CIF","cif_fields"))
        else:
            raise ValueError('Fields are missing from stix2cif config file')
        
        if dict_row.__len__() > 1:
            fields = fields_map.replace("'","")
            for fl in fields.split(','):
                if dict_row.get(fl):
                    data[fl] = dict_row.get(fl)
                else:
		    if fl != 'guid' and fl != 'detecttime' and fl != 'reporttime':
                    	data[fl] = 'null'
		    if fl == 'detecttime':
			data[fl] = str(datetime.now().isoformat())
		    if fl == 'reporttime':
			data[fl] = ''
        else:
            if dict_row.get('assessment'):
                assessment = dict_row.get('assessment')
        
        if data.get('assessment') == 'null':
            data['assessment'] = assessment
                     
        return data
        
if __name__ == '__main__':
    pass
        
