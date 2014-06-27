#! /usr/bin/python2.6
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
Usage:
    stix2cif [-c <config>]
    stix2cif [--version]
    stix2cif [-h | --help]
    
Options:
    --version            Show version.
                               [default: 1.0.0]
    -h, --help           Show this screen.
      
    -c                   Configuration file to use 
					[default: ./stix2cif_config.cfg]
    
'''
'''
Created on Mar 20, 2014

@author: san
'''

import sys, logging.config, os, time
from docopt import docopt
import Stix_CIF_Config
from __version__ import version as stix2cif_version
import Stix_Listener as listener
import Stix_Parser, CIF_Feed_Builder

def main(argv=None):
    
    '''
    Step 1: Load config file 
    '''
    if not argv:
        argv = sys.argv[1:]
        
    args = docopt(__doc__, argv, version=stix2cif_version)
    try:
	if args.get('<config>') == None:
		config_file = "stix2cif_config.cfg"
	else:
		config_file = args.get('<config>')

        cf = open(config_file, 'r')
    except IOError as err:
        print 'Cannot open configuration file: ' + str(err), sys.stderr
        sys.exit(1)
    config = Stix_CIF_Config.StixCIF_ConfigParser()
    with cf:
        config.readfp(cf)
        
        try:
            driver = Driver(config)
        except Exception as ex:
            print 'Could not initialize driver: ' + str(ex),sys.stderr
            sys.exit(2)
    
    logging.config.fileConfig(config_file, disable_existing_loggers=False)
    logger = logging.getLogger(__name__)
    logger.info('Starting Driver...')
    try:
        driver.run()
    except:
        logger.exception("Error during file processing, exiting ...")
        
    logger.info('Finished Driver, exiting.') 
    

class Driver(object):
    '''
    stix2cif main process driver
    '''
    
    def __init__(self, config):
        self._log = logging.getLogger(__name__)
        self._wait_time = config.get('DEFAULT', 'wait_time')
        self.config = config
        
    def run(self):
        '''
        Step 2: Monitor folder for new files
        '''
        self._log.info('Looking for new STIX files to process ...')
        cur_listener = listener.Stix_Listener()
        if self.config.has_option("STIX", "stix_dir"):
            stix_dir = self.config.get("STIX", "stix_dir")  
        else: stix_dir = './'
            
        if not os.path.exists(stix_dir):
            self._log.error("Dropoff dir doesn't exist: {0}".format(stix_dir))
            return 1   
      
        file_list = cur_listener.get_New_Files(stix_dir)
        if file_list.__len__() > 0:
            self._log.debug('Number of new files: '.format(file_list.__len__()))
            '''                    
            Step 3: Parse XML STIX files one by one and create STIX Object 
            '''
            self._log.info('Start to process new STIX files ...')
            for fn in file_list:
                self._log.debug('File name: {0}'.format(fn))

		parser = None
		cur_stix = None
		assessment = ''
		parameters = {}

                parser = Stix_Parser.Stix_Parser(self.config)
                try:
                    cur_stix, assessment = parser.get_STIX_Package(stix_dir+fn) 
                    parameters = parser.parse_STIX_Package(cur_stix, assessment)
                except Exception as ex:
                    self._log.exception("Could not process Package from {0}. {1}"
								   .format(fn, ex))
		    cur_listener.move_Non_Processed_File(fn, stix_dir)
                    continue
                      
                '''
                Step 4-6: Build CIF feed and config file, 
                    Make a call to CIF and send the feed
                '''
                feed_builder = CIF_Feed_Builder.CIF_Feed_Builder(self.config)
                self._log.debug('Prepare feed file and feed config file.')
                try:
                    feed_builder.submit(parameters)                    
                except Exception as ex:
                    self._log.exception("Could not submit data to CIF. {0}"
								    .format(ex))
                        
                '''
                Step 7: Move processed files to archive folder
                '''
                self._log.debug("The file {0} processed. Waiting for {1} secs."
					     .format(fn, int(self._wait_time)))
                time.sleep(int(self._wait_time))
                cur_listener.move_Processed_File(fn, stix_dir)
        
        else:
	    print('No new files to process.')
            self._log.info('No new files to process.')
            return 0
        
        self._log.debug("Driver stopped")                       
        
if __name__ == '__main__':
    sys.exit(main()) 
