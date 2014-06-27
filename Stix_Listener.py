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
import glob
import logging, os
from datetime import datetime

logger = logging.getLogger(__name__)

class Stix_Listener(object):
    '''
    classdocs
    '''   

    def __init__(self):
        '''
        Constructor
        '''
    
    def get_New_Files(self, dir_name):
        file_list = glob.glob1(dir_name,'*.xml')
        if file_list.__len__() > 0:
            for fn in file_list:
                logger.debug('STIX file name: {0}'.format(fn))
        else:
            logger.debug('No new STIX files')
            
        return file_list
        
    #util       
    def move_Processed_Files(self, dir_name):
        dist = dir_name+'/processed_'+ str(datetime.date(datetime.now()))
        
        if glob.glob1(dir_name,'*.xml').__len__() > 0:
            if not os.path.exists(dist):
                glob.os.mkdir(dist)
            glob.os.system("mv" + " " + dir_name + "/*.xml " + dist)
            
        logger.debug("STIX source files were moved to processed directory.")
        
    #util       
    def move_Processed_File(self, file_Name, dir_name):
        dist = dir_name+'/processed_'+ str(datetime.date(datetime.now()))
        if os.path.exists(os.path.join(dir_name, file_Name)):
            if not os.path.exists(dist):
                glob.os.mkdir(dist)
            
            glob.os.system("mv "+os.path.join(dir_name, file_Name)+" "+dist)
            logger.debug("STIX source files were moved to processed directory.")
        else:
            logger.error("Cannot move file (does not exist) {0}."
				     .format(os.path.join(dir_name, file_Name)))
            
    #util      
    def move_Non_Processed_File(self, file_Name, dir_name): 
        dist = dir_name+'/nonprocessed_'+ str(datetime.date(datetime.now()))
        if os.path.exists(os.path.join(dir_name, file_Name)):
            if not os.path.exists(dist):
                glob.os.mkdir(dist)
        
            glob.os.system("mv " + os.path.join(dir_name, file_Name)+" "+dist)
            logger.debug("Unprocessed STIX files're moved to quarantine dir.")
        else:
            logger.error("Cannot move non_processed file to  {0}."
				.format(os.path.join(dir_name, file_Name)))
       
    #util      
    def move_Back(self, dir_name): 
        source = dir_name+'/processed_'+ str(datetime.date(datetime.now()))
        
        if glob.glob1(source,'*.xml').__len__() > 0:
            glob.os.system("mv" + " " + source + "/*.xml " + dir_name)
            glob.os.system("rm -r " + source)
        logger.debug("For testing: STIX source files were moved back.")
        
if __name__ == '__main__':
    pass
