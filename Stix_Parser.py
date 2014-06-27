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
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class Stix_Parser(object):
    '''
    classdocs
    '''
    def __init__(self, config):
        '''
        Constructor
        '''
        self.config = config
      
    def get_STIX_Package(self, file_name):
        from stix.core import STIXPackage
         
        stix_package = STIXPackage.from_xml(file_name)
        stix_dict = stix_package.to_dict() # parse to dictionary
        logger.debug('STIX Dict: {0}'.format(stix_dict))
        assessment = 'suspicious'
        logger.debug('STIX Header: {0}'
			.format(stix_package.stix_header.to_dict().keys()))
        if stix_dict.get('stix_header'):
            for i in stix_package.stix_header.to_dict().keys():
                logger.debug('{0}: {1}'
			.format(i,stix_package.stix_header.to_dict().get(i)))
        
            logger.debug('STIX Header:package_intents: {0}'
			.format(stix_package.stix_header.package_intents[0]))
            assessment = self.parse_PackageIntent(
				stix_package.stix_header.package_intents[0])
        else:
            logger.debug('No STIX Package Header')
        
        return stix_package, assessment
    
    def parse_STIX_Package(self, package, assessment):
        
        stix_parameters = []
        stix_parameters.append({'assessment':assessment})
        
        if package.indicators.__len__() > 0:
            self.parse_indicator(package, stix_parameters)
            
        elif package.observables <> None:
            indicator = {}
            self.parse_abservables(package.observables.observables,
						 indicator, stix_parameters)
            
        return stix_parameters
    
    def parse_indicator(self, package, stix_parameters):
        '''
        it parse list of indicators from STIX package 
        '''
        import stix.common.confidence
        
        for ind in package.indicators: 
                indicator = {}          
                #Producer
                if ind.producer <> None:
                    indicator['source'] = ind.producer.identity.name
                    if ind.producer.time.produced_time <> None:
                        indicator['detecttime'] = datetime.isoformat(
					ind.producer.time.produced_time.value)
                    if ind.producer.time.received_time <> None:
                        indicator['reporttime'] = datetime.isoformat(
					ind.producer.time.received_time.value)
                #Confidence
                if ind.confidence <> None:
                    if isinstance(ind.confidence, str):
                        indicator['confidence'] = self.config().get(
					"Confidence_DEFAULT", ind.confidence)
                    elif isinstance(ind.confidence,
					 stix.common.confidence.Confidence):
                        indicator['confidence'] = ind.confidence.value.value
                #Description
                if ind.description <> None:
                    indicator = self.parse_description(ind.description.value,
								indicator)
                #Observables
                if ind.observables.__len__() > 0: 
                    indicator = self.parse_abservables(ind.observables,
						 indicator, stix_parameters)
                        
                        
                self.check_for_multivalues(indicator, stix_parameters)
            #for ind end 
             
    def parse_abservables(self, observables, indicator, stix_parameters):
        '''
        It parses list of Observables  from package or from inicator
        '''
        for obs in observables:
            #Observable_composition
            if obs.observable_composition <> None:
                #Observable
                for i in obs.observable_composition.observables:
                    indicator = self.parse_abservable(i.object_.properties,
								 indicator)
                                    
                    if i.object_.related_objects <> None:
                        for j in i.object_.related_objects:
                            fields = {}
                            
                            fields = self.parse_abservable(
				j.related_object.get_properties(), fields)
                            stix_parameters.append(fields)
                            
            elif obs.object_ <> None:
                logger.debug("only one observable.")
                indicator = self.parse_abservable(obs.object_.properties,
								 indicator)
                            
                if obs.object_.related_objects <> None:
                    for i in obs.object_.related_objects:
                        fields = {}
                        
                        fields = self.parse_abservable(i.get_properties(),
									fields)
                        stix_parameters.append(fields)
                            
            elif obs.event <> None:
                pass
            else:
                pass
            
            return indicator
            
    def parse_abservable(self, obs, fields_dict):
        import cybox.objects.network_connection_object
        import cybox.objects.address_object
        import cybox.objects.file_object
        import cybox.objects.domain_name_object
        import cybox.objects.email_message_object
        import cybox.objects.port_object
        import cybox.objects.uri_object
        import cybox.objects.socket_address_object
        import cybox.objects.artifact_object
        import cybox.objects.dns_record_object
               
        logger.debug('Observable type: {0}'.format(type(obs)))
        
        if isinstance(obs, 
		cybox.objects.network_connection_object.NetworkConnection):
            logger.debug("NetworkConnection")
            fields_dict = self.parse_NetworkConnection(obs, fields_dict)
                                
        if isinstance(obs, cybox.objects.address_object.Address):
            logger.debug("Address")
            fields_dict = self.parse_Address(obs, fields_dict)
                                
        if isinstance(obs, cybox.objects.address_object.EmailAddress):
            logger.debug("EmailAddress")
            fields_dict = self.parse_EmailAddress(obs, fields_dict)
                                
        if isinstance(obs, cybox.objects.file_object.File):
            logger.debug("File")
            fields_dict = self.parse_File(obs, fields_dict)
                                
        if isinstance(obs, cybox.objects.domain_name_object.DomainName):
            logger.debug("DomainName")
            fields_dict = self.parse_DomainName(obs, fields_dict)
                                
        if isinstance(obs, cybox.objects.email_message_object.EmailMessage):
            logger.debug("EmailMessage")
            fields_dict = self.parse_EmailMessage(obs, fields_dict)
                                
        if isinstance(obs, cybox.objects.port_object.Port):
            logger.debug("Port")
            fields_dict = self.parse_Port(obs, fields_dict)
                                
        if isinstance(obs, cybox.objects.uri_object.URI):
            logger.debug("URI")
            fields_dict = self.parse_URI(obs, fields_dict)
                                
        if isinstance(obs, cybox.objects.socket_address_object.SocketAddress):
            logger.debug("SocketAddress")
            fields_dict = self.parse_SocketAddress(obs, fields_dict)
        
        if isinstance(obs, cybox.objects.artifact_object.Artifact):
            logger.debug("Artifact: {0}".format(obs.to_dict().keys()))
            fields_dict = self.parse_ArtifactObject(obs, fields_dict)
            
        if isinstance(obs, cybox.objects.dns_record_object.DNSRecord):
            logger.debug("DNSRecord: {0}".format(obs.to_dict().keys()))
            fields_dict = self.parse_DNSRecord(obs, fields_dict)
        
        
        return fields_dict
    
    def parse_description(self, value, fields_dict):
        '''
        One of the cases of STIX documents is one that was in some point of 
        time generated directly from CIF. They can have a lot of additional
        info in indicator description.
        '''
        desc_split = str.split(value, '; ')
        if desc_split.__len__() > 1:
            for i, v in enumerate(desc_split):
                if i == 0:
                    #extract assesment
                    tmp = str.split(v, '. ')
                    tmp1 = str.split(tmp[0], ': ')
                    if tmp1[0] == 'Assessment':
                        fields_dict['assessment'] = tmp1[1]
                    #Extract purpose
                    tmp1 = str.split(tmp[1], ': ')
                    tmp2 = str.split(tmp1[1], ' = ')
                    if tmp2[0] == 'purpose':
                        fields_dict['purpose'] = tmp2[1]
                else:
                    l = str.strip(v)
                    if l:
                        tmp = str.split(l, ' = ')
                        if tmp.__len__() > 1:
                            field = tmp[0]
                            if tmp[0] == 'Internet Registry':
                                field = 'rir'
                            if tmp[0] == 'Country Code':
                                field = 'cc'
                            if tmp[0] == 'Prefix':
                                field = 'prefix'
                            fields_dict[field] = tmp[1]
                            
        elif desc_split.__len__() == 1:
            if fields_dict.get('description'):
                fields_dict['description']  = value + '; ' + fields_dict.get(
								'description')
            else:
                fields_dict['description']  = value 
                
        return fields_dict
    
    def parse_NetworkConnection(self, value, fields_dict):
        #protocol
        if value.layer7_protocol <> None:
            if fields_dict.get('description'):
                fields_dict['description'] = fields_dict.get(
		'description') + '; ' + value.layer7_protocol.value
            else:
                fields_dict['description'] = value.layer7_protocol.value
            
        if value.source_socket_address <> None:
            if value.source_socket_address.ip_address <> None:
                fields_dict[
		'address'] = value.source_socket_address.ip_address.address_value.value
                        
            if value.source_socket_address.port <> None:
                fields_dict[
		'portlist'] = value.source_socket_address.port.port_value.value
                        
        if value.layer4_protocol <> None:
            fields_dict['protocol'] = value.layer4_protocol.value
                
        return fields_dict
    
    def parse_Address(self, value, fields_dict):
        
        if value.category <> None:
            if value.category == 'asn':
                fields_dict['asn'] = value.address_value.value
            
            if value.category == 'ipv4-addr':
                fields_dict['address'] = value.address_value.value
            
            if value.category == 'e-mail':
                fields_dict['address'] = value.address_value.value
        
        return fields_dict
    
    def parse_EmailMessage(self, value, fields_dict):
        if value.to_dict().get('from_'):
            if value.from_.category == 'e-mail':
                fields_dict['address'] = value.from_.address_value.value
                if fields_dict.get('description'):
                    fields_dict['description'] = fields_dict.get(
						'description') + ' e-mail'
                else:
                    fields_dict['description'] = 'e-mail'
        elif  value.to_dict().get('to'):
            if value.to.category == 'e-mail':
                fields_dict['address'] = value.to.address_value.value
                if fields_dict.get('description'):
                    fields_dict['description'] = fields_dict.get(
						'description') + ' e-mail'
                else:
                    fields_dict['description'] = 'e-mail'
        elif value.header <> None:
            if value.header.to_dict().get('from'): 
                if value.header.to_dict().get('from').get(
						'category') == 'e-mail':
                    fields_dict['address'] = value.header.to_dict().get(
				'from').get('address_value').get('value')
                    if fields_dict.get('description'):
                        fields_dict['description'] = fields_dict.get(
						'description') + ' e-mail'
                    else:
                        fields_dict['description'] = 'e-mail'
            
                
        return fields_dict
    
    def parse_Port(self, value, fields_dict):
        return fields_dict 
    
    def parse_URI(self, value, fields_dict):
        if fields_dict.get('address'):
            fields_dict['rdata'] = value.value.value
        else:
            fields_dict['address'] = value.value.value
                    
        return fields_dict
    
    def parse_SocketAddress(self, value, fields_dict):
        return fields_dict
    
    def parse_File(self, value, fields_dict):
        if value.hashes <> None:
            fields_dict['assessment'] = 'malware'
            for h in value.hashes:
                fields_dict[
		'malware_'+str(h.type_).lower()] = str(h.simple_hash_value)
                if fields_dict.get('source'):
                    fields_dict['description'] = fields_dict.get(
					'source') + ' ' + str(h.type_).lower()
                else:
                    fields_dict['description'] = str(h.type_).lower()
        
        return fields_dict
    
    def parse_ArtifactObject(self, value, fields_dict):
        return fields_dict
    
    def parse_DomainName(self, value, fields_dict):
        return fields_dict
    
    def parse_EmailAddress(self, value, fields_dict):
        return fields_dict
    
    def parse_DNSRecord(self, value, fields_dict):
        if value.to_dict().get('ip_address'):
            fields_dict[
		'address'] = value.to_dict()['ip_address']['address_value']
        
        if value.to_dict().get('domain_name'):
            if fields_dict.get('address'):
                fields_dict['rdata'] = value.to_dict()['domain_name']['value']
            else:
                fields_dict['address'] = value.to_dict()['domain_name']['value']
        
        if value.to_dict().get('description'):
            fields_dict['description'] = str(fields_dict.get(
				'description')) + value.to_dict()['description']
            
        return fields_dict

    def check_for_multivalues(self, fields_dict, stix_parameters):
        import copy
        
        flag = 0
        tmp_dict = {}
        for i in fields_dict:
            tmp = str(fields_dict[i]).split(',')
            if tmp.__len__() > 1:
                flag = 1
                for j in tmp:
                    j = str.strip(j)
                    if j <> '':
                        tmp_dict = copy.deepcopy(fields_dict)
                        tmp_dict[i] = j
                        fields_dict = tmp_dict
                        stix_parameters.append(fields_dict)
            
        if flag == 0:
            stix_parameters.append(fields_dict)
            
        return stix_parameters
    
    def parse_PackageIntent(self, value):
        assessment = 'suspicious'
        tmp_line = str.split(value.value, ' - ')
        if tmp_line.__len__() > 1:
            if tmp_line[1] == 'Phishing':
                assessment = 'phishing'
            if tmp_line[1] == 'Malware Artifacts':
                assessment = 'malware'
        else:
            if tmp_line[0] in ('Malware Characterization', 'Malware Samples'):
                assessment = 'malware'
            if tmp_line[0] == 'Incident':
                assessment = 'incident report'
                
        return assessment

                    
if __name__ == '__main__':
    pass
        
