### import paramiko
from netaddr import *
import pprint
import connect2
import re
### import argparse
### import getpass
import datetime
from xml.dom import minidom
import os,sys


global FWList,FWList2 , PredefinedSerList , PredefinedSerListSRX
PredefinedSerList = ['ssh', 'telnet','ftp' ,'snmp', 'ping','traceroute', 'http' ,'https', 'dns', 'RDP' , 'ntp','any' , 'syslog' , 'smtp' , 'sftp' , 'rdp']
PredefinedSerListSRX = {'21': ['tcp','junos-ftp'], '69': ['udp','junos-tftp'], '554': ['tcp','junos-rtsp'], '139': ['tcp','junos-netbios-session'], '445': ['tcp','junos-smb-session'], '22': ['tcp','junos-ssh'], '23': ['tcp','junos-telnet'], '25': ['tcp','junos-smtp'], '49': ['tcp','junos-tacacs'], '65': ['tcp','junos-tacacs-ds'], '68': ['udp','junos-dhcp-client'], '67': ['udp','junos-dhcp-server'], '79': ['tcp','junos-finger'], '80': ['tcp','junos-http'], '443': ['tcp','junos-https'], '110': ['tcp','junos-pop3'], '113': ['tcp','junos-ident'], '119': ['tcp','junos-nntp'], '123': ['udp','junos-ntp'], '143': ['tcp','junos-imap'], '993': ['tcp','junos-imaps'], '179': ['tcp','junos-bgp'], '389': ['tcp','junos-ldap'], '444': ['tcp','junos-snpp'], '512': ['udp','junos-biff'], '513': ['udp','junos-who'], '514': ['udp','junos-syslog'], '515': ['tcp','junos-printer'], '520': ['udp','junos-rip'], '1812': ['udp','junos-radius'], '1813': ['udp','junos-radacct'], '2049': ['tcp','junos-nfsd-tcp'], '2049': ['udp','junos-nfsd-udp'], '2401': ['tcp','junos-cvspserver'], '646': ['tcp','junos-ldp-tcp'], '646': ['udp','junos-ldp-udp'], '3220': ['tcp','junos-xnm-ssl'], '3221': ['tcp','junos-xnm-clear-text'], '500': ['udp','junos-ike']}













class GetSRX():

	def __init__(self,connection):
		self.connection		= connection

	def RouteSRX(self,LS, IP):
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Get The Route for: ") + str(IP)
		### logging.info("Get The Route for: " + str(IP))
		

		if LS == 'root-logical-system' :
			LS = ''
		else:
			LS = " logical-system " + LS

			
		T = {}
		#print 'show route %s | display xml\n' %(IP.network
		if type(IP) == IPRange:
			IP = IP[0]
		else:
			IP =  IP.network
		AAA = connect2.SendCommand(self.connection,'show route %s %s | display xml\n' %(LS, IP))
		for ii, i in enumerate(AAA):
			if '<table-name>' in i:
				RT = i.replace('<table-name>','').replace('</table-name>','').lstrip().replace('\n','')
				NW= ''; Pt = '' ; NH = '' ;  Intf=''
				continue
			if '<protocol-name>' in i:
				Pt = i.replace('<protocol-name>','').replace('</protocol-name>','').lstrip().replace('\n','')
				continue
			if '<rt-destination>' in i:
				NW = i.replace('<rt-destination>','').replace('</rt-destination>','').lstrip().replace('\n','')
				continue
			if '<nh-table>' in i:
				NH = i.replace('<nh-table>','').replace('</nh-table>','').lstrip().replace('\n','')
				AAA = connect2.SendCommand(self.connection,'show route%s table %s %s | display xml\n' %(LS,NH, IP))
				for ii, i in enumerate(AAA):
					if '<via>' in i:
						Intf = i.replace('<via>','').replace('</via>','').lstrip().replace('\n','')
						break
				if Intf == '':
					continue
				T[RT] = [NW,Pt, NH, Intf]
				continue
			if '<nh-local-interface>' in i:
				Intf = i.replace('<nh-local-interface>','').replace('</nh-local-interface>','').lstrip().replace('\n','')
				T[RT] = [NW,Pt, NH, Intf]
			if '<to>' in i:
				NH = i.replace('<to>','').replace('</to>','').lstrip().replace('\n','')
			if '<via>' in i:
				Intf = i.replace('<via>','').replace('</via>','').lstrip().replace('\n','')
				T[RT] = [NW,Pt, NH, Intf]
		return T
	# Return T  {'10.74.9.0': 
								# {u'RBT-.inet.0\n': [u'10.74.0.0/20', u'Static', u'10.78.74.9', u'reth1.355'], 
								# u'CH-vr.inet.0\n': [u'10.74.0.0/20', u'Static', u'10.78.74.9', u'reth1.355'], 
								# u'inet.0\n':		[u'0.0.0.0/0', u'Static', u'10.74.169.1', u'fxp0.0']}}

	def ZoneSRX(self,Intf,LS):
		zone = ''
		if LS == 'root-logical-system' :
			NLS = ''
		else:
			NLS = " logical-systems " + LS

		RI = 'inet.0'
		T = {}
		if Intf == 'fxp0.0':
			zone = 'None' ; RI= 'inet.0'
			T[Intf] = [zone,RI]
			return T
			
		AAA = connect2.SendCommand(self.connection,'show configuration%s security zones | display set | match interfaces' %(NLS))
		AAA2 = connect2.SendCommand(self.connection,'show configuration%s routing-instances | display set | match interface' %(NLS))
		
		for i in AAA:

			i = i.replace(NLS , '')

			if 'set security zones security-zone' in i and 'interface' in i and Intf == i.split()[6]:
				zone = i.split()[4]
				
		for i in AAA2:				
			i = i.replace(NLS , '')
			if 'set routing-instances' in i and 'interface' in i and Intf == i.split()[4]:
				RI = i.split()[2]
		if zone == '':
			print "No zone for " + str(Intf)
		T[Intf] = [zone,RI]
		return T    
	### Return T[reth1.355] = [IN-Untrust (Zone), CH-vr(RI)] ###

	def ZonesSRX(self, LS):
		if LS == 'root-logical-system' :
			NLS = ''
		else:
			NLS = " logical-system " + LS



		AAA = connect2.SendCommand(self.connection,'show security zones type security terse%s' %(NLS))
		Z = []
		for i in AAA:
			if 'Security' in i:
				Z.append(i.split()[0])
		return Z 
		# print Z = [u'Zone name', u'Zone name']

	def AddSRX(self,LS,IP):
		if LS == 'root-logical-system' :
			NLS = ''
		else:
			NLS = " logical-systems " + LS

		T = {} ;T[IP] = {}
		if type(IP) == IPRange:
			IPadd  = IP[0]
			IPadd2 = IP[-1]
			AAA = connect2.SendCommand(self.connection,'show configuration %s security zones | display set | match %s | match address-book' %(NLS, IPadd))
			
			for i in AAA:
				i = i.replace(NLS , '')
				if 'set security zones security-zone' in i and 'range-address' == i.split()[8] and i.split()[9] == str(IPadd) and i.split()[11] == str(IPadd2):
					zone = i.split()[4]
					Add = i.split()[7] 
					T[IP][zone] = Add

		else:
			IPadd =  IP.network
			AAA = connect2.SendCommand(self.connection,'show configuration %s security zones | display set | match %s | match address-book' %(NLS, IPadd))
			
			for i in AAA:
				i = i.replace(NLS , '')
				if 'set security zones security-zone' in i and i.split()[8] == str(IP) :
					zone = i.split()[4]
					Add = i.split()[7] 
					T[IP][zone] = Add
		
		return T
	# print T = {'10.74.9.0' : {Untrust: [ 'Address_name'] } }

	def AddINSRX(self,IP,LS):
		if LS == 'root-logical-system' :
			LS = ''
		else:
			LS = " logical-systems " + LS

		T = {};T[IP] = {} ;  IPName = [] ; IPZone = '' ; X = ''
		AAA = connect2.SendCommand(self.connection,'show configuration %s |display set | match address-book' %(LS))
		for i in AAA:
			if  "set groups" in i:
				continue
			if LS == '' and "set logical-systems" in i:
				continue
			i = i.replace(LS , '')
			if "security address-book global address" in i:   ### to overcome the global address
				i = "a a " + i
			if 'range-address' not in i and 'address-set' not in i and IP in IPNetwork(i.split()[8]):
				IPZone = i.split()[4]  ###zone = in
				if IPZone != X:
					X = IPZone
					IPName = []

				IPName.append(i.split()[7])
				T[IP][IPZone] = IPName
				continue

			if 'range-address' in i and IP in IPRange(i.split()[9] , i.split()[11]):
				IPZone = i.split()[4]  ###zone = in
				if IPZone != X:
					X = IPZone
					IPName = []
				
				IPName.append(i.split()[7])
				T[IP][IPZone] = IPName

			#################   Due to Error at IPRange Function ########################
			###r = IPRange('10.1.1.1', '10.1.1.3')	                                   ##
			###i = IPNetwork('10.1.1.1')                                               ##
			###if i in r: print True                                                   ##
			#############################################################################
			if  'range-address' in i  and len(IP) == 1: # and len(IPRange(i.split()[9] , i.split()[11])) == 2
				for t in IPRange(i.split()[9] , i.split()[11]):
					if IPAddress(IP) == t:
						IPZone = i.split()[4]  ###zone = in
						if IPZone != X:
							X = IPZone
							IPName = []
			
						IPName.append(i.split()[7])
						T[IP][IPZone] = IPName
					
						
			if 'address-set' in i and i.split()[9] in IPName:
				IPZone = i.split()[4]  ###zone = in
				if IPZone != X:
					X = IPZone
					IPName = []
				
				IPName.append(i.split()[7])
				T[IP][IPZone] = IPName
		return T
		# print T = {'10.74.9.0' : {Untrust: [ 'Address_name' , Address_name2] } }
					
	def ServSRX(self,LS, SerT, SerU, SerS,Pred):
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Get List of Services")
		### logging.info("Get List of Services")
		SS= [] ; SA = []
		
		if LS == 'root-logical-system' :
			NLS = ''
		else:
			NLS = " logical-systems " + LS


		# if IMS == ' logical-system IMS':
			# IMS = ' logical-systems IMS'
		for service in Pred:
			SS.append('junos-' + service.lower())  ###  different than Forti Script
			continue
			
		for service in SerT:
			Q = 0
			if service in PredefinedSerListSRX.keys():
				if PredefinedSerListSRX[service][0] == 'tcp':
					SS.append(PredefinedSerListSRX[service][1]) 
					continue

			
			AAA = connect2.SendCommand(self.connection,'show configuration%s applications | display set' %(NLS))
			
			for ii,i in enumerate(AAA):
				i = i.replace(NLS, '')
				if 'source-port' in AAA[ii-1]:
					if 'destination-port' in i and service == i.split()[5] and 'tcp' in AAA[ii-2].replace(NLS , '').split()[5] and 'term' not in i.split()[4]:
						SS.append(i.split()[3]) ; Q = 1
						break
				else:
					if 'destination-port' in i and service == i.split()[5] and 'tcp' in AAA[ii-1].replace( NLS , '').split()[5] and 'term' not in i.split()[4]:
						SS.append(i.split()[3]) ; Q = 1
						break
			if Q == 0:	
				SA.append(service + '_TCP') 
		for service in SerU:
			Q = 0
			if service in PredefinedSerListSRX.keys():    ### Check the predefined Service
				if PredefinedSerListSRX[service][0] == 'udp':
					SS.append(PredefinedSerListSRX[service][1]) 
					continue
			AAA = connect2.SendCommand(self.connection,'show configuration%s applications | display set' %(NLS))
			
			for ii,i in enumerate(AAA):
				i = i.replace( NLS , '')
				if 'source-port' in AAA[ii-1]:
					if 'destination-port' in i and service == i.split()[5] and 'udp' in AAA[ii-2].replace( NLS , '').split()[5] and 'term' not in i.split()[4]:
						SS.append(i.split()[3]) ; Q = 1
						break
				else:
					if 'destination-port' in i and service == i.split()[5] and 'udp' in AAA[ii-1].replace( NLS , '').split()[5] and 'term' not in i.split()[4]:
						SS.append(i.split()[3]) ; Q = 1
						break
			#print 'Missing Service: ' + service
			if Q == 0:
				SA.append(service + '_UDP')	
		for service in SerS:
			Q = 0
			AAA = connect2.SendCommand(self.connection,'show configuration%s applications | display set' %( NLS ))
			
			for ii,i in enumerate(AAA):
				i = i.replace(NLS,'')
				if 'source-port' in AAA[ii-1]:
					if 'destination-port' in i and service == i.split()[5] and 'sctp' in AAA[ii-2].replace( NLS, '').split()[5] and 'term' not in i.split()[4]:
						SS.append(i.split()[3]) ; Q = 1
						break
				else:
					if 'destination-port' in i and service == i.split()[5] and 'sctp' in AAA[ii-1].replace( NLS , '').split()[5] and 'term' not in i.split()[4]:
						SS.append(i.split()[3]) ; Q = 1
						break
			#print 'Missing Service: ' + service
			if Q == 0:
				SA.append(service + '_SCTP')
			
		if 'junos-icmp-all' not in SS:
			SS.append('junos-icmp-all')
		
		return SS , SA

	def RISRX(self,LS):
		RI = ['inet.0']
		AAA = []

		if LS == 'root-logical-system':
			NLS = ''
		else:
			NLS = ' logical-systems ' + LS


		AAA = connect2.SendCommand(self.connection,'show configuration%s routing-instances | display set | match interface' %(NLS))
		
		for i in AAA:
			i = i.replace( NLS , '')

			if i.split()[2]+ '.inet.0' not in RI:
				RI.append(i.split()[2]+ '.inet.0')


		return RI

	def PolicySRX(self,LS,IPs, IPd, X, Y, Any):
		AddNameLists = self.AddINSRX(IPs,LS)
		AddNameListd = self.AddINSRX(IPd,LS)
		if LS == 'root-logical-system':
			LS = ''
		else:
			LS = ' logical-systems ' + LS

		# if IMS == ' logical-system IMS':
			# IMS = ' logical-systems IMS'
		a1 = False ; a2 = False
		### PolicyConfig = [] ; PoliciesNo = [] ;
		Config = '' ;  Policies = {}
		AAA = connect2.SendCommand(self.connection,'show configuration%s security policies from-zone %s to-zone %s |display set' %(LS,X,Y))
		for ii, i in enumerate(AAA):
			Config = Config + i + '\n'
			i = i.replace( LS , '')
			if 'source-address' in i:
				for AddNames in AddNameLists[IPs][X]:
					if AddNames == i.split()[11]:
						a1 = True
				if Any == False:
					continue
				else:
					if 'any' in i.split()[11].lower():
						a1 = True
						continue
			if 'destination-address' in i:
				for AddNamed in AddNameListd[IPd][Y]:
					if AddNamed == i.split()[11]:
						a2 = True
						continue
				if Any == False:
					continue
				else:
					if 'any' in i.split()[11].lower():
						a2 = True
						continue
			if 'then' in i:
				if a1 == True and a2 == True:
					PolicyName = i.split()[8]
					Policies[PolicyName] = Config
				Config = ''
				a1 = False ; a2 = False
		return Policies

	def NATSRX(self,SRCB,DSTB,SRCA,DSTA):
		if SRCB != IPNetwork('0.0.0.0/0') or DSTB != IPNetwork('0.0.0.0/0'):
			#################### Source NAT  #####################
			config = '' ; Pool = '' ; ruleset = '' ; rule = ''
			jj1  = False ; jj2  = False
			VV = [IPNetwork('255.255.255.255')] ; VVVV= [IPNetwork('255.255.255.255')]
			AAA = connect2.SendCommand(self.connection,'show configuration security nat source | display set')
			for ii, i in enumerate(AAA):
				if 'source-address' in i:
					VV.append(IPNetwork(i.split()[10]))
					ruleset = i.split()[5]
					rule    = i.split()[7]
					config = config + i
					continue
				if 'destination-address' in i:
					VVVV.append(IPNetwork(i.split()[10]))
					config = config + i
					continue

				if 'then' in i:
					config = config + i
					for V in VV:
						if SRCB in V or SRCB == IPNetwork('0.0.0.0/0'):
							jj1 = True
					for VVV in VVVV:
						if DSTB in VVV or DSTB == IPNetwork('0.0.0.0/0'):
							jj2 = True
					if jj1 == True and jj2 == True:
						Pool = i.split()[11]

						AAAA = connect2.SendCommand(self.connection,'show configuration security nat source | display set | match "nat source pool"')
						for iiii, ii in enumerate(AAAA):
							if Pool == ii.split()[5]:
								config = config + ii
						print config
				
					jj1  = False ; jj2  = False
					config = ''	 ; Pool = ''			
					VV = [IPNetwork('255.255.255.255')]
					VVVV= [IPNetwork('255.255.255.255')]
					continue

				if 'rule ' + rule in i:
					config = config + i
			#################### Distinatiom NAT  #####################
			config = '' ; Pool = ''
			jj1  = False ; jj2  = False
			VV = [IPNetwork('255.255.255.255')] ; VVVV= [IPNetwork('255.255.255.255')]
			AAA = connect2.SendCommand(self.connection,'show configuration security nat destination | display set')
			for ii, i in enumerate(AAA):
				if 'source-address' in i:
					VV.append(IPNetwork(i.split()[10]))
					ruleset = i.split()[5]
					rule    = i.split()[7]
					config = config + i
					continue
				if 'destination-address' in i:
					VVVV.append(IPNetwork(i.split()[10]))
					ruleset = i.split()[5]
					rule    = i.split()[7]
					config = config + i
					continue

				if 'then' in i:
					config = config + i
					for V in VV:
						if SRCB in V or SRCB == IPNetwork('0.0.0.0/0'):
							jj1 = True
					for VVV in VVVV:
						if DSTB in VVV or DSTB == IPNetwork('0.0.0.0/0'):
							jj2 = True
					if jj1 == True and jj2 == True:
						Pool = i.split()[11]
									
				
						AAAA = connect2.SendCommand(self.connection,'show configuration security nat destination | display set | match "nat destination pool"')
						for iiii, ii in enumerate(AAAA):
							if Pool == ii.split()[5]:
								config = config + ii
						print config
				
					jj1  = False ; jj2  = False
					config = ''	 ; Pool = ''			
					VV = [IPNetwork('255.255.255.255')]
					VVVV= [IPNetwork('255.255.255.255')]
					continue
				if 'rule ' + rule in i:
					config = config + i			
					
		################ PART 2 ############

		rule = '' ; ruleset = '' ; config = '' ; PoolName = ''	
			
			######################## Source Pool ######################
		if SRCA != IPNetwork('0.0.0.0/0'):
			rule = '' ; ruleset = '' ; config = '' ; PoolName = ''
			AAA = connect2.SendCommand(self.connection,'show configuration security nat source | display set | match "nat source pool" | except host-address-base')
			for ii, i in enumerate(AAA):
				if ' address ' in i and ' to ' in i and 'host' not in i:
					if len(SRCA) == 1:
						if IPAddress(SRCA) in [z for  z in IPRange(IPAddress(str(i.split()[7]).replace('/32','')), IPAddress(str(i.split()[9]).replace('/32','')))]:
							PoolName =  i.split()[5]
							continue
				if ' address ' in i and ' to ' in i and 'host' not in i and SRCA in IPRange(IPAddress(str(i.split()[7]).replace('/32','')), IPAddress(str(i.split()[9]).replace('/32',''))):
					PoolName =  i.split()[5]
					continue


				if ' address ' in i and ' to ' not in i and 'host' not in i and SRCA in IPNetwork(str(i.split()[7])):	
					PoolName =  i.split()[5]
					continue

			######################## Destination Pool ######################
		if DSTA != IPNetwork('0.0.0.0/0'):
			AAA = connect2.SendCommand(self.connection,'show configuration security nat destination | display set | match "nat destination pool" | except host-address-base')
			for ii, i in enumerate(AAA):
				if ' address ' in i and ' to ' in i and 'host' not in i:
					if len(DSTA) == 1:
						if IPAddress(DSTA) in [z for  z in IPRange(IPAddress(str(i.split()[7]).replace('/32','')), IPAddress(str(i.split()[9]).replace('/32','')))]:
							PoolName =  i.split()[5]
							continue
				if ' address ' in i and ' to ' in i and 'host' not in i and DSTA in IPRange(IPAddress(str(i.split()[7]).replace('/32','')), IPAddress(str(i.split()[9]).replace('/32',''))):
					PoolName =  i.split()[5]
					continue


				if ' address ' in i and ' to ' not in i and 'host' not in i and DSTA in IPNetwork(str(i.split()[7])):	
					PoolName =  i.split()[5]
					continue
			print PoolName

		if PoolName != '':
			######################## Print Policy from Pool #########################
			AAA = connect2.SendCommand(self.connection,'show configuration security nat | display set')
			for ii, i in enumerate(AAA):
				if 'source-address' in i:
					if rule != i.split()[7]:
						config = ''
					config = config + i
					ruleset = i.split()[5]
					rule    = i.split()[7]
					continue
				if 'destination-address' in i:
					if rule != i.split()[7]:
						config = ''
					config = config + i
					ruleset = i.split()[5]
					rule    = i.split()[7]
					continue
				if len(i.split()) == 12:
					if 'then' in i and PoolName == i.split()[11]:
						config = config + i
						print config
						config = ''
						continue
				if PoolName == i.split()[5]:
					print i

				if 'rule ' + rule in i:
					config = config + i	

	def LSSRX(self):
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Get Firewall Logical Systems")
		### logging.info("Get Firewall Logical Systems")
		LS = ['root-logical-system']
		AAA = connect2.SendCommand(self.connection,'show configuration system security-profile | display set')

		for i in AAA:
			
			if 'logical-system' in i and 'logical-system' == i.split()[4]:
				LS.append(i.split()[5])
		return LS 
		# print LS = [u'logical-system', u'logical-system', u'logical-system', u'logical-system', u'logical-system', u'logical-system']

	def AddressesPerZone(self,LS, zone):
		
		if LS == 'root-logical-system' :
			NLS = ''
		else:
			NLS = " logical-systems " + LS

		if zone == 'global':
			AAA = connect2.SendCommand(self.connection,'show configuration %s security | display set' %(NLS))

			ADDes = {}
			for i in AAA:
				Newi = i.replace( NLS , '')
				if 'set security address-book global address ' in Newi:
					ADDes[Newi.split()[5]] = Newi.split()[6]
			return ADDes

		else:
			AAA = connect2.SendCommand(self.connection,'show configuration %s security zones | display set' %(NLS))
			ADDes = {}
			for i in AAA:
				
				Newi = i.replace( NLS , '')

				if 'security-zone '+zone+' address-book address ' in Newi:
					ADDes[Newi.split()[7]] = Newi.split()[8]

			return ADDes
		# print ADDes = {u'10.58.216.213-Name': u'10.58.216.213/32;', u'10.58.216.211/32-Name': u'10.58.216.211/32;'

	def AddressesSetPerZone(self,LS, zone):
		
		if LS == 'root-logical-system' :
			NLS = ''
		else:
			NLS = " logical-systems " + LS

		if zone == 'global':
			AAA = connect2.SendCommand(self.connection,'show configuration %s security | display set' %(NLS))

			ADDes = {}
			for i in AAA:
				Newi = i.replace( NLS , '')
				if 'set security address-book global address-set' in Newi:
					ADDes.setdefault(Newi.split()[5],[]).append(Newi.split()[7])
			return ADDes

		else:
			AAA = connect2.SendCommand(self.connection,'show configuration %s security zones | display set' %(NLS))
			ADDes = {}
			for i in AAA:
				
				Newi = i.replace( NLS , '')

				if 'security-zone '+zone+' address-book address-set' in Newi:
					ADDes.setdefault(Newi.split()[7],[]).append(Newi.split()[9])
			return ADDes
		# print ADDes = {u'10.58.216.213-Name': u'10.58.216.213/32;', u'10.58.216.211/32-Name': u'10.58.216.211/32;'

	def CleanAddresses(self,LS):       #### Dupicated Address
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Clean Addresses")
		### logging.info("Clean Addresses")

		if LS == 'root-logical-system' :
			NLS = ''
		else:
			NLS = " logical-systems " + LS

		zones = self.ZonesSRX(LS)
		zones.append('global')
		for zone in zones:
			if zone == 'junos-host':
				continue


			addresses = self.AddressesPerZone(LS,zone)

			a = {}
			####  Get the dublicated Values  ####
			for key, value in addresses.items():   #### re arrange the addresses
				if value not in a:
					a[value] = [key]
				else:
					a[value].append(key)
					
			for key, value in a.items():   ### Delete the non duplicated values
				if len(value) == 1 or  key == 'range-address':
					del a[key]
			######################################
			print LS, zone ,a

			for key, value in a.items():   #### IP, Addresses
				print 'IP: ' + key + '   Addresses: ' + ' , '.join(value)
				print
				
				
				if value[0] == value[1]+'/32' and len(value) == 2:
					given_value = value[0]
				elif value[1] == value[0]+'/32' and len(value) == 2:
					given_value = value[1]
					
				else:
					given_value = raw_input("Select one: ")
					
				if given_value not in value and zone != "global":
					print "set %s security zones security-zone %s address-book address %s %s" %(NLS,zone,given_value,key)
				if given_value not in value and zone == "global":
					print "set %s security address-book address global %s %s" %(NLS,given_value,key)
					
					
				for ii in range(len(sorted(value))):
					if value[ii] == given_value:
						continue

					AAA = connect2.SendCommand(self.connection,'show configuration %s security | display set' %(NLS))

					for i in AAA:
						Newi = i.replace(NLS , '')


						################   NAT ##################################
						if 'source-address-name' in Newi or 'destination-address-name' in Newi:
							if len(Newi.split()) > 10 and  value[ii] == Newi.split()[10]:
								print "delete " + " ".join(i.split()[1:])
								print " ".join(i.split()[:len(i.split())-1]) + " " + given_value    #### Replace the last value at the string with new value
								continue

						if zone not in Newi and zone != "global":
							continue
						
						######### Policy Match #################################
						if 'security policies from-zone' in Newi and len(Newi.split()) > 11 and value[ii] == Newi.split()[11]:
							if 'destination-address' in Newi and 'to-zone ' + zone in Newi:
								print "delete " + " ".join(i.split()[1:])
								print " ".join(i.split()[:len(i.split())-1]) +  " " + given_value
								continue
							
							elif 'source-address' in Newi and 'from-zone ' + zone in Newi:
								print "delete " + " ".join(i.split()[1:])
								print " ".join(i.split()[:len(i.split())-1]) + " " + given_value
								continue
							elif zone == "global":
								print "delete " + " ".join(i.split()[1:])
								print " ".join(i.split()[:len(i.split())-1]) +  " " + given_value
								continue
							
						if 'zones security-zone' in Newi and len(Newi.split()) > 7 and zone in Newi.split()[4] and  value[ii] == Newi.split()[7]:
							print "delete " + " ".join(i.split()[1:])
							continue
						if 'zones security-zone' in Newi and 'address-set' in Newi and len(Newi.split()) > 9 and zone in Newi.split()[4] and  value[ii] == Newi.split()[9]:
							print "delete " + " ".join(i.split()[1:])
							print " ".join(i.split()[:len(i.split())-1]) + " " + given_value
							continue
						### For Global Zone ####	


						if 'address-set' in Newi and len(Newi.split()) > 7 and zone in Newi.split()[3] and  value[ii] == Newi.split()[7] and zone == "global":
							print "delete " + " ".join(i.split()[1:])
							print " ".join(i.split()[:len(i.split())-1]) + " " + given_value
							continue
						if 'security address-book' in Newi and len(Newi.split()) > 6 and zone in Newi.split()[3] and  value[ii] == Newi.split()[5] and zone == "global":
							print "delete " + " ".join(i.split()[1:])
							continue

	def CleanUnusedAddresses(self,LS):

		if LS == 'root-logical-system' :
			NLS = ''
		else:
			NLS = " logical-systems " + LS

		zones = self.ZonesSRX(LS)
		zones.append('global')
		
		
		AAA = connect2.SendCommand(self.connection,'show configuration %s security | display set' %(NLS))


		for zone in zones:
			if zone == 'junos-host':
				continue
			addresses = self.AddressesPerZone(LS,zone)
			addressSet = self.AddressesSetPerZone(LS,zone)


			print LS, zone

			for key, value in addresses.items():   #### IP, Addresses

				for i in AAA:

					Newi = i.replace(NLS , '')
					if key not in Newi or addresses[key] == '':
						continue

					if 'security nat' in Newi:
						if 'destination-address-name' in Newi or 'source-address-name' in Newi and key == Newi.split()[10]:
							addresses[key] = ''
							continue

					if 'security policies' in Newi and zone in Newi and "policies global policy" not in Newi:
						if 'source-address' in Newi or 'destination-address' in Newi:
							if key == Newi.split()[11]:
								addresses[key] = ''
								continue
								
					if 'policies global policy' in Newi:   #### Global policy
						if 'source-address' in Newi or 'destination-address' in Newi:
							if key == Newi.split()[8]:
								addresses[key] = ''
								continue
								
					if 'security zones' in Newi and 'address-set' in Newi and zone in Newi:
						if key == Newi.split()[9]:
							addresses[key] = ''
							continue
					######## Global Zone ########
					
					if 'security policies' in Newi and zone == 'global' and "policies global policy" not in Newi:
						if 'source-address' in Newi or 'destination-address' in Newi:
							if key == Newi.split()[11]:
								addresses[key] = ''
								continue
					
					if 'address-book global' in Newi and 'address-set' in Newi and zone == 'global':
						if key == Newi.split()[7]:
							addresses[key] = ''
							continue					
				if addresses[key] != '' and zone != 'global':
					print "delete%s security zones security-zone " %(NLS) + zone + " address-book address " + key		
					
				if addresses[key] != '' and zone == 'global':
					print "delete%s security address-book global address " %(NLS)  + key
	
			
			##### Duplicated Address-Set #####
			for key, value in addressSet.items():   #### IP, Addresses
				for i in AAA:
					Newi = i.replace(NLS , '')
					if key not in Newi or addressSet[key] == '':
						continue

					if 'security nat' in Newi:
						if 'destination-address-name' in Newi or 'source-address-name' in Newi and key == Newi.split()[10]:
							addressSet[key] = ''
							continue

					if 'security policies' in Newi and zone in Newi and "policies global policy" not in Newi:
						if 'source-address' in Newi or 'destination-address' in Newi:
							if key == Newi.split()[11]:
								addressSet[key] = ''
								continue
								
					if 'policies global policy' in Newi:   #### Global policy
						if 'source-address' in Newi or 'destination-address' in Newi:
							if key == Newi.split()[8]:
								addressSet[key] = ''
								continue
								
					######## Global Zone ########
					
					if 'security policies' in Newi and zone == 'global' and "policies global policy" not in Newi:
						if 'source-address' in Newi or 'destination-address' in Newi:
							if key == Newi.split()[11]:
								addressSet[key] = ''
								continue
					
				
				if addressSet[key] != '' and zone != 'global':
					print "delete%s security zones security-zone " %(NLS) + zone + " address-book address-set " + key		
					
				if addressSet[key] != '' and zone == 'global':
					print "delete%s security address-book global address-set " %(NLS)  + key

	def NAT_cleanup(self,LS):
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Clean NAT")
		if LS == 'root-logical-system' :
			NLS = ''
		else:
			NLS = " logical-systems " + LS

		SourceNAT = ''
		
		
		AAA = connect2.SendCommand(self.connection,'show configuration %s security nat | display xml' %(NLS))

		xmldoc = minidom.parse("AAA.read")
		for i in AAA:
			xmldoc = minidom.parse("kml.xml")

		
		DestiantionNAT = ''

		for zone in zones:
			if zone == 'junos-host':
				continue
			addresses = self.AddressesPerZone(LS,zone)

			a = {}
			####  Get the dublicated Values  ####
			for key, value in addresses.items():   #### re arrange the addresses
				if value not in a:
					a[value] = [key]
				else:
					a[value].append(key)
					
			for key, value in a.items():   ### Delete the non duplicated values
				if len(value) == 1:
					del a[key]
			######################################
			print LS, zone ,a

			for key, value in a.items():   #### IP, Addresses
				print 'IP: ' + key + '   Addresses: ' + ' , '.join(value)

				
				if value[0] == value[1]+'/32' and len(value) == 2:
					given_value = value[0]
				elif value[1] == value[0]+'/32' and len(value) == 2:
					given_value = value[1]
					
				else:
					given_value = raw_input("Select one: ")
					
				if given_value not in value:
					print "set %s security zones security-zone %s address-book address %s %s" %(NLS,zone,given_value,key)

				for ii in range(len(sorted(value))):
					if value[ii] == given_value:
						continue

					AAA = connect2.SendCommand(self.connection,'show configuration %s security | display set' %(NLS))

					for i in AAA:
						Newi = i.replace(NLS , '')



						if 'source-address-name' in Newi or 'destination-address-name' in Newi:
							if len(Newi.split()) > 10 and  value[ii] == Newi.split()[10]:
								print "delete " + " ".join(i.split()[1:])
								print i.replace(value[ii],given_value)
								continue

						if zone not in Newi:
							continue

						if 'security policies from-zone' in Newi and len(Newi.split()) > 11 and value[ii] == Newi.split()[11]:
							print "delete " + " ".join(i.split()[1:])
							print i.replace(value[ii],given_value)
							continue
						if 'zones security-zone' in Newi and len(Newi.split()) > 7 and zone in Newi.split()[4] and  value[ii] == Newi.split()[7]:
							print "delete " + " ".join(i.split()[1:])
							continue
						if 'zones security-zone' in Newi and 'address-set' in Newi and len(Newi.split()) > 9 and zone in Newi.split()[4] and  value[ii] == Newi.split()[9]:
							print "delete " + " ".join(i.split()[1:])
							print i.replace(value[ii],given_value)
							continue
			
	def QuickPolicyCheck(self,LS, SourceIP,DestiantionIP):
		if LS == 'root-logical-system' :
			NLS = ''
		else:
			NLS = " logical-systems " + LS



		###  stdin, stdout, stderr = self.connection.exec_command('show configuration %s security | display xml | no-more' %(NLS))


		###  xmldoc = minidom.parse(stdout)



		#

		xmldoc = minidom.parse("C:\\Users\\hashem\\Desktop\\Python_Project\\V6\\policy_sec3.xml")





		###  stdin , stdout, stderr = self.connection.exec_command('show configuration %s security policies | display xml | no-more' %(NLS))
		###  xmldoc = minidom.parse(stdout)

		## Policies = xmldoc.getElementsByTagName("policies")[0]

		if SourceIP == "any" or SourceIP == "0.0.0.0" or SourceIP == all:
			AddresslistSRC  = "0.0.0.0"
		else:
			AddresslistSRC  = self.AddINSRX(IPNetwork(SourceIP) , LS)

		if DestiantionIP == "any" or DestiantionIP == "0.0.0.0" or DestiantionIP == "all":
			AddresslistDST = "0.0.0.0"
		else:
			AddresslistDST  = self.AddINSRX(IPNetwork(DestiantionIP) , LS)

		print SourceIP, AddresslistSRC
		print DestiantionIP, AddresslistDST
		# print "test2"
		### print Addresslist
		# print T = {'10.74.9.0' : {Untrust: [ 'Address_name' , Address_name2] } }

		for i in range(len(xmldoc.getElementsByTagName("from-zone-name"))):

			try:
				AddresslistSRC2 =  AddresslistSRC[IPNetwork(SourceIP)][xmldoc.getElementsByTagName("from-zone-name")[i].firstChild.data]
				AddresslistDST2 =  AddresslistDST[IPNetwork(DestiantionIP)][xmldoc.getElementsByTagName("to-zone-name")[i].firstChild.data]
				print AddresslistSRC2
				print AddresslistDST2
			except:
				continue
			for policy in xmldoc.getElementsByTagName("policy"):

				if len(policy.getElementsByTagName("from-zone-name")) != 0:
					continue
				for z in AddresslistSRC2:
					#  print " ".join(p.firstChild.data for p in policy.getElementsByTagName("destination-address"))
					if z in " ".join(p.firstChild.data for p in policy.getElementsByTagName("source-address")):
						# print policy.getElementsByTagName("name")[0].firstChild.data
						# print " ".join(p.firstChild.data for p in policy.getElementsByTagName("destination-address"))
						# print " ".join(p.firstChild.data for p in policy.getElementsByTagName("application"))

						for zz in AddresslistDST2:
							#  print " ".join(p.firstChild.data for p in policy.getElementsByTagName("destination-address"))
							if zz in " ".join(p.firstChild.data for p in policy.getElementsByTagName("destination-address")):
								print policy.getElementsByTagName("name")[0].firstChild.data
								# print " ".join(p.firstChild.data for p in policy.getElementsByTagName("destination-address"))
								# print  " ".join(p.firstChild.data for p in policy.getElementsByTagName("application"))

	def CleanPoliciesSRX(self, LS):
		if LS == 'root-logical-system' :
			NLS = ''
			NLS2 = ''
		else:
			NLS = " logical-systems " + LS
			NLS2 = " logical-system " + LS
		stdin, stdout, stderr = self.connection.exec_command('show configuration %s security | display xml | no-more' %(NLS))
		stdin2, stdout2, stderr2 = self.connection.exec_command('show security policies hit-count %s  | display xml | no-more' %(NLS2))
		
		
		xmldoc = minidom.parse(stdout)
		xmldoc2 = minidom.parse(stdout2)

		# pretty_xml_as_string = xmldoc.toprettyxml()
		# print pretty_xml_as_string
		Policies = xmldoc.getElementsByTagName("policies")[0]
		Policies1 = Policies.getElementsByTagName("policy")

		ToZone1 = '' ; FromZone1 = ''
		for policy_from_to in Policies1:
			TTT = [] ;
			
			
			if not policy_from_to.getElementsByTagName("from-zone-name"):
				continue
			
			FromZone = policy_from_to.getElementsByTagName("from-zone-name")[0].firstChild.data
			ToZone = policy_from_to.getElementsByTagName("to-zone-name")[0].firstChild.data
			# print "From Zone: " + FromZone
			# print "To Zone: " + ToZone
			
			policy1 = policy_from_to.getElementsByTagName("policy")
			
			for p1 in policy1:
				sourceaddress = '' ; destinationaddress = '' ; application = ''
				L1 =[] ;L2 =[] ;L3 =[]
				
				
				if p1.getElementsByTagName("name")[0].firstChild.data in TTT:
					continue
				
				sourceaddress = p1.getElementsByTagName("source-address")
				for r in sourceaddress: L1.append(r.firstChild.data)

				destinationaddress =  p1.getElementsByTagName("destination-address")
				for r in destinationaddress: L2.append(r.firstChild.data)
				
				application =  p1.getElementsByTagName("application")
				for r in application: L3.append(r.firstChild.data)
				
		
				
				X =  p1.getElementsByTagName("name")[0].firstChild.data

				
				ListOfSRC = [] ; ListOfDST = [] ; ListOfAPP = [] ; ListOfPol = []
				
				for p2 in policy1:
					sourceaddress1 = '' ; destinationaddress1 = '' ; application1 = '';
					K1 =[] ;K2 =[] ;K3 =[]
		
					sourceaddress1 = p2.getElementsByTagName("source-address")
					for r in sourceaddress1: K1.append(r.firstChild.data)

					destinationaddress1 =  p2.getElementsByTagName("destination-address")
					for r in destinationaddress1: K2.append(r.firstChild.data)
					
					application1  =  p2.getElementsByTagName("application")
					for r in application1: K3.append(r.firstChild.data)
					
					Y =  p2.getElementsByTagName("name")[0].firstChild.data	
					###########	SRC	###############
					if L2 == K2 and L3 == K3 and X != Y and L1 != ['any'] and K1 != ['any']:   ### If dst = dst and app = app and source not have any
						TTT.append(Y)
						ListOfSRC.append(" ".join(K1))
						ListOfPol.append(Y)
						continue
					###########	DST	###############
					if L1 == K1 and L3 == K3 and X != Y and L2 != ['any'] and K2 != ['any']:
						TTT.append(Y)
						ListOfDST.append(" ".join(K2))
						ListOfPol.append(Y)
						continue
					###########	APP	###############
					if L1 == K1 and L2 == K2 and X != Y and L3 != ['any'] and K3 != ['any']:
						TTT.append(Y)
						ListOfAPP.append(" ".join(K3))
						ListOfPol.append(Y)
						continue

						
				#################   Printing    #############################
				if ListOfSRC != [] or ListOfDST != [] or ListOfAPP != []:
					
					if FromZone != FromZone1 and ToZone != ToZone1:
						print "From Zone: " + FromZone
						print "To Zone: " + ToZone
						ToZone1 = ToZone
						FromZone1 = FromZone
					###########  Hit count  ##############
					
					for policyHitcount in xmldoc2.getElementsByTagName("policy-hit-count-entry"):
						if FromZone == policyHitcount.getElementsByTagName("policy-hit-count-from-zone")[0].firstChild.data and ToZone == policyHitcount.getElementsByTagName("policy-hit-count-to-zone")[0].firstChild.data and X == policyHitcount.getElementsByTagName("policy-hit-count-policy-name")[0].firstChild.data:
							Policy_HitCount = policyHitcount.getElementsByTagName("policy-hit-count-count")[0].firstChild.data 
							break
							
					print "Policy: " + X + "        Hitcount: " + Policy_HitCount
					PolicyAndHits1 = []
					ListOfPol1 = []
					for Z in ListOfPol:
						for policyHitcount in xmldoc2.getElementsByTagName("policy-hit-count-entry"):
							if FromZone == policyHitcount.getElementsByTagName("policy-hit-count-from-zone")[0].firstChild.data and ToZone == policyHitcount.getElementsByTagName("policy-hit-count-to-zone")[0].firstChild.data and Z == policyHitcount.getElementsByTagName("policy-hit-count-policy-name")[0].firstChild.data:
								PolicyAndHits1.append(Z)
								PolicyAndHits1.append(" Hitcount: ")
								PolicyAndHits1.append(policyHitcount.getElementsByTagName("policy-hit-count-count")[0].firstChild.data)
								if policyHitcount.getElementsByTagName("policy-hit-count-count")[0].firstChild.data == '0':
									ListOfPol1.append(Z)    #### To delete only the policies with 0 hitcount
								break
					
					### print ListOfPol1, ListOfPol
					print 'Duplicated Policy: ' + " ".join(PolicyAndHits1)
					for Z in ListOfPol1:
						print "delete%s security policies from-zone %s to-zone %s policy %s " %(NLS, FromZone, ToZone, Z)
						
				if ListOfSRC != []:
					print "set%s security policies from-zone %s to-zone %s policy %s match source-address [ %s ]" %(NLS, FromZone, ToZone, X, " ".join(str(Z) for Z in ListOfSRC))
				if ListOfDST != []:
					print "set%s security policies from-zone %s to-zone %s policy %s match destination-address [ %s ]" %(NLS, FromZone, ToZone, X, " ".join(str(Z) for Z in ListOfDST))
				if ListOfAPP != []:
					print "set%s security policies from-zone %s to-zone %s policy %s match application [ %s ]" %(NLS, FromZone, ToZone, X, " ".join(str(Z) for Z in ListOfAPP))		


# connection = connect2.ConnectTo("10.11.254.52","thmahmoud","75579997")
# a = GetSRX("asdf")
# a.Yahia2()
## a.QuickPolicyCheck('AD-LSYS','','10.58.126.144')
# print a.RISRX('AD-LSYS',True)

class GetForti():
	def __init__(self,connection):
		self.connection		= connection
		
	def VdomsForti(self):
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Get Firewall VDOMs")
		### logging.info("Get Firewall VDOMs")
		Vdoms = []
		AAA = connect2.SendCommand(self.connection,'config global\nshow system vdom-property\n')

		for ii, i in enumerate(AAA):
			if 'edit' in i:
				Vdoms.append(re.findall(r'\".*\"', AAA[ii])[0].replace('"' , ''))
		return Vdoms
	### Vdoms = ['root' , 'ISP' , 'IT-WAF' , 'Internet' , 'RAN' , 'VAS-Dom' , 'IT-VAS-Back']

	def ZoneForti(self,Vdom,intf):
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Get The Zone for the Interface : ") + str(intf)
		### logging.info("Get The Zone for the Interface : " + str(intf))
		AAA = connect2.SendCommand(self.connection,'config vdom\n\redit %s\n\rshow system zone | grep -f  %s' %(Vdom,intf))
		
		for ii, i in enumerate(AAA):
			if '"' + intf +'"' in i:
				if 'edit' in AAA[ii-1]:
					zn = re.findall(r'\".*\"', AAA[ii-1])[0]
					return zn
				if 'edit' in AAA[ii-2]:
					zn = re.findall(r'\".*\"', AAA[ii-2])[0]
					return zn
	### Zone Name ###

	def RouteForti(self,Vdom,IP):
	
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Get The Route for: ") + str(IP)
		### logging.info("Get The Route for: " + str(IP))
		T = {} ;D = 0 ; NT = ''
		if type(IP) == IPRange:
			B = IP[0]
		else:
			B = IP.network

		AAA = connect2.SendCommand(self.connection,'config vdom\n\redit %s\n\rget router info routing-table details %s' %(Vdom,B))

		if 'Network not in table' in AAA[3]:
			AAA = connect2.SendCommand(self.connection,'config vdom\n\redit %s\n\rget router info routing-table details 0.0.0.0' %(Vdom))
			D = 1

		for iii,i in enumerate(AAA):
			if 'connected' in i:
				NT = AAA[iii-1].split()[9]
				pt='Connected'
				intf = AAA[iii+1].split()[4]
				zn = self.ZoneForti(Vdom,intf)
				NH = ''
				break
			if 'static' in i:
				pt='static'
				if D == 1:
					pt = 'defualt'
				NT = AAA[iii-1].split()[9]
				if 'inactive' in AAA[iii+1]:
					intf = AAA[iii+1].split()[2]
					
				else:
					intf = AAA[iii+1].split()[3]
					NH = AAA[iii+1].split()[1].replace(',','')
				zn = self.ZoneForti(Vdom,intf)

				break
			if 'bgp' in i:
				pt='bgp'
				NT = AAA[iii-1].split()[9]
				intf = AAA[iii+2].split()[3]
				NH = AAA[iii+2].split()[1].replace(',','')
				zn = self.ZoneForti(Vdom,intf)
				break
		if NT == '':
			print 'No route for: ' + str(IP)
			return



		T = [NT ,pt ,intf ,zn,NH]

		return T
	### T = [Network ,'routing protocol', u'routing interface', u'routing Zone']

	def AddForti(self,Vdom,IP,Zone):  ### use the routing zone to confirm the address
		
		
		IPAddrName = 'none' ; ZoneName = 'any'
		if type(IP) == IPRange:
			B = IP[0]
		else:
			B = IP.network
		AAA = connect2.SendCommand(self.connection,'config vdom\n\redit %s\n\rshow firewall address | grep -f %s' %(Vdom,B))
		
		for ii,i in enumerate(AAA):
			if 'set subnet' in i and type(IP) == IPNetwork:             # if there is address match
				if 'associated-interface' in AAA[ii-1] and Zone == re.findall(r'\".*\"', AAA[ii-1])[0]:  # if there is a Zone matched
					if IP.network == IPAddress(AAA[ii].split()[2]) and IP.netmask == IPAddress(AAA[ii].split()[3]) and 'edit' in AAA[ii-3]: # if the IP/subnet match
						IPAddrName = re.findall(r'\".*\"', AAA[ii-3])[0] 
						ZoneName   = re.findall(r'\".*\"', AAA[ii-1])[0]
						break
				elif 'associated-interface' in AAA[ii-1] and Zone != re.findall(r'\".*\"', AAA[ii-1])[0]:  # if there is a Zone and it not matched
					continue
				else:                   ### if global zone
					if  IP.network == IPAddress(AAA[ii].split()[2]) and IP.netmask == IPAddress(AAA[ii].split()[3]) and 'edit' in AAA[ii-2]:# if the IP/subnet match
						IPAddrName = re.findall(r'\".*\"', AAA[ii-2])[0]
						ZoneName   = 'any'
						break
			if 'set start-ip' in i and type(IP) == IPRange:
				if 'associated-interface' in AAA[ii-1] and Zone == re.findall(r'\".*\"', AAA[ii-1])[0]:
					if IP[0] == IPAddress(AAA[ii].split()[2]) and IP[-1] == IPAddress(AAA[ii+1].split()[2]) and 'edit' in AAA[ii-4]:
						IPAddrName = re.findall(r'\".*\"', AAA[ii-4])[0] 
						ZoneName   = re.findall(r'\".*\"', AAA[ii-1])[0]
						break
				else:
					if  IP[0] == IPAddress(AAA[ii].split()[2]) and IP[-1] == IPAddress(AAA[ii+1].split()[2]) and 'edit' in AAA[ii-3]:# 
						IPAddrName = re.findall(r'\".*\"', AAA[ii-3])[0]
						ZoneName   = 'any'
						break
		
		return  [IPAddrName,ZoneName]
	###print GetAddress2('10.74.151.12','root',IPAddress('10.74.154.197'))

	def AddINForti(self,Vdom,IP,zone, Any):   ### Get all Address Names related to the IP
		
		IPAddrList={} 
		print IP
		AAA = connect2.SendCommand(self.connection,'config vdom\n\redit %s\n\rshow firewall address' %(Vdom))
		for ii,i in enumerate(AAA):
			if 'edit' in i:
				IPAddrName = re.findall(r'\".*\"', AAA[ii])[0]
				if 'set type iprange' in AAA[ii+2]:
					if 'set associated-interface' in AAA[ii+3]:
						if zone == re.findall(r'\".*\"', AAA[ii+3])[0]:
							ZZZ = re.findall(r'\".*\"', AAA[ii+3])[0]
							IPAddr2 = IPAddress(AAA[ii+4].split()[2])
							IPAddr3 = IPRange(IPAddr2, AAA[ii+5].split()[2])
						else: 
							continue
					else:
						ZZZ = 'any'
						IPAddr2 = IPAddress(AAA[ii+3].split()[2])
						IPAddr3 = IPRange(IPAddr2, AAA[ii+4].split()[2])
						
						
					if type(IP) == IPRange:
						if IP in IPAddr3:
							IPAddrList[IPAddrName] = [IPAddr3,ZZZ]
							continue
					if type(IP) == IPNetwork:
						if IP in IPAddr3:
							IPAddrList[IPAddrName] = [IPAddr3,ZZZ]
							continue

	#################   Due to Error at IPRange Function ########################
	###r = IPRange('10.1.1.1', '10.1.1.3')	                                   ##
	###i = IPNetwork('10.1.1.1')                                               ##
	###if i in r: print True                                                   ##
	#############################################################################

					if type(IP) == IPNetwork and len(IP) == 1:
						for t in IPAddr3:
							if IPAddress(IP) == t:
								IPAddrList[IPAddrName] = [IPAddr3,ZZZ]
								continue


				if 'set subnet' in AAA[ii+3]:
					if zone == re.findall(r'\".*\"', AAA[ii+2])[0]: ## AAA[ii+2].split()[2]:
						IPAddr= IPNetwork(AAA[ii+3].split()[2]+'/'+AAA[ii+3].split()[3])
						if IP in IPAddr:
							IPAddrList[IPAddrName] = [IPAddr,zone]
						else:   ### Wrong IP
							continue
					else:   ### Wrong zone
						continue
				if 'set subnet' in AAA[ii+2]:
					IPAddr= IPNetwork(AAA[ii+2].split()[2]+'/'+AAA[ii+2].split()[3])
					if IP in IPAddr:
						IPAddrList[IPAddrName] = [IPAddr,'any']
				if Any == True:
					if 'next' in AAA[ii+2]:
						IPAddrList[IPAddrName] = [IPNetwork('0.0.0.0/0'),'any']
						continue
					if 'next' in AAA[ii+3] and 'set subnet' not in AAA[ii+2] and zone == re.findall(r'\".*\"', AAA[ii+2])[0]:
						IPAddrList[IPAddrName] = [IPNetwork('0.0.0.0/0'),zone]
		for a in IPAddrList.keys():
			print a , IPAddrList[a][0] ,IPAddrList[a][1] 
		return IPAddrList
		#{u'TM_OSS_Subnet_10.74.231.0/26': [IPNetwork('10.74.231.0/26'), u'"OSS"'], 
		#	u'10.74.231.5-14': [IPRange('10.74.231.5', '10.74.231.14'), u'"OSS"']}
		
	def ServForti(self,Vdom, SerT, SerU, SerS,Pred): 
		
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Get List Services Name")
		### logging.info("Get List Services Name")
		SS = [] ; SA = []
		for service in Pred:
			SS.append(service)
			
		for service in SerT:
			Q = 0
			AAA = connect2.SendCommand(self.connection,'config vdom\n\redit %s\n\rshow firewall service custom | grep -f %s' %(Vdom,service))
			
			for ii,i in enumerate(AAA):
				if 'tcp-portrange' in i and service == AAA[ii].split()[2].replace(':0-65535','') and 'portrange' not in AAA[ii+1]:
					if 'edit' in AAA[ii-1]:
						ccc1 = re.findall(r"\".*\"", i)
						SS.append(re.findall(r"\".*\"", AAA[ii-1])[0]) ; Q = 1
						break
					else:
						SS.append(re.findall(r"\".*\"", AAA[ii-2])[0]) ; Q = 1
						break
			#print 'Missing Service: ' + service
			if Q == 0:
				SA.append(service + '_TCP') 
		for service in SerU:
			Q = 0
			AAA = connect2.SendCommand(self.connection,'config vdom\n\redit %s\n\rshow firewall service custom | grep -f %s' %(Vdom,service))
			
			for ii,i in enumerate(AAA):
				if 'udp-portrange' in i and service == AAA[ii].split()[2].replace(':0-65535','') and 'portrange' not in AAA[ii+1] and 'portrange' not in AAA[ii-1]:
					if 'edit' in AAA[ii-1]:
						SS.append(re.findall(r"\".*\"", AAA[ii-1])[0]); Q = 1
						break
					else:
						SS.append(re.findall(r"\".*\"", AAA[ii-2])[0]); Q = 1
						break
			#print 'Missing Service: ' + service
			if Q == 0:
				SA.append(service + '_UDP')
		for service in SerS:
			Q = 0
			AAA = connect2.SendCommand(self.connection,'config vdom\n\redit %s\n\rshow firewall service custom | grep -f %s' %(Vdom,service))
			
			for ii,i in enumerate(AAA):
				if 'sctp-portrange' in i and service == AAA[ii].split()[2].replace(':0-65535','') and 'portrange' not in AAA[ii-1]:
					if 'edit' in AAA[ii-1]:
						SS.append(re.findall(r"\".*\"", AAA[ii-2])[0]); Q = 1
						break
					else:
						SS.append(re.findall(r"\".*\"", AAA[ii-2])[0]); Q = 1
						break
			#print 'Missing Service: ' + service
			if Q == 0:
				SA.append(service + '_SCTP')

		if 'PING' not in SS:
			SS.append('PING')
		if 'TRACEROUTE' not in SS:
			SS.append('TRACEROUTE')

		return SS, SA

	def PolicyForti(self,Vdom,IPs, IPd, Any):  ### {'TM_OSS_Subnet_10.74.231.0/26': [IPNetwork('10.74.231.0/26'), u'"OSS"'],
		
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Check the Policies")
		### logging.info("Check the Policies")
		T = self.RouteForti(Vdom,IPs)
		zones = T[3]
		AddNameLists = self.AddINForti(Vdom,IPs,zones,Any)

		TT = self.RouteForti(Vdom,IPd)
		zoned = TT[3]
		AddNameListd = self.AddINForti(Vdom,IPd,zoned,Any)
		### PolicyConfig = [] ; PoliciesNo = [] ;
		Config = '' ;  Policies = {}
		i1 = False ; i2 = False ; i3 = False ; i4 = False
		AAA = connect2.SendCommand(self.connection,'config vdom\n\redit %s\n\rshow firewall policy' %(Vdom))	
		for ii, i in enumerate(AAA):
			Config = Config + i
			if 'edit' in i:
				PolicyNo = i.split()[1]
				continue
			if 'set srcintf' in i and zones in i.split():
				i1 = True
				continue
			if 'set dstintf' in i and zoned in i.split():
				i2 = True
				continue
			if 'set service' in i:
				Services = i.split()[2:]
				continue
			if 'set srcaddr' in i:
				for AddNames in AddNameLists.keys():
					ccc1 = re.findall(r"\".*\"", i)[0].split()
					for aaa in ccc1:
						if AddNames  in aaa:
							i3 = True
							continue
				# if Any == False:
					# continue
				# else:
					# if 'all' in i.split()[2].lower():
						# i3 = True

			if 'set dstaddr' in i:
				for AddNamed in AddNameListd.keys():
					ccc2 = re.findall(r"\".*\"", i)[0].split()
					for aaa in ccc2:
						if AddNamed  in aaa:
							i4 = True
							continue

				# if Any == False:
					# continue
				# else:
					# if 'all' in i.split()[2].lower():
						# i4 = True
				# continue
				
			if 'next' in i:
				if i1 == True and i2 == True and i3 == True and i4 == True:
					Policies[PolicyNo] = Config
				Config = ''
				i1 = False ; i2 = False ; i3 = False ; i4 = False
				
		return Policies 
		### Policies = {u'46': u' edit 46\n  set srcintf "Gen-rd-VRF"\n  set dstintf "OSS"\n   set srcaddr "10.75.7.0/24"\n   set dstaddr "Telemisr_OSS_Subnet_10.74.231.0/24"\n  set action accept\n   set schedule "always"\n   set service "RDP" \n  next\n' }

class GetF5():

	def __init__(self,connection):
		self.connection = connection
	def RouteF5(self):	
		return
	def RDsF5(self):	
		RDs = {}
		AAA = connect2.SendCommand(self.connection,'tmsh list /net route-domain id')
		for ii, i in enumerate(AAA):
			if 'net route-domain' in i:
				T = i.split()[2]
			if 'id'  in i:
				RDs[i.split()[1]] = T

		return RDs
# MI_10.114.128.0_18 { source { addresses { 10.114.128.0/18 { } } } translation { source Drafts/MI_197.198.128.0_18 }
	def NATF5(self,SRCB,DSTB,SRCA,DSTA):
		
		T  = {} ; TT= {} ; TTT= {} ; TTTT = {}; ST = {} ; DT = {}
		AAA = connect2.SendCommand(self.connection,'tmsh show running-config security nat one-line recursive')
		for ii, i in enumerate(AAA):
			if 'security nat policy' in i:
				for jj , j in enumerate(i.split()):
					if 'source' == j and i.split()[jj+1] == '{':
						T[i.split()[jj+12]] = i.split()[jj+4]    ### Name  :IP
						##############################
						# if SRCB in IPNetwork(i.split()[jj+4]) or SRCB == IPNetwork('0.0.0.0/0'):
							# if i.split()[jj+7] == 'destination' and i.split()[jj+8] == '{':  #If there is a match source and destination
								# print 'Yes'
							# elif i.split()[jj+12] == 'translation' and i.split()[jj+11] == 'source':
								# print i.split()[jj+12]
						##############################
						
						
					if 'destination' == j and i.split()[jj+1] == '{':
						TT[i.split()[jj+12]] = i.split()[jj+4]
						##############################
						# if DSTB in IPNetwork(i.split()[jj+4]) or SRCB == IPNetwork('0.0.0.0/0'):
							
							# if i.split()[jj+12] == 'translation' and i.split()[jj+11] == 'destination':
								# print i.split()[jj+12]						
						##############################
				continue
			if 'source-translation' in i:
				for jj , j in enumerate(i.split()):
					if 'source-translation' in j:
						TTT[i.split()[jj+1]] = i.split()[jj+5]   ### Name : IPs
						continue
			if 'destination-translation' in i:
				for jj , j in enumerate(i.split()):
					if 'destination-translation' in j:
						TTTT[i.split()[jj+1]] = i.split()[jj+5]
						continue
		for K in T.keys():
			if K in TTT.keys():
				ST[T[K]] = TTT[K]
				continue
		for K in TT.keys():
			if K in TTTT.keys():
				DT[TT[K]] = TTTT[K]
				continue

				
				
		# print T 
		# print ''
		# print ''
		# print ''
		# print ''
		# print TT
		# print ''
		# print ''
		# print ''
		# print ''
		# print TTT 
		# print ''
		# print ''
		# print ''
		# print TTTT 
		# print ''
		# print ''
		# print ''
		# print ST 
		# print ''
		# print ''
		# print ''
		# print DT
		if SRCB != IPNetwork('0.0.0.0/0'):
			for i in ST.keys():
				if '-' in i:
					if SRCB in IPRange(i.split('-')[0],i.split('-')[1]):
						print i, ST[i]
				else:
					if SRCB in IPNetwork(i):
						print i, ST[i]
		if DSTB != IPNetwork('0.0.0.0/0'):
			for i in DT.keys():
				if '-' in i:
					if DSTB in IPRange(i.split('-')[0],i.split('-')[1]):
						print i ,DT[i]			
				else:
					if DSTB in IPNetwork(i):
						print i ,DT[i]
		if SRCA != IPNetwork('0.0.0.0/0'):
			for i in ST.keys():
				if '-' in i:
					if SRCA in IPRange(ST[i].split('-')[0],ST[i].split('-')[1]):
						print i, ST[i]			
				else:
					if SRCA in IPNetwork(ST[i]):
						print i, ST[i]
		if DSTA != IPNetwork('0.0.0.0/0'):
			for i in DT.keys():
				if '-' in i:
					if DSTA in IPRange(DT[i].split('-')[0],DT[i].split('-')[1]):
						print i, DT[i]
				else:
					
					if DSTA in IPNetwork(DT[i]):
						print i, DT[i]
		# if SRCB != IPNetwork('0.0.0.0/0') or DSTB != IPNetwork('0.0.0.0/0'):
		############ Source  ##################
	
		############ Destination  #############

		
		# if SRCA != IPNetwork('0.0.0.0/0'):
		
		
		
		
		
		# if DSTA != IPNetwork('0.0.0.0/0'):
		
		
		
	
				# print i

# a = GetF5('aaa')
# a.NATF5()
# connection = connect2.ConnectTo('10.74.224.8',)				
# a  = GetForti(connection)
# print a.AddINForti('VAS', IPNetwork('10.71.97.156/31' ) , '"IVAS_SRV_IN"')
