import sys
import logging
from PySide import QtCore, QtGui 
from PySide.QtCore import QThread, SIGNAL
import gui_3rd_test1
from netaddr import *
import pprint
import re , os
from  get2 import GetForti,GetSRX,GetF5
import time
import datetime
import connect2

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

def SRCs(SRCs):
	### N = 1 ;  SRC={} ; 
	SRCIPList={}
	for IPsss in SRCs:
		for IPss in IPsss.split():
			for IPs in IPss.split(','):
				B=[]
				if 'any' == IPs.lower() or 'all' == IPs.lower() or '0.0.0.0' == IPs:
					SRCIPList = {IPNetwork('0.0.0.0/0') : 'all'}
					continue
				### Get IP from Name ###	
				if '-' in IPs:
					if re.search(r"[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?-[1-2]?[0-9]?[0-9]?",IPs):
						C = re.findall(r"[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?-[1-2]?[0-9]?[0-9]?", IPs)
						C2 = re.findall( r"[1-2]?[0-9]?[0-9]?-" , C[0])[0]
						C2 = C[0].replace(C2,'')
						if re.search(r"[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?-[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?",IPs):
							C = re.findall(r"[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?-[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?", IPs)
							C2 = re.findall(r"[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?$", C[0])[0]
					else:
						print( ' Wrong Entry!!!'    )
						continue
					C1 = re.findall(r"^[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?", C[0])[0]
					C = IPRange(C1,C2)
					SRCIPList[C] = IPs
					continue
				else:
					B = re.findall(r"[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\/?[1-3]?[0-9]?", IPs)
					if B == []:
						print(  ' Wrong Entry-1!!!'    )
						continue
					try:
						SRCIPList[IPNetwork(B[0])] = IPs
						continue
					except  (AddrFormatError,ValueError):
						print(  ' Wrong Entry-2!!!'   )
						continue
	return SRCIPList


def SRVs2(SRVs):
	PredefinedSerList = ['ssh','telnet','ftp','snmp','ping','traceroute','http','https','dns','RDP','ntp','any','syslog','smtp','sftp','rdp']	
	ServiceTCPs = [] ; ServiceUDPs = [] ; ServiceSCTPs = [] ; ServicePreds = []
	for sss in SRVs:
		for ss in sss.split():
			for s in ss.split(','):	
				if s == '':
					continue
				if 'udp' in s.lower():
					ServiceUDP = s.lower().replace('"', '').replace('-udp', '').replace('_udp','').replace("udp", "")
					if '-' in ServiceUDP:
						if len(re.findall(r"^\d+", ServiceUDP)) > 0 and len(re.findall(r"\d+$", ServiceUDP)) > 0:
							B1 = re.findall(r"^\d+", ServiceUDP)[0].replace('-', '')
							B2 = re.findall(r"\d+$", ServiceUDP)[0].replace('-', '')
							### B3 = range(int(B1),int(B2))
							if int(B2) < int(B1) or int(B1) > 65535 or int(B2) > 65535:
								print 'Can\'t detect the service from : '   + s + "     ==> Hint: Use the '-' in the Range only"
								continue
						else:
							print 'Can\'t detect the service from : ' + s + "     ==> Hint: Use the '-' in the Range only"
							continue

						ServiceUDPs.append(ServiceUDP)
						continue
					elif not ServiceUDP.isdigit():
						print 'Can\'t detect the service from : ' + s + "     ==> Hint: Port No. Should be Integer"
						continue					
					elif int(ServiceUDP) > 65535:
						print 'Can\'t detect the service from : ' + s + "     ==> Hint: The Max port No. is 65535"
						continue
					
					ServiceUDPs.append(ServiceUDP)
					continue
					
				if 'sctp' in s.lower():
					ServiceSCTP = s.lower().replace('"', '').replace('-sctp', '').replace('_sctp','').replace("sctp", "")
					if '-' in ServiceSCTP:
						if len(re.findall(r"^\d+", ServiceSCTP)) > 0 and len(re.findall(r"\d+$", ServiceSCTP)) > 0:
							B1 = re.findall(r"^\d+", ServiceSCTP)[0].replace('-', '')
							B2 = re.findall(r"\d+$", ServiceSCTP)[0].replace('-', '')
							### B3 = range(int(B1),int(B2))
							if int(B2) < int(B1) or int(B1) > 65535 or int(B2) > 65535:
								print 'Can\'t detect the service from : '   + s + "     ==> Hint: Use the '-' in the Range only"
								continue
						else:
							print 'Can\'t detect the service from : ' + s + "     ==> Hint: Use the '-' in the Range only"
							continue
 
						ServiceSCTPs.append(ServiceSCTP)
						continue
					elif not ServiceSCTP.isdigit():
						print 'Can\'t detect the service from : ' + s + "     ==> Hint: Port No. Should be Integer"
						continue					
					elif int(ServiceSCTP) > 65535:
						print 'Can\'t detect the service from : ' + s + "     ==> Hint: The Max port No. is 65535"
						continue
					
					ServiceSCTPs.append(ServiceSCTP)
					continue
					
				elif s.lower() in PredefinedSerList:
					ServicePreds.append(s.upper())
					continue

				else: 		### TCP Services
					ServiceTCP = s.lower().replace('"', '').replace('-tcp', '').replace('_tcp','').replace("tcp", "")
					if '-' in ServiceTCP:
						if len(re.findall(r"^\d+", ServiceTCP)) > 0 and len(re.findall(r"\d+$", ServiceTCP)) > 0:
							B1 = re.findall(r"^\d+", ServiceTCP)[0].replace('-', '')
							B2 = re.findall(r"\d+$", ServiceTCP)[0].replace('-', '')
							### B3 = range(int(B1),int(B2))
							if int(B2) < int(B1) or int(B1) > 65535 or int(B2) > 65535:
								print 'Can\'t detect the service from : '   + s + "     ==> Hint: Use the '-' in the Range only"
								continue
						else:
							print 'Can\'t detect the service from : ' + s + "     ==> Hint: Use the '-' in the Range only"
							continue

						ServiceTCPs.append(ServiceTCP)
						continue
					elif not ServiceTCP.isdigit():
						print 'Can\'t detect the service from : ' + s + "     ==> Hint: Port No. Should be Integer"
						continue					
					elif int(ServiceTCP) > 65535:
						print 'Can\'t detect the service from : ' + s + "     ==> Hint: The Max port No. is 65535"
						continue
					
					ServiceTCPs.append(ServiceTCP)
					
			#### remove the duplicate values and sort them ###		
	ServiceTCPs = sorted(list(set(ServiceTCPs)))
	ServiceUDPs = sorted(list(set(ServiceUDPs)))
	ServiceSCTPs= sorted(list(set(ServiceSCTPs)))
	ServicePreds= list(set(ServicePreds))
	
	
	return ServiceTCPs, ServiceUDPs, ServiceSCTPs, ServicePreds

	
class MyApp(QtGui.QMainWindow, gui_3rd_test1.Ui_MainWindow):
	
	def __init__(self):
		super(self.__class__, self).__init__()
		self.setupUi(self)	
		self.usr = '' ; self.pwd =''; self.FWIP = '' ; self.FWType = ''
		self.N = 0
		
		LOG_FORMAT = '%(asctime)s [%(levelname)s] %(filename)s:%(lineno)d : %(message)s'
		logging.basicConfig(filename='Logs.log', format =LOG_FORMAT, level=logging.DEBUG)
		
		print datetime.datetime.now().strftime("The Script run at: %d/%m/%Y-%H:%M:%S")
		logging.debug(datetime.datetime.now().strftime("The Script run at: %d/%m/%Y-%H:%M:%S"))
		
		self.FilesLocation = os.path.dirname(os.path.realpath(sys.argv[0]))
		try:
			file = open(self.FilesLocation + "\\" + "FWList.csv", "r")
			for ii, i in enumerate(file.readlines()):
				self.FWList.addItem("")
				self.FWList.setItemText(ii, QtGui.QApplication.translate("MainWindow", "%s_%s" %(i.split(',')[1], i.split(',')[2]), None, QtGui.QApplication.UnicodeUTF8))
			file.close()
			self.FWList.addItem("")
			self.FWList.setItemText(ii+1, QtGui.QApplication.translate("MainWindow", "All_FW" , None, QtGui.QApplication.UnicodeUTF8))
			self.FWList.addItem("")
			self.FWList.setItemText(ii+2, QtGui.QApplication.translate("MainWindow", "All_Forti_FW" , None, QtGui.QApplication.UnicodeUTF8))
			self.FWList.addItem("")
			self.FWList.setItemText(ii+3, QtGui.QApplication.translate("MainWindow", "All_SRX_FW" , None, QtGui.QApplication.UnicodeUTF8))
		except Exception , MSG:
			print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : ") + str(MSG)
			logging.error(str(MSG))
			
		self.FWList.currentIndexChanged.connect(self.Get_Login_Data)
		self.FWList.currentIndexChanged.connect(connect2.ClearCashingCommand)
		self.FWList.currentIndexChanged.connect(self.DisplayVDOM)
		
		self.Pass.setEchoMode (QtGui.QLineEdit.Password)   ### Display the password as ****
		self.Vdoms.currentIndexChanged.connect(connect2.ClearCashingCommand)

		self.Get_Vdom.clicked.connect(self.DisplayVDOM)
		self.Diagnose.clicked.connect(self.diag)

		self.Run.clicked.connect(self.NATing)
		self.Run.clicked.connect(self.Poli)
		self.Apply.clicked.connect(self.App)
		
		self.address_cleanup.clicked.connect(self.address_cleanup1)
		self.Unused_addresses_cleanup.clicked.connect(self.CleanUnusedAddresses1)
		
		self.Policy_cleanup.clicked.connect(self.CleanPoliciesSRX1)


		self.actionClear_Cash_Command.triggered.connect(connect2.ClearCashingCommand)
		self.actionAdd_New_Firewall.triggered.connect(self.Add_New_Firewall)
		self.actionOpen.triggered.connect(self.Add_New_Firewall)

		self.actionExit.triggered.connect(self.Add_New_Firewall)

		self.Merge_1.clicked.connect(lambda: self.Merge(SRCs(self.src.toPlainText().split('\n')) , self.src))
		self.Merge_2.clicked.connect(lambda: self.Merge(SRCs(self.dst.toPlainText().split('\n')) , self.dst))
		self.Sort_1.clicked.connect(lambda: self.Sort(SRCs(self.src.toPlainText().split('\n')) , self.src))
		self.Sort_2.clicked.connect(lambda: self.Sort(SRCs(self.dst.toPlainText().split('\n')) , self.dst))
		self.Range_1.clicked.connect(lambda: self.Range(SRCs(self.src.toPlainText().split('\n')) , self.src))
		self.Range_2.clicked.connect(lambda: self.Range(SRCs(self.dst.toPlainText().split('\n')) , self.dst))

		self.SRVSort.clicked.connect(lambda: self.SRVSort_1(SRVs2(self.srv.toPlainText().split('\n')) , self.srv))
		self.FO.setCheckState(QtCore.Qt.Checked)

		#if self.FO.isChecked():

	def Get_Login_Data(self):
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Get Username, Password, FW IP and FW Type")
		logging.info("Get Username, Password, FW IP and FW Type")
		
		self.connection = None
		
		if self.FO.isChecked():		### Check FO username
			self.usr = ''
			self.pwd = ''
		else:						### Use the Username and password
			self.usr = self.Username.text()
			self.pwd = self.Pass.text()


		FW = self.FWList.currentText()

		if self.usr == '' or self.pwd == '' or  FW == '':    ### confirm the username and password given
			self.Output.append('No Username, Password or Firewall Not Selected')
			datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : No Username, Password or Firewall Not Selected")
			self.usr = '' ; self.pwd =''; self.FWIP = '' ; self.FWType = ''
			return
		if FW == 'All_FW' or FW == 'All_Forti_FW' or FW == 'All_SRX_FW':
			self.FWIP = FW ; self.FWType = ''
			return
		try:				### Get the IP
			self.FWIP = re.findall(r"[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?", FW)[0]
		except:
			print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Check FW IP at FWList.csv")
			logging.error("Check FW IP at FWList.csv")
			self.usr = '' ; self.pwd =''; self.FWIP = '' ; self.FWType = ''

		if self.FWIP == '':
			return
		try:				### Get FW Type ###
			f = open(self.FilesLocation + "\\" + 'FWList.csv','r')
			lines = f.readlines()
			f.close()
			for line in lines:
				if self.FWIP in line:
					self.FWType = line.split(',')[3]

			if self.N != 0 :
				if self.connection != None:
					self.connection.close()
			self.N = self.N + 1



			################  Compare the current Data with the expire date ################
			ExpectedDate = "2019-10-15 00:00"   ### DD/MM/YYYY
			ExpectedDate = datetime.datetime.strptime(ExpectedDate, "%Y-%m-%d %H:%M")
			
			CurrentDate = datetime.datetime.now()
			
			if CurrentDate > ExpectedDate:
				### app.quit()
				return
				
			################  ################ ################ ################ ################
			
			self.connection = connect2.ConnectTo(self.FWIP,self.usr,self.pwd,self.Use_Backup.isChecked())

			if self.connection == None:
				return
			################  Compare the Device Data with the expire date ################
			if self.FWType == 'Juniper_SRX':
				AAA = connect2.SendCommand(self.connection,'show system uptime')
				for ii, i in enumerate(AAA):
					if 'Current time:' in i:
						DeviceData = i.split()[2] + " " "00:00" 
						DeviceData = datetime.datetime.strptime(DeviceData, "%Y-%m-%d %H:%M")

						if DeviceData > ExpectedDate:
							connect2.Closed(self.connection)
							print("Date missed")
							return

			if self.FWType == 'Fortigate':	
				AAA = connect2.SendCommand(self.connection,'config global\nget system status\n')	
				for ii, i in enumerate(AAA):
					if 'System time:' in i:
						### if i.split()[3] == 'Feb' or i.split()[3] == 'Jan' or i.split()[3] == 'Jun':
						if i.split()[3] == i.split()[3]:
							if i.split()[6] == '2019':
								continue
						else:
							connect2.Closed(self.connection)
							print("Date missed")
							return
						
		except IOError , MSG:
			print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : ") + str(MSG)
			logging.debug(str(MSG))
			self.usr = '' ; self.pwd =''; self.FWIP = '' ; self.FWType = ''


	def DisplayVDOM(self):

		if self.FWType == '':      ### if All_FW Selected
			self.Vdoms.clear()
			self.Vdoms.addItem("")
			self.Vdoms.addItem("")
			self.Vdoms.setItemText(1, QtGui.QApplication.translate("MainWindow", "ALL_VDOMs" , None, QtGui.QApplication.UnicodeUTF8))
			self.Vdoms.update()
			return
			
		if self.connection == None:
			return

		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Connected to : ") + self.FWIP
		if self.FWType == 'Fortigate':
			print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Get Firewall VDOMs")
			logging.info("Get Firewall VDOMs")
			
			Geta = GetForti(self.connection)
			Vdoms = Geta.VdomsForti()
			Vdoms.append('ALL_VDOMs')
			self.Vdoms.clear()
			self.Vdoms.addItems(Vdoms)
			self.Vdoms.update()
		elif self.FWType == 'Juniper_SRX':
			print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Get Firewall RIs")
			logging.info(" Get Firewall RIs")
			Geti = GetSRX(self.connection)
			LSs = Geti.LSSRX()
			LSs.append('ALL_LSs')
			self.Vdoms.clear()
			self.Vdoms.addItems(LSs)
			self.Vdoms.update()
		elif self.FWType == 'F5':
			print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Get Firewall RDs")
			logging.info("Get Firewall RDs")
			Getj = GetF5(self.connection)
			RDs = [ k + ': ' + v for k, v in Getj.RDsF5().items() ]
			RDs.append('ALL_RDs')
			self.Vdoms.clear()
			self.Vdoms.addItems(RDs)
			self.Vdoms.update()

	def address_cleanup1(self):
		if self.connection == None:
			return

		if   self.FWType == 'Fortigate':
			return
			
		elif self.FWType == 'Juniper_SRX':
			LS = self.Vdoms.currentText()

			Geth = GetSRX(self.connection)
			if LS == 'ALL_LSs' :
				LSs = [self.Vdoms.itemText(i) for i in range(self.Vdoms.count())]
				for LS in LSs:
					if LS == 'ALL_LSs':
						continue
					self.Output.append(LS)
					Geth.CleanAddresses(LS)

			else:
				Geth.CleanAddresses(LS)

				
	def CleanUnusedAddresses1(self):
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S]: Unused Addresses Cleanup Started")	
		logging.info("Unused Addresses Cleanup Started")	
		
		if self.connection == None:
			return

		if   self.FWType == 'Fortigate':
			return
			
		elif self.FWType == 'Juniper_SRX':
			LS = self.Vdoms.currentText()

			Geth = GetSRX(self.connection)
			if LS == 'ALL_LSs' :
				LSs = [self.Vdoms.itemText(i) for i in range(self.Vdoms.count())]
				for LS in LSs:
					if LS == 'ALL_LSs':
						continue
					self.Output.append(LS)
					Geth.CleanUnusedAddresses(LS)

			else:
				Geth.CleanUnusedAddresses(LS)
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S]: Unused Addresses Cleanup Finished")	
		logging.info("Unused Addresses Cleanup Finished")	
				
	def NAT_cleanup1(self):
		if self.connection == None:
			return

		if   self.FWType == 'Fortigate':
			return
			
		elif self.FWType == 'Juniper_SRX':
			LS = self.Vdoms.currentText()

			Geth = GetSRX(self.connection)
			if LS == 'ALL_LSs' :
				LSs = [self.Vdoms.itemText(i) for i in range(self.Vdoms.count())]

				for LS in LSs:
					if LS == 'ALL_LSs':
						continue
					self.Output.append(LS)
					Geth.NAT_cleanup(LS)

			else:
				Geth.NAT_cleanup(LS)
				
	def CleanPoliciesSRX1(self):
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Policy Cleanup Started")
		logging.info("Policy Cleanup Started")

		if self.connection == None:
			return

		if   self.FWType == 'Fortigate':
			return
		
		
		elif self.FWType == 'Juniper_SRX':
			LS = self.Vdoms.currentText()

			Geth = GetSRX(self.connection)
			if LS == 'ALL_LSs' :
				LSs = [self.Vdoms.itemText(i) for i in range(self.Vdoms.count())]

				for LS in LSs:
					if LS == 'ALL_LSs':
						continue
					print "Logical System: " +  LS
					self.Output.append(LS)
					Geth.CleanPoliciesSRX(LS)

			else:
				print "Logical System: " +  LS
				Geth.CleanPoliciesSRX(LS)				
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S]: Policy Cleanup Finished")	
		logging.info("Policy Cleanup Finished")
		
		
	def diag(self):					#### Start new Thread
		if self.Vdoms.currentText() == 'ALL_VDOMs':
			print 'Select Valid Vdom.'
			return
		SRCIPList = SRCs(self.src.toPlainText().split('\n'))
		DSTIPList = SRCs(self.dst.toPlainText().split('\n'))
		if len(SRCIPList.keys()) == 0:
			print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Error : Source IP is Mandatory.")
			logging.error("Source IP is Mandatory.")
			return

		elif type(SRCIPList.keys()[0]) == IPRange:
			print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Error : IP Range Not supported.")
			logging.error("IP Range Not supported")
			return
		else:
			s = 'net ' + str(SRCIPList.keys()[0])

		if len(DSTIPList.keys()) == 0:
			d = ''
		elif type(DSTIPList.keys()[0]) == IPRange:
			print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Error : IP Range Not supported.")
			logging.error("IP Range Not supported")
			return
		else:
			d = 'and net ' + str(DSTIPList.keys()[0])
			
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Connected to : ") + self.FWIP
		logging.error("Connected to : " + self.FWIP)
		

		self.get_thread = Diagnose(self.connection, self.Output, self.Vdoms, s, d, self.srv,  self.FWType)
		self.connect(self.get_thread, SIGNAL("finished()"), self.done_diag)

		self.get_thread.start()
		self.Diagnose_Stop.clicked.connect(self.get_thread.terminate)
		
		self.Diagnose.setEnabled(False)

	def done_diag(self):			#### End of the Thread
		# self.btn_stop.setEnabled(False)
		# self.btn_start.setEnabled(True)
		# self.progress_bar.setValue(0)
		# QtGui.QMessageBox.information(self, "Done!", "Diagnose Done!")
		
		self.Diagnose.setEnabled(True)
		
		self.connection.close()
		print 'Disconnected_1'
	def done_poli(self):			#### End of the Thread

		self.Run.setEnabled(True)

	def Poli(self):

		if  self.NAT.isChecked():
			return


		if  self.checkBox.isChecked():   ### QCheck checkbox
			Geth = GetSRX(self.connection)
			LS = self.Vdoms.currentText()

			SRCIPList = SRCs(self.src.toPlainText().split('\n')).values()
			DSTIPList = SRCs(self.dst.toPlainText().split('\n')).values()

			for i in SRCIPList:
				for j in DSTIPList:
					Geth.QuickPolicyCheck(LS,i, j)
			return

		if self.Vdoms.currentText() == 'ALL_VDOMs':
			print 'Select Valid Vdom.'
		self.get_thread2 = Policy(self.connection,self.FWType , self.Output, self.Vdoms, self.src, self.dst, self.srv, self.Check, self.Include_Any, self.Policy_Name)
		self.connect(self.get_thread2, SIGNAL("finished()"), self.done_poli)
		self.get_thread2.start()
		self.Diagnose_Stop.clicked.connect(self.get_thread2.terminate)
		self.Run.setEnabled(False)		
	def App(self):
		FWLi = []
		
		if self.FWType == '':
			try:
				f = open(self.FilesLocation + "\\" + 'FWList.csv','r')
				for line in f.readlines():
					if self.FWIP == 'All_Forti_FW' and 'Fortigate' in line:
						FWLi.append(line.split(',')[2])
						self.FWType = 'Fortigate'
						continue
					elif self.FWIP == 'All_SRX_FW' and 'Juniper_SRX' in line:
						FWLi.append(line.split(',')[2])
						self.FWType = 'Juniper_SRX'
						continue
				f.close()
			except IOError , MSG:
				print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : ") + str(MSG)
				return
		if FWLi == []:
			FWLi.append(self.FWIP)
		
		self.get_thread3 = Appl(self.usr ,self.pwd , FWLi , self.FWType , self.Output, self.Vdoms)
		self.connect(self.get_thread3, SIGNAL("finished()"), self.done_App)
		self.get_thread3.start()
		self.Diagnose_Stop.clicked.connect(self.get_thread3.terminate)
		self.Apply.setEnabled(False)
		
	def done_App(self):			#### End of the Thread
		self.Apply.setEnabled(True)


	def Add_New_Firewall(self):
		self.window2 = AddFW()
		self.window2.show()
	def Merge(self,IPList , srcdst):
		IPList2 = {} ; MIPs = []
		for X in IPList.keys():
			if type(X) == IPNetwork:
				MIPs.append(X)
			else:
				IPList2[X] = IPList[X]
		MIPs = sorted(cidr_merge(MIPs))
		for MIP in MIPs:
			if MIP not in IPList.keys():
				IPList2[MIP] = str(MIP)
				for i in IPList.keys():
					if MIP.network in i:
						IPList2[MIP] = IPList[i].replace(str(i.prefixlen), str(MIP.prefixlen))
			else:
				IPList2[MIP] = IPList[MIP]
		IPList = IPList2
		srcdst.clear()
		for IP in sorted(IPList.keys()):
			srcdst.appendPlainText(IPList[IP])
	def Range(self,IPList , srcdst):
		C = []
		for i in IPList.keys():
			if type(i) == IPNetwork and str(i.netmask) == '255.255.255.255':
				C.append(i)
		C.append(IPNetwork('255.255.255.255'))		
		C = sorted(C)
		T = C[0].network
		B = C[0]	### begin
		Z = C[0]	### end
		for i in range(1,len(C)):
			if C[i].network == T + 1:
				Z = C[i]
				del IPList[C[i]]
				T = T + 1
				continue
			if B != Z:
				IPList[IPRange(B,Z)] = IPList[B] + '-' + str(Z.network).replace(re.findall(r"[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.", str(B))[0],'')
				del IPList[B]
				T = C[i].network
				B = C[i]
				Z = C[i]
			else:
				T = C[i].network
				B = C[i]
				Z = C[i]

		srcdst.clear()
		for IP in sorted(IPList.keys()):
			srcdst.appendPlainText(IPList[IP])
	def Sort(self,IPList , srcdst):
		srcdst.clear()
		for IP in sorted(IPList.keys()):
			srcdst.appendPlainText(IPList[IP])
	def SRVSort_1(self,ServicesLists , srves):
		srves.clear()
		Services = ''
		### print ServicesLists
		for TCPService in ServicesLists[0]:  ##( For TCP)
			Services = Services + TCPService + '_TCP\n'
		for UDPService in ServicesLists[1]:  ##( For UDP)
			Services = Services + UDPService + '_UDP\n'
		for SCTPService in ServicesLists[2]:  ##( For SCTP)
			Services = Services + SCTPService + '_SCTP\n'
		for PredService in ServicesLists[3]:  ##( For Predefined)
			Services = Services + PredService + '\n'

		srves.appendPlainText(Services)
	
		
	def NATing(self):
		if self.connection == None:
			return

		if self.NAT.isChecked() == False:
			return
		if '-' in self.src.toPlainText():
			B1 = re.findall(r"[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\/?[1-3]?[0-9]?", self.src.toPlainText().split('-')[0])
			B2 = re.findall(r"[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\/?[1-3]?[0-9]?", self.src.toPlainText().split('-')[1])
		else:
			B1 = []	; B2 = []
		if '-' in self.dst.toPlainText():
			B3 = re.findall(r"[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\/?[1-3]?[0-9]?", self.dst.toPlainText().split('-')[0])
			B4 = re.findall(r"[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\.[1-2]?[0-9]?[0-9]?\/?[1-3]?[0-9]?", self.dst.toPlainText().split('-')[1])
		else:
			B3 = [] ; B4 = []
		if B1 == []:
			SRCB = IPNetwork('0.0.0.0/0')
		else:
			try:
				SRCB = IPNetwork(B1[0])
			except  (AddrFormatError,ValueError):
				print(  ' Wrong IP'   )
				SRCB = IPNetwork('0.0.0.0/0')
		if B2 == []:
			DSTB = IPNetwork('0.0.0.0/0')
		else:
			try:
				DSTB = IPNetwork(B2[0])
			except  (AddrFormatError,ValueError):
				print(  ' Wrong IP'   )
				DSTB = IPNetwork('0.0.0.0/0')
		if B3 == []:
			SRCA = IPNetwork('0.0.0.0/0')
		else:
			try:
				SRCA = IPNetwork(B3[0])
			except  (AddrFormatError,ValueError):
				print ' Wrong IP'
				SRCA = IPNetwork('0.0.0.0/0')
		if B4 == []:
			DSTA = IPNetwork('0.0.0.0/0')
		else:
			try:
				DSTA = IPNetwork(B4[0])
			except  (AddrFormatError,ValueError):
				print(  ' Wrong IP'   )
				DSTA = IPNetwork('0.0.0.0/0')				


		print  SRCB,DSTB,SRCA,DSTA

		if self.FWType == 'Juniper_SRX':
			print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Connected to : ") + self.FWIP

			Geth = GetSRX(self.connection)
			Geth.NATSRX(SRCB,DSTB,SRCA,DSTA)
			print  SRCB,DSTB,SRCA,DSTA

		if self.FWType == 'F5':

			Geth = GetF5(connection)
			Geth.NATF5(SRCB,DSTB,SRCA,DSTA)
			print  SRCB,DSTB,SRCA,DSTA

class Diagnose(QThread):
	def __init__(self,connection,  Output , Vdoms , s , d , srv , FWType):
		QThread.__init__(self)
		self.Output       = Output  
		self.connection = connection
		self.Vdoms        = Vdoms  
		self.s            = s 
		self.d            = d  
		self.srv          = srv  
		self.FWType       = FWType
		
	def __del__(self):
		self.wait()

	def run(self):
		if self.FWType == 'Fortigate':
			Vdom = self.Vdoms.currentText()

			# SerT,SerU,SerS = SRVs(self.srv.toPlainText().split('\n'))
			# SS , SA = Get.ServForti(self.connection, Vdom,SerT, SerU, SerS)
			stdin, stdout, stderr =  self.connection.exec_command('config vdom\nedit %s\ndiagnose sniffer packet any "%s  %s" 4 100' %(Vdom, self.s, self.d) , get_pty=True)
			for ii, line in enumerate(iter(stdout.readline, "")):
				print ii , line.replace('\n','')

			self.connection.close()
		elif self.FWType == 'Juniper_SRX':
			return   ####  <<<-->>>
			LS = self.Vdoms.currentText()	
			SRCIPList = SRCs(self.src.toPlainText().split('\n'))
			DSTIPList = SRCs(self.dst.toPlainText().split('\n'))

			### SRCIPList = SRCs(['10.78.60.16'])
			### DSTIPList = SRCs(['10.78.65.2'])

			SerT,SerU,SerS,Pred = SRVs2(self.srv.toPlainText().split('\n'))
			SS , SA = Get.ServSRX(self.connection, LS,SerT, SerU, SerS,Pred)

			AddSRXPolicy(self.FWIP, LS ,self.connection,SRCIPList,DSTIPList,SS,SA,self.Check.isChecked(),self.Include_Any.isChecked(),self.Output,self.Policy_Name.text())
		elif self.FWType == 'F5':
			stdin, stdout, stderr =  self.connection.exec_command('tcpdump -nnei 0.0:nnn -s0 -S -c 100 %s  %s' %(self.s, self.d) , get_pty=True)
			
			for ii, line in enumerate(iter(stdout.readline, "")):
				if 'verbose output suppressed' in line or 'capture size' in line or 'packets captured' in line or 'packets received' in line or 'dropped by kernel' in line:
					print ii , line.replace('\n','')
				else:
					print ii, line.replace('\n','').replace(re.findall(r"flowt.*localport=\d*",line)[0],'')

class Policy(QThread):
	def __init__(self, connection,FWType, Output , Vdoms , src , dst , srv , Check , Include_Any , Policy_Name):
		QThread.__init__(self)
		self.FWType		= FWType
		self.connection	 = connection
		self.Output       = Output  
		self.Vdoms        = Vdoms  
		self.src          = src 
		self.dst          = dst  
		self.srv          = srv  
		self.Check        = Check  
		self.Include_Any  = Include_Any
		self.Policy_Name  = Policy_Name
		

	def __del__(self):
		self.wait()
	
	def run(self):			
		SRCIPList = SRCs(self.src.toPlainText().split('\n'))
		DSTIPList = SRCs(self.dst.toPlainText().split('\n'))
		### SRCIPList = {IPNetwork('192.168.63.1'): u'10.1.132.1'}
		### DSTIPList = {IPNetwork('10.1.132.1'): u'10.1.132.1'}


		if self.FWType == 'Fortigate':
			Vdom = self.Vdoms.currentText()
			if self.Check.isChecked():
					self.FindFortiPolicy(self.connection,Vdom,SRCIPList,DSTIPList,self.Include_Any.isChecked())
			self.AddFortiPolicy(self.connection,Vdom, SRCIPList,DSTIPList)   ### Printing ###

		elif self.FWType == 'Juniper_SRX':
			LS = self.Vdoms.currentText()
			
			SerT,SerU,SerS,Pred = SRVs2(self.srv.toPlainText().split('\n'))
			Getc = GetSRX(self.connection)
			if LS == 'ALL_LSs' :
				LSs = [self.Vdoms.itemText(i) for i in range(self.Vdoms.count())]
				for LS in LSs:
					self.Output.append(LS)
					SS , SA = Getc.ServSRX( LS ,SerT, SerU, SerS,Pred)
					self.AddSRXPolicy(self.connection,LS,SRCIPList,DSTIPList,SS,SA,self.Check.isChecked(),self.Include_Any.isChecked(),self.Policy_Name.text())
			else:
				SS , SA = Getc.ServSRX( LS ,SerT, SerU, SerS,Pred)
				self.AddSRXPolicy(self.connection,LS,SRCIPList,DSTIPList,SS,SA,self.Check.isChecked(),self.Include_Any.isChecked(),self.Policy_Name.text())

		elif self.FWType == 'F5':
			print 'Under Maint.'
			self.connection.close()
			return

	def AddFortiPolicy(self,connection, Vdom,SRCIPList,DSTIPList):
		SRC = {} ; DST = {} ; T1 = {} ; T2 = {}
		Getd = GetForti(connection)
		SerT,SerU,SerS,Prod = SRVs2(self.srv.toPlainText().split('\n'))
		SS , SA = Getd.ServForti(Vdom,SerT, SerU, SerS,Prod)
		
		for IP in SRCIPList.keys():
			if '@' in SRCIPList[IP]:
				self.Output.append('config router static')
				NIntf = re.findall(r"@\S*$", SRCIPList[IP])[0].replace('@','')
				NT , pt, intf, zn , NH = Getd.RouteForti(Vdom,IP)
				if NIntf == intf:   ### Check if the new interface is follow the routing table
					SRC[IP] = [NT, pt,intf,zn, NH]
				else:
					AAA = connect2.SendCommand(connection,'config vdom\n\redit %s\n\rshow router static | grep -f  %s' %(Vdom, NIntf))
					
					for ii, i in enumerate(AAA):
						if 'set device "' + NIntf + '"' in i:
							if 'gateway' in AAA[ii-2]:
								self.Output.append('edit 0')
								time.sleep(.06)
								self.Output.append('set dst %s' %(IP) )
								time.sleep(.06)
								self.Output.append('set gateway %s' %(AAA[ii-2].split()[2]))
								time.sleep(.06)
								self.Output.append('set device %s' %((AAA[ii].split()[2])))
								time.sleep(.06)
								self.Output.append('next' )
								break
							if 'gateway' in AAA[ii-1]:
								self.Output.append('edit 0' )
								time.sleep(.06)
								self.Output.append('set dst %s' %(IP))
								time.sleep(.06)
								self.Output.append('set gateway %s' %(AAA[ii-1].split()[2]))
								time.sleep(.06)
								self.Output.append('set device %s' %((AAA[ii].split()[2])))
								time.sleep(.06)
								self.Output.append('next' )
								break
					SRC[IP] = [str(IP) ,'static', NIntf, Getd.ZoneForti(Vdom,NIntf), '']
			else:
				SRC[IP] = Getd.RouteForti(Vdom,IP)
	### SRC = {IPNetwork('3.3.3.3'): ['Network', 'routing protocol', u'routing interface', u'routing Zone' , 'NH']}

		for IP in DSTIPList.keys():
			if '@' in DSTIPList[IP]:
				self.Output.append( 'config router static' )
				NIntf = re.findall(r"@\S*$", DSTIPList[IP])[0].replace('@','')
				NT , pt,intf,zn , NH = Getd.RouteForti(Vdom,IP)
				if NIntf == intf:   ### Check if the new interface is follow the routing table
					DST[IP] = [NT ,pt,intf,zn,NH]
				else:
					AAA = connect2.SendCommand(connection,'config vdom\n\redit %s\n\rshow router static | grep -f  %s' %(Vdom, NIntf))
					
					for ii, i in enumerate(AAA):
						if 'set device "' + NIntf + '"' in i:
							if 'gateway' in AAA[ii-2]:
								self.Output.append('edit 0')
								time.sleep(.06)
								self.Output.append('set dst %s' %(IP))
								time.sleep(.06)
								self.Output.append('set gateway %s' %(AAA[ii-2].split()[2]))
								time.sleep(.06)
								self.Output.append('set device %s' %((AAA[ii].split()[2])))
								time.sleep(.06)
								self.Output.append('next')
								break
							if 'gateway' in AAA[ii-1]:
								self.Output.append('edit 0')
								time.sleep(.06)
								self.Output.append('set dst %s' %(IP))
								time.sleep(.06)
								self.Output.append('set gateway %s' %(AAA[ii-1].split()[2]))
								time.sleep(.06)
								self.Output.append('set device %s' %((AAA[ii].split()[2])))
								time.sleep(.06)
								self.Output.append('next')
								break
					DST[IP] = [str(IP) , 'static', NIntf, Getd.ZoneForti(Vdom,NIntf) ,'']
			else:
				DST[IP] = Getd.RouteForti(Vdom,IP)  
	### DST = {IPAddress('3.3.3.3'): ['Network' , 'routing protocol', u'routing interface', u'routing Zone' , 'NH']}


		
		for i in SRC.keys():    # adding Address name, Address Zone
			if i == IPNetwork('0.0.0.0/0'):
				SRC[i].append('all')
				SRC[i].append('any')
				break
			else:
				T1[i] = Getd.AddForti(Vdom,i,SRC[i][3])
				SRC[i].append(T1[i][0]); SRC[i].append(T1[i][1])
	###  print SRC  # SRC = {IPAddress('3.3.3.3'): ['network', 'routing protocol', u'routing interface', u'routing Zone','NH, 'Address Name', 'Address Zone']}
		for i in DST.keys():    # adding Address name, Address Zone
			if i == IPNetwork('0.0.0.0/0'):
				DST[i].append('all')
				DST[i].append('any')
				break
			else:
				T2[i] = Getd.AddForti(Vdom,i,DST[i][3])
				DST[i].append(T2[i][0]); DST[i].append(T2[i][1])
	###  print DST  # DST = {IPAddress('3.3.3.3'): ['Network','routing protocol', u'routing interface', u'routing Zone', 'NH' , 'Address Name', 'Address Zone']}
		
		### connect2.Closed(connection)
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Disconnected from : ")
		
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Start Fortigate Printing")
		logging.info("Start Fortigate Printing")
		####################################################
		##################### PRINTING #####################
		####################################################
		
		self.Output.append('{0:25} {1:18} {2:15} {3:15} {4:15} {5:}'.format('\nSource IP:', 'Network' , 'Protocol' , 'Interface' , 'Zone' , 'Add Name'))
		for i in SRC.keys():
			self.Output.append('{0:25} {1:18} {2:15} {3:15} {4:15} {5:}'.format(str(i), str(SRC[i][0]) , str(SRC[i][1]) , str(SRC[i][2]) , str(SRC[i][3]) , str(SRC[i][5]))      )
			time.sleep(.06)
		self.Output.append('{0:25} {1:18} {2:15} {3:15} {4:15} {5:}'.format('\nDestination IP:', 'Network' , 'Protocol' , 'Interface' , 'Zone' , 'Add Name'))
		for i in DST.keys():
			self.Output.append('{0:25} {1:18} {2:15} {3:15} {4:15} {5:}'.format(str(i), str(DST[i][0]) , str(DST[i][1]) , str(DST[i][2]) , str(DST[i][3]) , str(DST[i][5])) )
			time.sleep(.06)
		self.Output.append('\nServices: ')
		time.sleep(.06)
		self.Output.append( '{0:25} {1:25} '.format(str(SS) , str(SA))  )
		time.sleep(.06)
		############   To Support the Empty Feilds ###############3
		if SRC == {}:
			SRC[''] = ['', '', '', '', '', '' , '']
		if DST == {}:
			DST[''] = ['', '', '', '', '', '' , '']
			
		###                     Addresses                       ###
		self.Output.append('\n\nconfig vdom\n\redit %s\n\rconfig firewall address\n\r' %(Vdom))
		time.sleep(.06)
		loop1 = 1 ; loop2 =1
		ls = SRC.keys()
		while loop1 == 1:  ### Print the missing Addresses
			NS=[] ; MS = []
			X =  SRC[ls[0]][3]   ### Zone
			for j in range(len(ls)):
				if SRC[ls[j]][3] == X:  ## Zone
					MS.append(ls[j])
				else:
					NS.append(ls[j])
			ld = DST.keys()
			while loop2 == 1:
				MD = [] ; ND = []
				Y = DST[ld[0]][3]    ### Zone
				for j in range(len(ld)):
					if DST[ld[j]][3] == Y:     ###Zone
						MD.append(ld[j])
					else:
						ND.append(ld[j])
				if X != Y:	#for x in MS
					for i in MS:    ### Add SRC Address ###
						if SRC[i][5] == 'none' and type(i) == IPNetwork:
							self.Output.append('edit %s' %(SRCIPList[i].split('@')[0]))
							time.sleep(.06)
							self.Output.append('set subnet %s' %(i))
							time.sleep(.06)
							self.Output.append('set associated-interface %s' %(SRC[i][3]))
							time.sleep(.06)
							self.Output.append('next')
							SRC[i][5] = SRCIPList[i].split('@')[0]
						if SRC[i][5] == 'none' and type(i) == IPRange:
							self.Output.append('edit %s' %(SRCIPList[i].split('@')[0]))
							time.sleep(.06)
							self.Output.append('set type iprange')
							time.sleep(.06)
							self.Output.append('set start-ip %s' %(i[0]))
							time.sleep(.06)
							self.Output.append('set end-ip %s' %(i[-1]) )
							time.sleep(.06)
							self.Output.append('set associated-interface %s' %(SRC[i][3]))
							time.sleep(.06)
							self.Output.append('next')
							SRC[i][5] = SRCIPList[i].split('@')[0]     ### Add the new address name instead of none address at SRC ###
					for i in MD:    ### Add SRC Address ###
						if DST[i][5] == 'none' and type(i) == IPNetwork:
							self.Output.append('edit %s' %(DSTIPList[i].split('@')[0]))
							time.sleep(.06)
							self.Output.append('set subnet %s' % (i))
							time.sleep(.06)
							self.Output.append('set associated-interface %s' %(DST[i][3]))
							time.sleep(.06)
							self.Output.append('next')
							DST[i][5] = DSTIPList[i].split('@')[0]
						if DST[i][5] == 'none' and type(i) == IPRange:
							self.Output.append( 'edit %s' %(DSTIPList[i].split('@')[0]))
							time.sleep(.06)
							self.Output.append( 'set type iprange')
							time.sleep(.06)
							self.Output.append( 'set start-ip %s' %(i[0]))
							time.sleep(.06)
							self.Output.append( 'set end-ip %s' %(i[-1]))
							time.sleep(.06)
							self.Output.append( 'set associated-interface %s' %(DST[i][3]))
							time.sleep(.06)
							self.Output.append( 'next' )
							DST[i][5] = DSTIPList[i].split('@')[0]     ### Add the new address name instead of none address at DST ###
				if ND != []:
					ld = ND
				else:
					break
			if NS != []:
				ls = NS
			else:
				break

		
		
		###                     Services                        ###
		self.Output.append( 'end\n\rconfig firewall service custom\n\r'    )
		for i in SA:    ### Print the missing Services
			if "TCP" in i:
				self.Output.append( 'edit %s' %(i)    )
				time.sleep(.06)
				self.Output.append( 'set tcp-portrange %s' %(i.replace('_TCP','')))
				time.sleep(.06)
				self.Output.append( 'next' )
			if "UDP" in i:
				self.Output.append('edit %s' %(i))
				time.sleep(.06)
				self.Output.append('set udp-portrange %s' %(i.replace('_UDP','')))
				time.sleep(.06)
				self.Output.append('next')
			if "SCTP" in i:
				self.Output.append( 'edit %s' %(i))
				time.sleep(.06)
				self.Output.append( 'set sctp-portrange %s' %(i.replace('_SCTP','')))
				time.sleep(.06)
				self.Output.append('next')


		###                     Policies                        ###
		self.Output.append('end\n\rconfig firewall policy\n\r')
		loop1 = 1 ; loop2 =1
		ls = SRC.keys()
		while loop1 == 1:   ### Print the Policies
			NS=[] ; MS = []
			X =  SRC[ls[0]][3]
			for j in range(len(ls)):
				if SRC[ls[j]][3] == X:   ### Zone
					MS.append(ls[j])
				else:
					NS.append(ls[j])
			ld = DST.keys()
			while loop2 == 1:
				MD = [] ; ND = []
				Y = DST[ld[0]][3]   ### Zone
				for j in range(len(ld)):
					if DST[ld[j]][3] == Y:   ### Zone
						MD.append(ld[j])
					else:
						ND.append(ld[j])
				if X != Y:
					self.Output.append( 'edit 0' )
					time.sleep(.1)
					self.Output.append( 'set srcintf %s' %(X) )
					time.sleep(.1)
					self.Output.append( 'set dstintf %s' %(Y) )
					time.sleep(.1)
					self.Output.append( 'set srcaddr %s' %(" ".join(str(SRC[x][5]) for x in MS)) )  ### Address Name
					time.sleep(.1)
					self.Output.append( 'set dstaddr %s' %(" ".join(str(DST[x][5]) for x in MD)) )
					time.sleep(.1)
					self.Output.append( 'set action accept' )
					time.sleep(.1)
					self.Output.append( 'set schedule "always"' )
					time.sleep(.1)
					self.Output.append( 'set service %s %s' %(" ".join(str(x) for x in SS) , " ".join(str(x) for x in SA))   )
					time.sleep(.1)
					self.Output.append( 'next' )
				if ND != []:
					ld = ND
				else:
					break
			if NS != []:
				ls = NS
			else:
				break
		
		self.Output.append( 'end' )
		time.sleep(.1)
		self.Output.append( '#######################################################' )
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : End Fortigate Printing")
		logging.info("End Fortigate Printing")
	def AddSRXPolicy(self,connection,LS,SRCIPList,DSTIPList,SS,SA,Check, Any,Policy_Name):
		if LS == 'root-logical-system' :
			NLS = ''
		else:
			NLS = " logical-systems " + LS

		TR = {}
		Gete = GetSRX(connection)
		for IP in SRCIPList.keys():	   ### Get the routes/Delte the wrong routes/Add the address Name

			TR[IP] = Gete.RouteSRX(LS, IP)
			TA = Gete.AddSRX(LS,IP)    ###  Return 
			for routetable in TR[IP].keys():
				if TR[IP][routetable][3] == 'fxp0.0' or TR[IP][routetable][3] == 'None':  ## If the interface is mgnt or no interface (in case of next-table)
					del TR[IP][routetable]
					continue
				TZ = Gete.ZoneSRX(TR[IP][routetable][3],LS)
				TR[IP][routetable].append(TZ[ TR[IP][routetable] [3]] [0])   ### Zone
				TR[IP][routetable].append(TZ[ TR[IP][routetable] [3]] [1])   ### RI
				if TA != None:
					for i in TA[IP].keys():
						if TR[IP][routetable][4] == i:
							TR[IP][routetable].append(TA[IP][i])
							break
				if IP == IPNetwork('0.0.0.0/0'):
					TR[IP][routetable].append('any')
				if len(TR[IP][routetable]) != 7:
					TR[IP][routetable].append('None')
				if TR[IP][routetable][5] not in routetable:
					del TR[IP][routetable]
					continue
		# print TR  {'10.74.9.0': 
								# {u'RBT-Internet.inet.0\n': 	[u'10.74.0.0/20', u'Static', u'10.78.74.9',  u'reth1.355', 'Untrust', 'RI'  ,  'Address name'], 
								# u'CH-vr.inet.0\n': 			[u'10.74.0.0/20', u'Static', u'10.78.74.9',  u'reth1.355', 'Untrust', 'RI'  ,  'Address name' ], 
								# u'inet.0\n': 					[u'0.0.0.0/0',    u'Static', u'10.74.169.1', u'fxp0.0',    'None' ,   'None' ,'Address name'}}

		TTR={}
		for IP in DSTIPList.keys():	   ### Get the routes/Add the address/zone
			TTR[IP] = Gete.RouteSRX(LS, IP)
			TTA = Gete.AddSRX( LS , IP)
			
			#print TTA
			for routetable in TTR[IP].keys():
				TTZ = Gete.ZoneSRX(TTR[IP][routetable][3],LS,)
				TTR[IP][routetable].append(TTZ[ TTR[IP][routetable] [3]] [0])
				TTR[IP][routetable].append(TTZ[ TTR[IP][routetable] [3]] [1])
				if TTA != None:
					for i in TTA[IP].keys():
						if TTR[IP][routetable][4] == i:
							TTR[IP][routetable].append(TTA[IP][i])
							break
				if IP == IPNetwork('0.0.0.0/0'):
					TTR[IP][routetable].append('any')
				if len(TTR[IP][routetable]) != 7:
					TTR[IP][routetable].append('None')

		routetables = Gete.RISRX(LS)
		### print routetables
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Start SRX Printing") 
		logging.info("Start SRX Printing")
		##################################
		########### Printing #############
		##################################
		
		for i in SA:
			if "TCP" in i:
				self.Output.append( 'set%s applications application %s protocol tcp destination-port %s' %( NLS , i,i.replace('_TCP',''))  )
				time.sleep(.06)
			if "UDP" in i:
				self.Output.append( 'set%s applications application %s protocol udp destination-port %s' %( NLS , i,i.replace('_UDP',''))   )
				time.sleep(.06)
			if "SCTP" in i:
				self.Output.append( 'set%s applications application %s protocol sctp destination-port %s' %( NLS , i,i.replace('_SCTP',''))   )
				time.sleep(.06)
		
		################## Printing Addresses And Policies ###############
		for routetable in routetables:
			loop1 = 1 ; loop2 =1 ; SSS = [] ; DDD = []
			self.Output.append(  '{0:25} {1:18} '.format('\n\nVirtual router: ' , str(routetable.split('.inet.0')[0]) )  )
			time.sleep(.06)
			for SIP in SRCIPList.keys():
				if routetable  in TR[SIP].keys():
					SSS.append(SIP)
			if len(SSS) == 0:
				continue
			for DIP in DSTIPList.keys():
				if routetable  in TTR[DIP].keys():
					DDD.append(DIP)
			if len(DDD) == 0:
				continue
			ls = SSS
			while loop1 == 1:
				MS = [] ; NS = []
				X = TR[ls[0]][routetable][4]
				for j in range(len(ls)):
					if TR[ls[j]][routetable][4] == X:
						MS.append(ls[j])
						continue
					else:
						NS.append(ls[j])
						continue
				ld = DDD
				while loop2 ==1:
					MD = [] ; ND = []
					Y = TTR[ld[0]][routetable][4]  ### Zone
					for j in range(len(ld)):
						if TTR[ld[j]][routetable][4] == Y:
							MD.append(ld[j])
							continue
						else:
							ND.append(ld[j])
							continue

					if Y != X:
						self.Output.append(    '{0:25} {1:18} {2:15} {3:15} {4:15} {5:}'.format('\nSource IP', 'Network' , 'Protocol' , 'Interface' , 'Zone' , 'Add Name'))
						for a in MS:   ### Create None IPs at TR,TTR and replace them at TR,TTR
							self.Output.append('{0:25} {1:18} {2:15} {3:15} {4:15} {5:}'.format(a , TR[a][routetable][0], TR[a][routetable][1]  ,TR[a][routetable][3], TR[a][routetable][4],  TR[a][routetable][6] ) )
							time.sleep(.06)
						self.Output.append('{0:25} {1:18} {2:15} {3:15} {4:15} {5:}'.format('\nDestination IP', 'Network' , 'Protocol' , 'Interface' , 'Zone' , 'Add Name'))
						for a in MD:
							self.Output.append('{0:25} {1:18} {2:15} {3:15} {4:15} {5:}'.format(a , TTR[a][routetable][0], TTR[a][routetable][1], TTR[a][routetable][3],TTR[a][routetable][4], TTR[a][routetable][6]) )
							time.sleep(.06)
						self.Output.append(  '\nService'    )
						time.sleep(.06)
						self.Output.append( '{0:25} {1:18}'.format(str(SS), str(SA))  )
						################################
						################################
						if Check == True:
							Policies = {}
							for IPs in MS:
								for IPd in MD:
									#Policies = Gete.PolicySRX(LS,IPs, IPd, X, Y,Any)
									Policies = dict(Policies.items() + Gete.PolicySRX(LS, IPs, IPd, X, Y,Any).items() )  

							for i in Policies.keys():
								print Policies[i]
								print
								
						#################################
						#################################

					
						for a in MS:   ### Create None IPs at TR,TTR and replace them at TR,TTR
							if TR[a][routetable][6] == 'None':
								if type(a) == IPRange:
									self.Output.append( 'set%s security zones security-zone %s address-book address %s range-address %s to %s' %(NLS, X, SRCIPList[a],a[0],a[-1])    )
								else:
									self.Output.append( 'set%s security zones security-zone %s address-book address %s %s ' %(NLS, X, SRCIPList[a],a)    )
								TR[a][routetable][6] = SRCIPList[a]
						self.Output.append( '\n'  )
						for a in MD:
							if TTR[a][routetable][6] == 'None':
								if type(a) == IPRange:
									self.Output.append( 'set%s security zones security-zone %s address-book address %s range-address %s to %s' %(NLS, Y, DSTIPList[a],a[0],a[-1])    )
								else:
									self.Output.append( 'set%s security zones security-zone %s address-book address %s %s ' %(NLS, Y, DSTIPList[a],a)   )
								TTR[a][routetable][6] = DSTIPList[a]
						if Policy_Name == '':
							Policy_Name = '<Policy_Name>'

						
						self.Output.append( '\nset%s security policies from-zone %s to-zone %s policy %s match source-address [%s]' 	%(NLS, X , Y, Policy_Name, " ".join(str(TR[x][routetable][6]) for x in MS))     )
						time.sleep(.1)
						self.Output.append( 'set%s security policies from-zone %s to-zone %s policy %s match destination-address [%s]'	%(NLS, X , Y,Policy_Name , " ".join(str(TTR[y][routetable][6]) for y in MD))    )
						time.sleep(.1)
						self.Output.append( 'set%s security policies from-zone %s to-zone %s policy %s match application [%s %s]' 		%(NLS, X , Y,Policy_Name, " ".join(str(x) for x in SS) , " ".join(str(x) for x in SA))    )
						time.sleep(.1)
						self.Output.append( 'set%s security policies from-zone %s to-zone %s policy %s then permit\n\n\n' 				%(NLS, X , Y,Policy_Name)   )

					if ND != []:
						ld = ND
					else:
						break

				if NS != []:
					ls = NS
				else:
					break	

	def FindFortiPolicy(self,connection,Vdom,SRCIPList,DSTIPList,Any):
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Checking the Access")
		logging.info("Checking the Access")
		Policies = {}
		Getf = GetForti(connection)
		for IPs in SRCIPList.keys():
			for IPd in DSTIPList.keys():
				Policies = dict(Policies.items() + Getf.PolicyForti(Vdom,IPs,IPd,Any).items())     
		for i in Policies.keys():
			print Policies[i]
			
		######  Additional Test 	####
		for IPs in SRCIPList.keys():
			for IPd in DSTIPList.keys():
				print '\n\n\n\n   Source:     ' + str(IPs)
				print '   Destination:' + str(IPd)
				
				
				T = Getf.RouteForti(Vdom,IPs)
				print "Source IP: " + str(IPs) +"   protocol: " + T[1] + "   Interface: "+ T[2] + "   Zone: " + T[3] + "   Next Hop: " + T[4]
				if T[1] == 'Connected':
					AAA = connect2.SendCommand(connection,'config vdom\n\redit %s\n\rexecute ping-options repeat-count 2\n\rexecute ping %s\n\rget sys arp | grep %s' %(Vdom,IPs.network,IPs.network))
					for iii,i in enumerate(AAA):
						if 'ping' in i or 'bytes' in i or 'packets' in i or 'round' in i:
							print i.split('/n')[0].replace('\n', '')

				if T[1] == 'static':
					AAA = connect2.SendCommand(connection,'config vdom\n\redit %s\n\rexecute ping-options repeat-count 2\n\rexecute ping %s' %(Vdom,T[4]))
					for iii,i in enumerate(AAA):
						if 'ping' in i or 'bytes' in i or 'packets' in i or 'round' in i:
							print i.split('/n')[0].replace('\n', '')

				T = Getf.RouteForti(Vdom,IPd)
				print "Source IP: " + str(IPd) +"   protocol: " + T[1] + "   Interface: "+ T[2] + "   Zone: " + T[3] + "   Next Hop: " + T[4]
				if T[1] == 'Connected':
					AAA = connect2.SendCommand(connection,'config vdom\n\redit %s\n\rexecute ping-options repeat-count 2\n\rexecute ping %s\n\rget sys arp | grep %s' %(Vdom,IPd.network,IPd.network))
					for iii,i in enumerate(AAA):
						if 'ping' in i or 'bytes' in i or 'packets' in i or 'round' in i:
							print i.split('/n')[0].replace('\n', '')

				if T[1] == 'static':
					AAA = connect2.SendCommand(connection,'config vdom\n\redit %s\n\rexecute ping-options repeat-count 2\n\rexecute ping %s' %(Vdom,T[4]))
					for iii,i in enumerate(AAA):
						if 'ping' in i or 'bytes' in i or 'packets' in i or 'round' in i:
							print i.split('/n')[0].replace('\n', '')

class Appl(QThread):
	def __init__(self,usr ,pwd , FWLi , FWType , Output , Vdoms):
		QThread.__init__(self)
		self.usr		= usr 
		self.pwd		= pwd 
		self.FWLi		= FWLi  
		self.FWType		= FWType 
		self.Output		= Output  
		self.Vdoms		= Vdoms  
	def __del__(self):
		self.wait()
	
	def run(self):
		for FWIP in self.FWLi:
			self.connection_4 = connect2.ConnectTo(FWIP,self.usr,self.pwd,None)
			if self.connection_4 == None:
				return
			print "Connected_4"
				

			if self.FWType == 'Fortigate':
				Vdom = self.Vdoms.currentText()
				if Vdom == 'ALL_VDOMs':
					Vdoms = [self.Vdoms.itemText(i) for i in range(self.Vdoms.count())]
					Getg = GetForti(self.connection_4)
					Vdoms = Getg.VdomsForti()
					print Vdoms
					for Vdom in Vdoms:
						if Vdom == 'ALL_VDOMs':
							continue
						else:
							'config vdom\nedit %s' %(Vdom)
							Appl_Config = 'config vdom\nedit %s\n' %(Vdom) + self.Output.toPlainText()
							stdin, stdout, stderr =  self.connection_4.exec_command(Appl_Config)
							print Appl_Config
							for i in stdout.readlines():
								print i.replace('\n', '')
							continue
					self.connection_4.close()
							
				else:
					Appl_Config = self.Output.toPlainText()
					stdin, stdout, stderr =  self.connection_4.exec_command(Appl_Config)
					print Appl_Config
					for i in stdout.readlines():
						print i.replace('\n', '')
					self.connection_4.close()
					continue
			elif self.FWType == 'Juniper_SRX':
				LS = self.Vdoms.currentText()
				Appl_Config = self.Output.toPlainText()
				stdin, stdout, stderr =  self.connection_4.exec_command(Appl_Config)
				print Appl_Config
				for i in stdout.readlines():
					print i.replace('\n', '')
				self.connection_4.close()
				continue
			elif self.FWType == 'F5':
				Appl_Config = self.Output.toPlainText()
				stdin, stdout, stderr =  self.connection_4.exec_command(Appl_Config)
				print Appl_Config
				for i in stdout.readlines():
					print i.replace('\n', '')
				self.connection_4.close()
				continue

def main():
	app = QtGui.QApplication(sys.argv) ##
	### app = QtGui.QApplication.instance()  # A new instance of QApplication
	form = MyApp()  # We set the form to be our MyApp (design)
	form.show()  # Show the form
	app.exec_()  # and execute the app

if __name__ == '__main__':  # if we're running file directly and not importing it
	main()  # run the main function
	

#c:\Users\ethamah\Desktop\Python_Project\GUI>pyside-uic.exe -x c:\Users\ethamah\Desktop\Python_Project\GUI\gui_3rd_test.ui -o c:\Users\ethamah\Desktop\Python_Project\GUI\gui_3rd_test.py
#c:\Users\ethamah\Desktop\Python_Project\GUI>python  setup.py py2exe
## os.system('dir c:\Users\ethamer\Desktop')
## time.strftime('%Y-%m-%d-%H:%M:%S')
## os.mkdir('c:\Thamer')

# config system console
    # set output standard
# end

## C:\Users\hashem\Desktop\Python_Project\V3>pyside-uic.exe -x gui_3rd_test1.ui -o gui_3rd_test1.py

## get the whl file for the module and use the below command to intall it (without internet)
## pip install C:\Users\thmahmoud\Downloads\paramiko-2.4.2-py2.py3-none-any.whl  -f ./ --no-index


### DQ42

### Swvlx1
