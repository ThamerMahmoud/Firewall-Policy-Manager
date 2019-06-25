import paramiko
from netaddr import *
import pprint
### import getpass
import os,sys
import socket
import datetime


os.system('cls')
global CashedCommand, BackupConfig, ConfigurationFile
CashedCommand = {}

def ClearCashingCommand():
	global CashedCommand
	CashedCommand = {}

	
def ConnectTo(IP,username,password, BackupConfig): #return open connection
	global ConfigurationFile
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	try:
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Connecting to :") + IP
		ssh.connect(IP, username=username, password=password)
	except paramiko.ssh_exception.AuthenticationException:
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Authentication Error : Check Your Username & Password")
		return None
	# except paramiko.ssh_exception.SSHException:
		# print 'Many Times login, Check after a while :)'
		# return None
	except socket.error:
		print datetime.datetime.now().strftime("[%d/%m/%Y-%H:%M:%S] : Failed to reach : ") + IP
		return None
		
	if BackupConfig:
		FilesLocation = os.path.dirname(os.path.realpath(sys.argv[0]))
		print FilesLocation + "\\BackupConfig\\" + IP + ".txt"
		try:
			ConfigurationF = open(FilesLocation + "\\BackupConfig\\" + IP + ".txt" , "r")
			ConfigurationFile = ConfigurationF.read().decode(errors='ignore').split('\n')
			ConfigurationF.close()
			
			print "file " + IP + ".txt readed"
			
		except:
			print "file " + IP + ".txt not exit"
			ConfigurationFile = []
	else:
		ConfigurationFile = []
	return ssh
	
	
	
def SendCommand(ssh,command):
	global CashedCommand, BackupConfig, ConfigurationFile
	a =[]

	if command not in CashedCommand.keys():
		if 'zone | display xml' in command:
			stdin, stdout, stderr = ssh.exec_command(command)
			CashedCommand[command] = stdout.read()
			return CashedCommand[command]
			################# Backup configuration ############################
			
		if "show configuration" in command and ConfigurationFile != [] :   #### juniper firewall only
			firstmatch = command.split('|')[0].replace('show configuration ','').strip()
			matches = command.split('match')[1:]



			for line in ConfigurationFile:
				if firstmatch in line:
					if  matches == []:
						a.append(line)
						continue
					if 'logical-system' in command:
						if all(match.replace('|' ,'').strip() in line for match in matches) and 'set logical-system' in line:
							a.append(line)
							continue
					elif 'logical-system' not in command:
						if all(match.replace('|' ,'').strip() in line for match in matches) and 'set logical-system' not in line:
							a.append(line)

			CashedCommand[command] = a
			### print command + "   >>>  backuped"
			return CashedCommand[command]


		stdin, stdout, stderr = ssh.exec_command(command)
		for line in stdout.read().decode(errors='ignore').split('\n'):
			if line == "":
				continue
			a.append(line)

		CashedCommand[command] = a

		return CashedCommand[command]
	else:
		###  print 'Cashed'
		return CashedCommand[command]
		
		
		
		
def Closed(ssh):
	ssh.close()
