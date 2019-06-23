import sys
from PySide import QtCore, QtGui 
from PySide.QtCore import QThread, SIGNAL
import gui_3rd_test1
import Add_FW,AddFW
from netaddr import *
import pprint
import re , os
from  get2 import GetForti,GetSRX,GetF5
import time
import datetime
import connect2


class AddFW(QtGui.QWidget, Add_FW.Ui_Form):
	def __init__(self):
		super(self.__class__, self).__init__()
		self.setupUi(self)
		
		try:
			file = open('FWList.csv','r')
			for ii, i in enumerate(file.readlines()):
				QtGui.QListWidgetItem(self.AddFW_FWList)
				self.AddFW_FWList.item(ii).setText(QtGui.QApplication.translate("Form", "%s_%s" %(i.split(',')[1], i.split(',')[2]), None, QtGui.QApplication.UnicodeUTF8))
				self.LastItem = ii
			file.close()
		except IOError , MSG:
			print MSG

		self.AddFW_Add.clicked.connect(self.Add)
		self.AddFW_Remove.clicked.connect(self.Remove)
		

	def Add(self):
		#############   Check Mandatory fileds  ##########
		try:
			IPAddress(self.AddFW_FWIP.text())
		except:
			return
		if self.AddFW_FWVendorList.currentText() == '':
			return
		##################################################
		try:
			file2 = open('FWList.csv','a+')
			self.LastItem = self.LastItem + 1
			file2.write('%s,%s,%s,%s,%s,\n' %(self.LastItem, self.AddFW_FWName.text(), self.AddFW_FWIP.text(), self.AddFW_FWVendorList.currentText() ,self.AddFW_LogicalSystemCHK.isChecked()))
			file2.close()
			QtGui.QListWidgetItem(self.AddFW_FWList)
			self.AddFW_FWList.item(self.LastItem).setText("%s_%s" %(self.AddFW_FWName.text(), self.AddFW_FWIP.text()))
		except IOError , MSG:
			print MSG
			return

			
	def Remove(self):
		listItems=self.AddFW_FWList.selectedItems()
		X = self.AddFW_FWList.currentItem().text().split('_')[1]
		if not listItems: return        
		for item in listItems:
		   self.AddFW_FWList.takeItem(self.AddFW_FWList.row(item))
		print 
		try:
			file = open('FWList.csv','r')
			lines = file.readlines()
			file.close()
			file = open('FWList.csv','w')
			for line in lines:
				if X not in line:
					file.write(line)
			file.close()
			self.LastItem = self.LastItem -1
		except IOError , MSG:
			print MSG
