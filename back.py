import os
try:
	from PyQt5.uic import loadUi
	from PyQt5.QtWidgets import QApplication, QMessageBox
	from PyQt5 import QtCore, QtGui, QtWidgets
	
except ModuleNotFoundError:
	os.system("pip install PyQt5")
from ajout import Ui_Form as ajoutClass
from principale import Ui_Form as principalClass
from login import Ui_Form as loginClass
from signup import Ui_Form as signupClass
from effacer import Ui_Form as effacerClass
from configurerDevice import Ui_Form as configDeviceClass
from addUserUI import Ui_Form as addUserUI
from deleteUser import Ui_supprimer as deleteAccount
from statistique import Ui_Statistique as statistique


import sqlite3
import json
import sys
import subprocess
import requests
import hashlib
try:
	import paramiko
except ModuleNotFoundError:
	os.system("pip install paramiko")

session=False
admin=False

#-------------------------------------------------
def historiqSetup():
	conn=sqlite3.connect("data.sqlite3.db")
	cursor=conn.execute('CREATE TABLE IF NOT EXISTS devices(id INT AUTO_INCREMENT PRIMARY KEY , serialNumber VARCHAR(300), name VARCHAR(255),idConnexion VARCHAR(500), certificat VARCHAR(1000), deleted VARCHAR(5))')
historiqSetup()
#--------------------------------------------------
def saveHistrique(serialNumber, deviceID, certificat, name):
	conn=sqlite3.connect("data.sqlite3.db")
	cursor=conn.cursor()
	req=cursor.execute("INSERT INTO devices (serialNumber, name, idConnexion, certificat, deleted) VALUES('{}', '{}', '{}', '{}', 'non')".format(serialNumber, name, deviceID, certificat))
	conn.commit()
	cursor.close()
	conn.close()	

#---------------------------------------
def setup():
	conn=sqlite3.connect("data.sqlite3.db")
	cursor=conn.execute('CREATE TABLE IF NOT EXISTS admin(id INT AUTO_INCREMENT PRIMARY KEY , username VARCHAR(255), password VARCHAR(500), type VARCHAR(255) null)')
	admins=conn.execute('SELECT * FROM admin')
	if len(admins.fetchall())==0:
		
		signup.show()
	elif session is False:
		loginn.show()

def setupAUI():
	ui.toAddDevice_5.show()
	ui.toAddDevice_6.show()
	ui.toAddDevice_2.show()


#---------------------------------------

def loginForm():
	username=uilogin.username.text()
	password=uilogin.password.text()
	if(len(username)==0 or len(password)==0):
		uilogin.label.setText("remplir vos coordonées")
	else:
		hashPass=hashlib.sha256(password.encode())
		password=hashPass.hexdigest()
		conn=sqlite3.connect("data.sqlite3.db")
		cursor=conn.cursor()
		sql="SELECT * FROM admin WHERE username=?  AND password=?"
		cursor.execute(sql, (username, password,))
		res=cursor.fetchall()

		if len(res)!=0:
			for row in res:
				if row[3]=="admin":
					setupAUI()
			cursor.close()
			conn.close()
			
			global session
			session=True
			loginn.close()
			# if admin alors setupAUI
		else:
			uilogin.label.setText("Vérifier vos coordonées")
#---------------------------------------
def signupForm():
	username=uisignup.username.text()
	password=uisignup.password.text()
	password2=uisignup.confirmpassword.text()
	if len(username)>0 and len(password)>0 and len(password2)>0:
		if password==password2:
			conn=sqlite3.connect("data.sqlite3.db")
			hashPass=hashlib.sha256(password.encode())
			password=hashPass.hexdigest()
			cursor=conn.cursor()
			req=cursor.execute("INSERT INTO admin (username, password, type) VALUES('{}', '{}', '{}')".format(username, password, 'admin'))
			conn.commit()
			cursor.close()
			conn.close()
			if req:
				uisignup.message.setText("Votre compte est créer avec succés")
				global session	
				session=True
				popup_window_after_signup()
				setupAUI()
			else:
				uisignup.message.setText("Erreur l'ors de création de compte")
		else:
			uisignup.message.setText("Vérifier vos coordonées")
	else:
		uisignup.message.setText("Remplir vos coordonées")

#---------------------------------------------
def AddNewUser():
	username=newAccount.username.text()
	password=newAccount.password.text()
	password2=newAccount.confirmpassword.text()
	if len(username)>0 and len(password)>0 and len(password2)>0:
		if password==password2:
			conn=sqlite3.connect("data.sqlite3.db")
			hashPass=hashlib.sha256(password.encode())
			password=hashPass.hexdigest()
			cursor=conn.cursor()
			req=cursor.execute("INSERT INTO admin (username, password, type) VALUES('{}', '{}', '{}')".format(username, password, 'user'))
			conn.commit()
			cursor.close()
			conn.close()
			if req:
				popup_window_add_user(username)
			else:
				newAccount.message.setText("Erreur l'ors de création de compte")
		else:
			newAccount.message.setText("Vérifier vos coordonées")
	else:
		newAccount.message.setText("Remplir vos coordonées")
#---------------------------------------------
def showAddWindow():
	if session is False:
		return setup()
	ajout.show()
#----------------------------------------------
def nouveauCompte():
	if session is False:
		return setup()
	newAccountUI.show()

#----------------------------------------------
def getDeviceIDWithSerialNumber(serialNumber):
	conn=sqlite3.connect("data.sqlite3.db")
	cursor=conn.cursor()
	sql="SELECT * FROM devices WHERE serialNumber=?"
	response=cursor.execute(sql, (serialNumber,))
	if response:
		row=response.fetchone()
		if row:
			return row[3]
	return False

#----------------------------------------------
def changeDeletedInDataBase(serialNumber):
	conn=sqlite3.connect("data.sqlite3.db")
	cursor=conn.cursor()
	sql="UPDATE devices SET deleted = 'oui' WHERE serialNumber=?"
	cursor.execute(sql, (serialNumber,))
	conn.commit()
	cursor.close()
	conn.close()

#----------------------------------------------
def deviceErrase():
	serialNumber=uieffacer.comboBox_2.currentText()
	deviceID=getDeviceIDWithSerialNumber(serialNumber)

	responseFronFirstRequest=doFirstRequest()
	if responseFronFirstRequest and deviceID:
		deleteDevice(responseFronFirstRequest, deviceID, serialNumber)
	else:
		uieffacer.message.setText("Cet appareil introuvable")
#------------------------------------------------
def showErraseWindow():
	if session is False:
		return setup()
	effacer.show()
#-----------------------------------------------
def coreLogiciel():
	serialNumber=uiajout.serialNumber.text()
	deviceName=uiajout.devicesNames.currentText()
	deviceNumber=uiajout.comboBox.currentText()
	deviceType=uiajout.devicesTypes.currentText()
	description=uiajout.description.text()
	manifacturez=uiajout.manifacturez.text()#openssl x509 -in self-cert.pem -outform der
	if len (serialNumber)>0 and len(deviceName)>0 and len(deviceNumber)>0 and len(deviceType)>0 and len(manifacturez)>0 and len(description)>0:
		os.system("bin\\OpenSSL-Win64\\bin\\openssl ecparam -name prime256v1 -genkey -noout -out util/self-key.pem")
		os.system('bin\\OpenSSL-Win64\\bin\\openssl req -config bin/OpenSSL-Win64/bin/openssl.cfg -new -x509 -key util/self-key.pem -days 365 -subj "/C=FR/ST=Isere/L=Grenoble/O=Schneider/CN={}" -out util/self-cert.pem'.format(serialNumber))
		os.system("bin\\OpenSSL-Win64\\bin\\openssl x509 -fingerprint -sha1 -in util/self-cert.pem > util/helper.txt")
		deviceID=getDeviceId()
		primaryKey=subprocess.Popen("bin/base64  util/self-cert.pem ", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		pkey=primaryKey.stdout.read().decode('utf-8')
		params={"DeviceId":deviceID, "DisplayName":deviceName, "Description":description, "Manufacturer":manifacturez, "DeviceType":deviceType, "ModelNumber":deviceNumber, "ProvisioningKey":{"PrimaryKey":pkey}}
		jsonFile=open("util/params.json", "w")
		jsonParams=json.dump(params, jsonFile ,indent=4)
		responseFronFirstRequest=doFirstRequest()
		if responseFronFirstRequest:
			uiajout.label.setText('Connexion au serveur')
			responseSecRequest=doSecondRequest(responseFronFirstRequest, deviceID, deviceName, description, manifacturez, deviceType, deviceNumber, pkey)
			if responseSecRequest:
				responseLastRequest=doLastRequest(responseFronFirstRequest,deviceID)
				if responseLastRequest:
					saveHistrique(serialNumber, deviceID[0:len(deviceID)-1], pkey, deviceName)
					popup_window_add_appareil(serialNumber, deviceName, description, manifacturez, deviceType , deviceNumber)
					ajout.close()
	else:
		uiajout.label.setText("Tous les coordonnées de l'appareil sont obligatoire !!!!")

#----------------------------------------------------------------------
def doFirstRequest():
	#get token
	try:
		fileToken=open('util/token.txt', 'r')
		fileTab=fileToken.readlines()
		token=''
		for item in fileTab:
			token+=item
		token='Bearer {}'.format(token)
		url = 'https://login.microsoftonline.com/db8e2ba9-95c1-4fbb-b558-6bf8bb1d2981/oauth2/v2.0/token'
		headers={
			'Authorization': token,
			'Cookie' : "fpc=Ak-Hanf5eiBHpj_OlYCt1JJnUFGNAQAAAIafedoOAAAA; stsservicecookie=estsfd; x-ms-gateway-slice=estsfd"
		 }
		payload={
			'grant_type': 'client_credentials',
			'client_id': '82bdf54e-faad-4c4f-9cc5-eef95666faa1',
			'client_secret': 'YRu8Q~AssrXZzkGxolQYp~WPIyMqAgxqwB86wcB0',
			'scope': 'https://etp-intgr.syseng.struxurewarecloud.com/.default'
			}
		files=[

			]
		response = requests.request("POST", url, headers=headers, data=payload, files=files)
		assert response.status_code==200
		return response.text
	except requests.exceptions.ConnectionError:
		print("erreur lors de létablissement de connexion")
		uiajout.label.setText('Veiller verifier votre connexion internet')
		return False
	except AssertionError:
		uiajout.label.setText("Veiller verifier votre token")
		return False
	
#----------------------------------------------------------------------
def doSecondRequest(dataFronFirstRequest, deviceID, deviceName, description, manifacturez, deviceType, deviceNumber, pkey):
	try:
		url ='https://etp-intgr.syseng.struxurewarecloud.com/api/devicemanagement/0d52c587-ea79-4c80-b101-c74aadf36b97/registry/enroll'
		jsonRes=json.loads(dataFronFirstRequest)
		deviceID=deviceID[0:len(deviceID)-1]
		token='Bearer {}'.format(jsonRes['access_token'])
		pkey=pkey.replace("\n", "")
		headers={
			'api-version':'1.0',
			'Content-Type': 'application/json',
			"Authorization" : token
		}
		datas=json.dumps({
			"DeviceId": deviceID,
			"DisplayName": deviceName,
			"Description": description,
			"Manufacturer": manifacturez,
			"DeviceType": deviceType,
			"ModelNumber": deviceNumber,
			"ProvisioningKey": {
						"PrimaryKey": pkey
					}
		})
		response = requests.request("POST", url, headers=headers, data=datas)
		if response.status_code==201:
			uiajout.label.setText("Appareil ajoutée avec succés")
			return True
		elif response.status_code==401:
			uiajout.label.setText('Ereur l\'ors de l\'authentification')
			return False
		elif response.status_code==409:
			uiajout.label.setText('Cet appareil déjà existent')
			return False
		else:
			uiajout.label.setText('Cet url n\'existe pas')
			return False
	except Exception:
		uiajout.label.setText("Veiller vérifier les données de l'appareil")
		return False

#----------------------------------------------------------------------
def doLastRequest(dataFronFirstRequest, deviceID):
	jsonRes=json.loads(dataFronFirstRequest)
	token='Bearer '+jsonRes['access_token']
	
	try:
		deviceID=deviceID[0:len(deviceID)-1]
		jsonRes=json.loads(dataFronFirstRequest)
		token='Bearer '+jsonRes['access_token']
		url="https://etp-intgr.syseng.struxurewarecloud.com/api/devicemanagement/0d52c587-ea79-4c80-b101-c74aadf36b97/registry/associate/{}".format(deviceID)
		#print(url)
		headers={
				'api-version':'1.0',
				'Authorization': token
		}
		payload={}
		response = requests.request("POST", url, headers=headers, data=payload)
		uiajout.label.setText('Device associé')
		print(response.status_code)
		if response.status_code==200:
			uiajout.label.setText('Appareil associé avec succés')
			return True
		elif response.status_code==401:
			uiajout.label.setText('Ereur l\'ors de l\'authentification')
			return False
		elif response.status_code==409:
			uiajout.label.setText('Cet appareil est déja associé')
			return False
		else:
			uiajout.label.setText('Cet url n\'existe pas')
			return False
	except Exception:
		uiajout.label.setText('Un erreur l\'ors de l\'opération')
		return False
		
#----------------------------------------------------------------------
def deleteDevice(dataFronFirstRequest, deviceID, serialNumber):
	try:
		url ='https://etp-intgr.syseng.struxurewarecloud.com/api/devicemanagement/0d52c587-ea79-4c80-b101-c74aadf36b97/registry/enroll/{}'.format(deviceID)
		jsonRes=json.loads(dataFronFirstRequest)	
		token='Bearer {}'.format(jsonRes['access_token'])
		headers={
			'api-version':'1.0',
			'Content-Type': 'application/json',
			"Authorization" : token
		}
		datas={}
		response = requests.request("DELETE", url, headers=headers, data=datas)
		if response.status_code==200:
			changeDeletedInDataBase(serialNumber)
			uieffacer.message.setText("Appareil supprimée avec succés ")
		elif response.status_code==404:
			uieffacer.message.setText("Cet appareil introuvable")
	except Exception:
		uieffacer.message.setText("Veillée vérifier les données de l'appareil")
		return False

#-------------------------------------------
def allDevicesNamesRequest(dataFronFirstRequest):
	try:
		url='https://etp-intgr.syseng.struxurewarecloud.com/api/devicemanagement/0d52c587-ea79-4c80-b101-c74aadf36b97/devices'
		jsonRes=json.loads(dataFronFirstRequest)
		token='Bearer {}'.format(jsonRes['access_token'])
		headers={
			'api-version':'1.0',
			'Content-Type': 'application/json',
			"Authorization" : token
		}
		payload={}
		response = requests.request("GET", url, headers=headers, data=payload)

		if response.status_code==200:
			return response.text
		elif response.status_code==404:
			print("get all devices names requests send page introuvable response <----->") 
			return False
	except Exception:
		print("Veillée vérifier les données de l'appareil")
		return False
#------------------------------------------------------------------------
def getDeviceIdWithName(deviceName):
	conn=sqlite3.connect("data.sqlite3.db")
	request=conn.execute("SELECT * FROM devices WHERE name = '{}'".format(deviceName))
	if request:
		return request.fetchall()
	return None
#------------------------------------------------------------------------
def getDeviceId():
	file=open("util/helper.txt", "r")
	contenu=file.readlines()
	contenu=contenu[0]
	contenu=contenu[17:len(contenu)]
	ncon=""
	for item in contenu:
		if item!=":":
			if item not in [1, 2, 3, 4, 5, 6, 7, 8, 9]:
				ncon+=item.lower()
			else:
				ncon+=item
	deviceID="urn:dev:cer:{}".format(ncon)
	return deviceID

#----------------------------------------------------------------------
def notifyDevice():
	if session==False:
		return setup()
	notifier.show()
def paramikoManipule(host, port, username, password, deviceID):
	try:
		result=retrieveDevice(deviceID)
		if result:
			ssh_client=paramiko.SSHClient()
			ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			ssh_client.load_system_host_keys()
			ssh_client.connect(host, port, username, password)
			sftp_client=ssh_client.open_sftp()
			sftp_client.put("util/edgeAgentService.json", "edgeAgentService.json")
			sftp_client.close()
			ssh_client.close()
			alertPopUpAfterConfigureDevice()
			#uinotifier.message.setText("votre device est configurer avec succés")
			#notifier.close()
		else:
			uinotifier.message.setText("cet device introuvable")
	except:
		uinotifier.message.setText("verifier vos coordonnées")
#-----------------------------
def alertPopUpAfterConfigureDevice():
	msg=QMessageBox()
	msg.setWindowTitle("Configurer appareil")
	msg.setText("votre device est configuré avec succés")
	msg.setIcon(QMessageBox.Information)
	msg.buttonClicked.connect(closeNotifieWindow)
	msg.exec_()
#----------------------------
def retrieveDevice(serialNumber):
	conn=sqlite3.connect("data.sqlite3.db")
	cursor=conn.cursor()
	sql="SELECT * FROM devices WHERE serialNumber =?"
	request=cursor.execute(sql,(serialNumber,))
	if request:
		result=request.fetchone()
		if result:
			params={"serialNumber":result[1], "DeviceID":result[3], "certificat":result[4]}
			jsonFile=open("util/edgeAgentService.json", "w")
			jsonParams=json.dump(params, jsonFile ,indent=4)
			return True
	return False
#------------------------------
def getDateFromZuluDate(zuluDate):
	if zuluDate:
		return zuluDate[0:10]
	return 0
#----------------------------
def showStatistic():
	statistiqueO.show()
	uistatistique.graphicsView.clear()
	dataFromFirstRequest=doFirstRequest()
	data=allDevicesNamesRequest(dataFromFirstRequest)

	if data:
		from datetime import date
		today=date.today()
		devicesAddedToday=0
		devicesAddedLastDays = 0
		jsonData=json.loads(data)
		devicesInfos=jsonData['Value']
		if devicesInfos:
			for item in devicesInfos:
				if getDateFromZuluDate(item["$metadata"]["$lastIndexUpdated"])==today:
					devicesAddedToday+=1
				else:
					devicesAddedLastDays+=1
			uistatistique.graphicsView.plot(x=[0, 8], y=[devicesAddedLastDays, devicesAddedToday])
	else:
		uistatistique.graphicsView.plot(x=[], y=[])
	
#---------------------
def retrieveUserAccount(username):

	conn=sqlite3.connect("data.sqlite3.db")
	cursor=conn.cursor()
	sql="SELECT * FROM admin WHERE username=?"
	result=cursor.execute(sql, (username,))
	if len(result.fetchall())>0:
		return True
	return False
#-----------------------
def deleteUserAccount():
	try:
		username=uiDeleteAccount.lineEdit.text()
		conn=sqlite3.connect("data.sqlite3.db")
		cursor=conn.cursor()
		sql="DELETE FROM admin WHERE username=?"
		cursor.execute(sql, (username,))
		conn.commit()
		deleteAccountO.close()
		showPopSuccessDeleteAccount()
	except sqlite3.Error as error:
		print(error)

#------------------------------
def configurerDevice():
	host=uinotifier.lineEdit.text()
	port=uinotifier.lineEdit_2.text()
	username=uinotifier.lineEdit_3.text()
	password=uinotifier.lineEdit_4.text()
	deviceID=uinotifier.comboBox_2.currentText()
	if len(port)==0 :
		port=22
	if host and port and username and password and deviceID: 
		paramikoManipule(host, port, username, password, deviceID)
	else:
		uinotifier.message.setText("Remplir tous les coordonnées ")
#------------------------------------------
def closeAjoutWindow():
	ajout.close()

#-----------------------------------------
def closeEffaceWindow():
	effacer.close()
#-------------------------------
def closeNotifieWindow():
	notifier.close()
#-------------------------------
def popup_window_delete_appareil():
    msg=QMessageBox()
    msg.setWindowTitle("Supprimée un appareil")
    msg.setText("Vous étes sure de supprimer cet appareil ?")
    msg.setIcon(QMessageBox.Warning)
    msg.buttonClicked.connect(deviceErrase)
    msg.exec_()

def checkInfoBeforeErraseDevice():
	if session is False:
		return setup()
	serialNumber=uieffacer.comboBox_2.currentText()
	if serialNumber:
		popup_window_delete_appareil()
	else:
		uieffacer.message.setText("Veiller taper vos coordonées")
#------------------------------
def popup_window_add_appareil(serialNumber, nom, description, manifacturer, typeA , numero):
    msg=QMessageBox()
    msg.setWindowTitle("Ajoutée un appareil")
    msg.setText("Appareil ajouté avec succés ")
    msg.setIcon(QMessageBox.Information)
    msg.setDetailedText("Numéro de série : "+serialNumber+"\nNom de l'appareil : "+nom+"\nDescription : "+description+"\nType de l'appareil : "+typeA+"\nManufacturer : "+manifacturer+"\nNuméro de l'appareil : "+numero)
    msg.exec_()
#--------------------------------------------
def popup_window_add_user(username):
    msg=QMessageBox()
    msg.setWindowTitle("Ajoutée un utilisateur")
    msg.setText("Compte crée avec succés ( "+username+" )")
    msg.setIcon(QMessageBox.Information)
    msg.buttonClicked.connect(closeAddUserWindow)
    msg.exec_()
#-------------------------------
def closeAddUserWindow():
	newAccountUI.close()
#----------------------------------
def showPopSuccessDeleteAccount():
	msg=QMessageBox()
	msg.setWindowTitle("Supprimée un utilisateur")
	msg.setText("Compte supprimée avec succée ")
	msg.setIcon(QMessageBox.Information)
	msg.exec_()
#--------------------------
def popup_window():
    msg=QMessageBox()
    msg.setWindowTitle("Supprimée un compte ")
    msg.setText("Vous étes sure de supprimer ce compte ?")
    msg.setIcon(QMessageBox.Warning)
    msg.buttonClicked.connect(deleteUserAccount)
    msg.exec_()
#---------------------------------------
def closeSignupWindow():
	signup.close()
#---------------------------------------
def popup_window_after_signup():
	msg=QMessageBox()
	msg.setWindowTitle("Crée un compte ")
	msg.setText("Votre compte est créer avec succés ")
	msg.setIcon(QMessageBox.Information)
	msg.buttonClicked.connect(closeSignupWindow)
	msg.exec_()
#----------------------------------
def insertItemsOfSerialNumbers(value):
	uieffacer.comboBox_2.clear()
	devicesInfos=getDeviceIdWithName(value)
	for item in devicesInfos:
		if item[5]=="non":
			uieffacer.comboBox_2.addItem(item[1])
#----------------------------------------------
def insertItemsOfSerialNumbersConfig(value):
	uinotifier.comboBox_2.clear()
	devicesInfos=getDeviceIdWithName(value)
	for item in devicesInfos:
		uinotifier.comboBox_2.addItem(item[1])
#------------------------------------------
def retourToMainFromStatistique():
	statistiqueO.close()
#---------------------------------------
def showPopWindwo():
	username=uiDeleteAccount.lineEdit.text()
	if len(username)>3:
		if retrieveUserAccount(username):
			popup_window()
		else:
			failedDeleteAccount("Cet compte n'existe pas")
	else:
		failedDeleteAccount("Taper le nom de l'utilisateur")
#---------------------
def failedDeleteAccount(error):
	msg=QMessageBox()
	msg.setWindowTitle("Supprimée un compte ")
	msg.setText(error)
	msg.setIcon(QMessageBox.Information)
	
	msg.exec_()
#-----------------------------
def showDeleteUserAccount():
	deleteAccountO.show()
#----------------------------------
def closeDeleteUserWindow():
	deleteAccountO.close()

#------------------------------------
def createExcelFile():
	try:
		import jpype
		import asposecells
		jpype.startJVM()
		from asposecells.api import Workbook, FileFormatType
	except ModuleNotFoundError:
		os.system("pip install aspose-cells")
		import jpype
		import asposecells
		jpype.startJVM()
		from asposecells.api import Workbook, FileFormatType
		
	
	dataFromFirstRequest=doFirstRequest()
	data=allDevicesNamesRequest(dataFromFirstRequest)
	
	if data:
		jsonData=json.loads(data)
		devicesInfos=jsonData['Value']
		if devicesInfos:
			wb=Workbook("allDevices.xlsx")
			wb.getWorksheets().get(0).getCells().insertRows(5, 10)
			sheet=wb.getWorksheets().get(0).getCells()
			row=5
			for item in devicesInfos:
				sheet.get("A"+str(row)).putValue(str(item["DeviceId"]))
				sheet.get("B"+str(row)).putValue(str(item["DeviceType"]))
				sheet.get("C"+str(row)).putValue(str(item["DeviceIP"]))
				sheet.get("D"+str(row)).putValue(str(item["DisplayName"]))
				sheet.get("E"+str(row)).putValue(str(item["Description"]))
				sheet.get("F"+str(row)).putValue(str(item["Tenant"]))
				sheet.get("G"+str(row)).putValue(str(item["IsRevoked"]))
				sheet.get("H"+str(row)).putValue(str(item["IsClaimable"]))
				sheet.get("I"+str(row)).putValue(str(item["DataOwner"]))
				sheet.get("J"+str(row)).putValue(str(item["DeviceOwner"]))

				sheet.get("K"+str(row)).putValue(str(item["Infos"]["Manufacturer"]))
				
				sheet.get("L"+str(row)).putValue(str(item["Infos"]["ModelNumber"]))
				sheet.get("M"+str(row)).putValue(str(item["Infos"]["SerialNumber"]))
				sheet.get("N"+str(row)).putValue(str(item["Infos"]["HardwareVersion"]))
				sheet.get("O"+str(row)).putValue(str(item["Infos"]["FirmwareVersion"]))
				sheet.get("P"+str(row)).putValue(str(item["Infos"]["SoftwareVersion"]))
				sheet.get("Q"+str(row)).putValue(str(item["Infos"]["NetworkBearer"]))
				sheet.get("R"+str(row)).putValue(str(item["Infos"]["APN"]))
				sheet.get("S"+str(row)).putValue(str(item["Infos"]["IMSI"]))
				sheet.get("T"+str(row)).putValue(str(item["Infos"]["EdgeOrchestratorType"]))
				sheet.get("U"+str(row)).putValue(str(item["Infos"]["Platform"]))

				sheet.get("V"+str(row)).putValue(str(item["States"]["RegistryState"]))
				sheet.get("W"+str(row)).putValue(str(item["States"]["LastRegistryStateUpdated"]))
				sheet.get("X"+str(row)).putValue(str(item["States"]["ConnectionState"]))
				sheet.get("Y"+str(row)).putValue(str(item["States"]["LastConnectionStateUpdate"]))
				
				sheet.get("Z"+str(row)).putValue(str(item["Policies"]["Desired"]["Firmware"]["Url"]))
				sheet.get("AA"+str(row)).putValue(str(item["Policies"]["Desired"]["Firmware"]["Version"]))

				sheet.get("AB"+str(row)).putValue(str(item["Policies"]["Desired"]["Time"]["SyncTime"]["Enabled"]))
				sheet.get("AC"+str(row)).putValue(str(item["Policies"]["Desired"]["Time"]["SyncTime"]["Frequency"]))

				sheet.get("AD"+str(row)).putValue(str(item["Policies"]["Reported"]["Firmware"]["FirmwareVersion"]))
				sheet.get("AE"+str(row)).putValue(str(item["Policies"]["Reported"]["Firmware"]["Status"]))
				sheet.get("AF"+str(row)).putValue(str(item["Policies"]["Reported"]["Firmware"]["Error"]))

				sheet.get("AG"+str(row)).putValue(str(item["Policies"]["Reported"]["ConfigurationFile"]["Restore"]["Filename"]))
				sheet.get("AH"+str(row)).putValue(str(item["Policies"]["Reported"]["ConfigurationFile"]["Restore"]["Tag"]))
				sheet.get("AI"+str(row)).putValue(str(item["Policies"]["Reported"]["ConfigurationFile"]["Restore"]["Timestamp"]))
				sheet.get("AJ"+str(row)).putValue(str(item["Policies"]["Reported"]["ConfigurationFile"]["Restore"]["Status"]))
				
				sheet.get("AK"+str(row)).putValue(str(item["Policies"]["Reported"]["ConfigurationFile"]["Backup"]["Filename"]))
				sheet.get("AL"+str(row)).putValue(str(item["Policies"]["Reported"]["ConfigurationFile"]["Backup"]["Tag"]))
				sheet.get("AM"+str(row)).putValue(str(item["Policies"]["Reported"]["ConfigurationFile"]["Backup"]["Timestamp"]))
				sheet.get("AN"+str(row)).putValue(str(item["Policies"]["Reported"]["ConfigurationFile"]["Backup"]["Status"]))

				sheet.get("AO"+str(row)).putValue(str(item["Policies"]["Reported"]["ConfigurationFile"]["Current"]["Filename"]))
				sheet.get("AP"+str(row)).putValue(str(item["Policies"]["Reported"]["ConfigurationFile"]["Current"]["Tag"]))
				sheet.get("AQ"+str(row)).putValue(str(item["Policies"]["Reported"]["ConfigurationFile"]["Current"]["Timestamp"]))
				sheet.get("AR"+str(row)).putValue(str(item["Policies"]["Reported"]["ConfigurationFile"]["Current"]["AppliedDate"]))
				sheet.get("AS"+str(row)).putValue(str(item["Policies"]["Reported"]["ConfigurationFile"]["Current"]["LocallyChanged"]))

				sheet.get("AT"+str(row)).putValue(str(item["Policies"]["Reported"]["Time"]["SyncTime"]["Enabled"]))
				sheet.get("AU"+str(row)).putValue(str(item["Policies"]["Reported"]["Time"]["SyncTime"]["Frequency"]))
				sheet.get("AV"+str(row)).putValue(str(item["Policies"]["Reported"]["Time"]["Timezone"]["CountryCode"]))
				sheet.get("AW"+str(row)).putValue(str(item["Policies"]["Reported"]["Time"]["Timezone"]["ZoneName"]))

				sheet.get("AX"+str(row)).putValue(str(item["Version"]["AgentVersion"]))

				sheet.get("AY"+str(row)).putValue(str(item["ServiceEndpointName"]))
				sheet.get("AZ"+str(row)).putValue(str(item["PrimaryNetworkAddress"]))
				sheet.get("BA"+str(row)).putValue(str(item["Location"]))
				sheet.get("BB"+str(row)).putValue(str(item["Attributes"]))
				sheet.get("BC"+str(row)).putValue(str(item["$metadata"]["$lastDesiredUpdated"]))
				sheet.get("BD"+str(row)).putValue(str(item["$metadata"]["$lastReportedUpdated"]))
				sheet.get("BE"+str(row)).putValue(str(item["$metadata"]["$lastIndexUpdated"]))

				row+=1
			wb.save(os.path.expanduser('~')+"/Desktop/devices.xlsx")
			popWindowSuccessExport()
		else:
			popWindowErrorGetAllDevices()
		jpype.shutdownJVM()
#----------------------------------------

app = QtWidgets.QApplication(sys.argv)


#------------------------------------------
def popWindowSuccessExport():
	msg=QMessageBox()
	msg.setWindowTitle("Exporter les appareils ")
	msg.setText("Opération terminée avec succée")
	msg.setIcon(QMessageBox.Information)
	msg.exec_()
#----------------------------------------------
def popWindowErrorGetAllDevices():
	msg=QMessageBox()
	msg.setWindowTitle("Erreur  ")
	msg.setText("Erreur l'ors d'obtenir des appareils")
	msg.setIcon(QMessageBox.Warning)
	msg.exec_()
#-------------------------------------------
principal = QtWidgets.QWidget()
ui = principalClass()
ui.setupUi(principal)
ui.toAddDevice.clicked.connect(showAddWindow)
ui.toAddDevice_2.clicked.connect(nouveauCompte)
ui.toAddDevice_3.clicked.connect(showErraseWindow)
ui.toAddDevice_4.clicked.connect(notifyDevice)
ui.toAddDevice_5.clicked.connect(showDeleteUserAccount)
ui.toAddDevice_6.clicked.connect(showStatistic)

ajout = QtWidgets.QWidget()
uiajout = ajoutClass()
uiajout.setupUi(ajout)
uiajout.addDeviceButton.clicked.connect(coreLogiciel)
uiajout.retourButton.clicked.connect(closeAjoutWindow)


loginn= QtWidgets.QWidget()
uilogin = loginClass()
uilogin.setupUi(loginn)
uilogin.loginButton.clicked.connect(loginForm)

signup= QtWidgets.QWidget()
uisignup = signupClass()
uisignup.setupUi(signup)
uisignup.signupbutton.clicked.connect(signupForm)

newAccountUI= QtWidgets.QWidget()
newAccount = addUserUI()
newAccount.setupUi(newAccountUI)
newAccount.signupbutton.clicked.connect(AddNewUser)


effacer= QtWidgets.QWidget()
uieffacer = effacerClass()
uieffacer.setupUi(effacer)
uieffacer.deleteButton.clicked.connect(checkInfoBeforeErraseDevice)
uieffacer.retourButton.clicked.connect(closeEffaceWindow)
uieffacer.comboBox.currentTextChanged.connect(insertItemsOfSerialNumbers)


notifier= QtWidgets.QWidget()
uinotifier = configDeviceClass()
uinotifier.setupUi(notifier)
uinotifier.pushButton.clicked.connect(configurerDevice)
uinotifier.retourButton.clicked.connect(closeNotifieWindow)
uinotifier.comboBox.currentTextChanged.connect(insertItemsOfSerialNumbersConfig)

deleteAccountO=QtWidgets.QWidget()
uiDeleteAccount=deleteAccount()
uiDeleteAccount.setupUi(deleteAccountO)
uiDeleteAccount.supprimerUser.clicked.connect(showPopWindwo)
uiDeleteAccount.retourButton.clicked.connect(closeDeleteUserWindow)


statistiqueO=QtWidgets.QWidget()
uistatistique=statistique()
uistatistique.setupUi(statistiqueO)

uistatistique.RetourButton.clicked.connect(retourToMainFromStatistique)
uistatistique.ExportButton.clicked.connect(createExcelFile)

principal.show()
if session==False:
	setup()
sys.exit(app.exec_())

