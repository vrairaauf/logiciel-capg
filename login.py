
 
from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.setWindowModality(QtCore.Qt.ApplicationModal)
        Form.resize(465, 431)
        Form.setMinimumSize(QtCore.QSize(465, 431))
        Form.setFixedWidth(465)
        Form.setFixedHeight(431)
        self.username = QtWidgets.QLineEdit(Form)
        self.username.setGeometry(QtCore.QRect(70, 140, 311, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei UI Light")
        font.setBold(False)
        font.setWeight(50)
        self.username.setFont(font)
        self.username.setAlignment(QtCore.Qt.AlignCenter)
        self.username.setObjectName("username")
        self.password = QtWidgets.QLineEdit(Form)
        self.password.setGeometry(QtCore.QRect(70, 220, 311, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei UI Light")
        font.setBold(False)
        font.setWeight(50)
        self.password.setFont(font)
        self.password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password.setAlignment(QtCore.Qt.AlignCenter)
        self.password.setObjectName("password")
        self.loginButton = QtWidgets.QPushButton(Form)
        self.loginButton.setGeometry(QtCore.QRect(160, 300, 131, 51))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei UI Light")
        font.setPointSize(12)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        self.loginButton.setFont(font)
        self.loginButton.setAutoDefault(False)
        self.loginButton.setObjectName("loginButton")
        self.label = QtWidgets.QLabel(Form)
        self.label.setGeometry(QtCore.QRect(60, 380, 311, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei UI Light")
        font.setPointSize(12)
        self.label.setFont(font)
        self.label.setText("")
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(Form)
        self.label_2.setGeometry(QtCore.QRect(150, 10, 151, 111))
        self.label_2.setText("")
        self.label_2.setPixmap(QtGui.QPixmap("file-dev/login.jpg"))
        self.label_2.setScaledContents(True)
        self.label_2.setObjectName("label_2")

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Login"))
        self.username.setPlaceholderText(_translate("Form", "username"))
        self.password.setPlaceholderText(_translate("Form", "****************"))
        self.loginButton.setText(_translate("Form", "Connecter"))

