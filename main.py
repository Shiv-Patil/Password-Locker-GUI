#! Python3
# Password Locker GUI app made using kivy.

from kivy.app import App
from kivy.properties import ObjectProperty
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.core.window import Window
from kivy.uix.button import Button
from kivy.uix.dropdown import DropDown
from kivy.uix.anchorlayout import AnchorLayout
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.gridlayout import GridLayout
from kivy.uix.scrollview import ScrollView
from kivy.lang.builder import Builder
import base64
import os
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
import json
import pyperclip
import string

Window.clearcolor = (0.188, 0.188, .188, 1)
Window.maximize()
Window.fullscreen = False
displaypassword = ''

class WindowManager(ScreenManager):
	def __init__(self, **kwargs): 
		super(WindowManager, self).__init__(**kwargs)
		with open("passwords.json", 'r') as file:
			'''
			If json file successfully loads,
			It will be stored in raw_credentials.
			Else, raw_credentials will be initialized to an empty dictionary.
			'''
			try:
				self.raw_credentials = json.load(file)
			except:
				self.raw_credentials = {}

		self.alias = ObjectProperty(None)
		self.masterpassword = ObjectProperty(None)
		self.credentials = {}
		self.account_name = ObjectProperty(None)
		self.password = ObjectProperty(None)


	def generate_password(self, size=16, char=string.ascii_uppercase+string.ascii_lowercase+string.digits):
		'''
		Function to generate a character password for a credential
		'''
		gen_pass = ''.join(random.choice(char) for _ in range(size))
		self.password = gen_pass

	def generate_key(self, masterpassword):
		'''
		Function to generate the decrypting key using master password.
		'''
		self.salt = b'yW4\x13m\xb0M\x8a\x84%\nAY={\x16' #random 16 length salt using secrets.token_bytes(16)  
		self.kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=self.salt,
			iterations=100000,
			backend=default_backend()
		)
		return base64.urlsafe_b64encode(self.kdf.derive(self.masterpassword.encode())) # Can only use kdf once

	def make_credentials_list(self):
		present = []
		self.key = self.generate_key(self.masterpassword)
		self.f = Fernet(self.key)
		for keys in self.raw_credentials:
			try:
				self.key = self.generate_key(self.masterpassword)
				self.f = Fernet(self.key)
				self.correct = self.raw_credentials[keys].encode()
				self.correct = self.f.decrypt(self.correct)
				self.correct = self.correct.decode()
				self.credentials.update({keys : self.raw_credentials[keys]})
			except InvalidToken:
				pass
		if len(self.credentials) < 1:
			for i in range(10):
				alias = f"master{str(i)}"
				for keys in self.raw_credentials:
					if alias in keys[:7]:
						if alias not in present:
							present.append(alias)
				else:
					self.alias = "master0"
			self.alias = f"master{str(len(present))}" if len(present) < 10 else None
		else:
			self.alias = list(self.credentials.keys())[0][:7]
		if self.alias == None:
			self.current = "Full"

	def check_existing(self):
		if self.account_name != "":
			for keys in self.credentials:
				if self.account_name == keys[8:]:   #starting from 8 because ther is underscore in the name.
					self.current = "AddOptions"
					break
				else:
					self.current = "PasswordOptions"
			else:
				self.current = "PasswordOptions"
		else:
			pass

	def save_credentials(self):
		self.password = self.password.encode()
		self.password = self.f.encrypt(self.password)
		self.password = self.password.decode('ascii')
		self.credentials.update({(f"{self.alias}_{self.account_name}") : self.password})
		self.raw_credentials.update({(f"{self.alias}_{self.account_name}") : self.password})
		self.password = ObjectProperty(None)
		with open("passwords.json", 'r+') as file:
			json.dump(self.raw_credentials, file)

	def delete_last(self):
		for key in [key for key in self.raw_credentials if key[:7] == "master9"]: del self.raw_credentials[key]

	def copy_credentials_check(self):
		if len(self.credentials) < 1:
			self.current = "NoCredentials"
		else:
			self.current = "CopyCredentials"

	def delete_credentials_check(self):
		if len(self.credentials) < 1:
			self.current = "NoCredentials"
		else:
			self.current = "DeleteCredential"

class MasterpasswordInputWindow(Screen):
	pass

class OptionsWindow(Screen):
	pass

class CreateCredentialWindow(Screen):
	pass

class AddOptionsWindow(Screen):
	pass

class EnterPasswordWindow(Screen):
	pass

class PasswordOptionsWindow(Screen):
	pass

class EnteredPasswordWindow(Screen):
	pass

class FinalAccountWindow(Screen):
	pass

class FullWindow(Screen):
	pass

class CopyCredentialWindow(Screen):
	def __init__(self, **kwargs):
		super(CopyCredentialWindow, self).__init__(**kwargs)
		self.scroll = ScrollView(size_hint=(1, 1), do_scroll_y=True, do_scroll_x=False, scroll_timeout=55, bar_width=10)
		self.grid = GridLayout(cols=1, size_hint_y=None)
		self.grid.bind(minimum_height=self.grid.setter('height'))
	def on_enter(self):
		button_list = []
		for i in self.manager.credentials:
			button_list.append(Button(text=i[8:], size_hint_y=None, height=40, on_release=lambda x, cred=i: self.do_accordingly(cred)))
			self.grid.add_widget(button_list[-1])
		self.scroll.add_widget(self.grid)
		self.ids.grid.add_widget(self.scroll)
	def delete_dropdown(self):
		self.grid.clear_widgets()
		self.scroll.clear_widgets()
		self.ids.grid.remove_widget(self.scroll)
	def do_accordingly(self, account_name):
		credentials = self.manager.credentials
		password = credentials[account_name]
		password = password.encode()
		password = self.manager.f.decrypt(password)
		password = password.decode()
		MyApp.displaypassword = password
		pyperclip.copy(password)
		ok = PopupContent()
		popup = Popup(title='Password Copied', content=ok,
			  auto_dismiss=False, size_hint=(1,1))
		ok.closebutton.bind(on_release=popup.dismiss)
		popup.open()
		self.delete_dropdown()
		self.manager.current = "Options"

class NoCredentialsWindow(Screen):
	pass

class PopupContent(GridLayout):
	def __init__(self, **kwargs):
		super(PopupContent, self).__init__(**kwargs)
		self.closebutton = self.ids.closebutton

class DeleteCredentialWindow(Screen):
	def __init__(self, **kwargs):
		super(DeleteCredentialWindow, self).__init__(**kwargs)
		self.scroll = ScrollView(size_hint=(1, 1), do_scroll_y=True, do_scroll_x=False, scroll_timeout=55, bar_width=10)
		self.grid = GridLayout(cols=1, size_hint_y=None)
		self.grid.bind(minimum_height=self.grid.setter('height'))
	def on_enter(self):
		button_list = []
		for i in self.manager.credentials:
			button_list.append(Button(text=i[8:], size_hint_y=None, height=40, on_release=lambda x, cred=i: self.do_accordingly(cred)))
			self.grid.add_widget(button_list[-1])
		self.scroll.add_widget(self.grid)
		self.ids.grid.add_widget(self.scroll)
	def delete_dropdown(self):
		self.grid.clear_widgets()
		self.scroll.clear_widgets()
		self.ids.grid.remove_widget(self.scroll)
	def do_accordingly(self, account_name):
		self.manager.current = "Options"
		self.delete_dropdown()
		del self.manager.raw_credentials[account_name]
		del self.manager.credentials[account_name]
		with open("passwords.json", 'r+') as file:
			json.dump(self.manager.raw_credentials, file)

class CustomButton(Button):
	pass

class MyApp(App):
	displaypassword = ""
	def build(self):
		return kvfile

kvfile = Builder.load_string(
'''
WindowManager:
	MasterpasswordInputWindow
	OptionsWindow
	CreateCredentialWindow
	AddOptionsWindow
	EnterPasswordWindow
	PasswordOptionsWindow
	FinalAccountWindow
	FullWindow
	CopyCredentialWindow
	NoCredentialsWindow
	DeleteCredentialWindow

<MasterpasswordInputWindow>:
	name: "MasterPasswordInput"
	GridLayout:
		cols: 1
		GridLayout:
			cols: 1
			rows: 3

			AnchorLayout:
				Label:
					text: "Welcome to the Password Locker!"
					font_size: 20
					color: .4, .4, .8, 1
					size_hint: .2, None
					height: 50
			AnchorLayout:
				Label:
					text: "Enter your Masterpassword: "
					font_size: 20
					size_hint: .2, None
					height: 50
			AnchorLayout:
				TextInput:
					id: masterpasswordinput
					multiline: False
					password: True
					size_hint: 0.8, None
					height: 30

		AnchorLayout:
			size_hint: .5, .5
			GridLayout:
				cols: 1
				rows: 2
				Button:
					background_color: .7, .7, .7, .8
					size_hint: 0.6, 0.3
					text: "Submit"
					on_release:
						root.manager.masterpassword = masterpasswordinput.text
						root.manager.credentials = {}
						root.manager.current = "Options" if root.manager.masterpassword != "" else "MasterPasswordInput"
						root.manager.make_credentials_list()
				Button:
					background_color: .7, .7, .7, .8
					size_hint: 0.6, 0.3
					text: "Exit"
					on_release:
						app.get_running_app().stop()

<OptionsWindow>:
	name: "Options"
	GridLayout:
		cols: 1
		rows: 4
		AnchorLayout:
			Button:
				background_color: .7, .7, .7, .8
				text: "Add Credential"
				on_release:
					root.manager.current = "CreateCredential"
		AnchorLayout:
			Button:
				background_color: .7, .7, .7, .8
				text: "Copy Credential"
				on_release:
					root.manager.copy_credentials_check()
		AnchorLayout:
			Button:
				background_color: .7, .7, .7, .8
				text: "Delete Credential"
				on_release:
					root.manager.delete_credentials_check()
		AnchorLayout:
			Button:
				background_color: .7, .7, .7, .8
				text: "Go Back"
				on_release:
					root.manager.current = "MasterPasswordInput"

<CreateCredentialWindow>:
	name: "CreateCredential"
	GridLayout:
		cols: 1
		GridLayout:
			cols: 1
			rows: 3
			AnchorLayout:
				Label:
					text: "Add Credential:"
					font_size: 20
					color: .4, .4, .8, 1
					size_hint: .2, None
					height: 50
			AnchorLayout:
				Label:
					text: "Enter account name: "
					font_size: 20
					size_hint: .2, None
					height: 50
			AnchorLayout:
				TextInput:
					id: accountnameinput
					multiline: False
					size_hint: 0.8, None
					height: 30
		AnchorLayout:
			size_hint: .5, .5
			GridLayout:
				cols: 1
				rows: 2
				Button:
					background_color: .7, .7, .7, .8
					size_hint: 0.6, 0.3
					text: "Submit"
					on_release:
						root.manager.account_name = accountnameinput.text
						root.manager.check_existing()
				Button:
					background_color: .7, .7, .7, .8
					size_hint: 0.6, 0.3
					text: "Go Back"
					on_release:
						root.manager.current = "Options"

<AddOptionsWindow>:
	name: "AddOptions"
	GridLayout:
		cols: 1
		rows: 4
		AnchorLayout:
			Label:
				text: "That account already exists."
				font_size: 20
				color: .4, .4, .8, 1
				size_hint: .2, None
				height: 50
		AnchorLayout:
			Label:
				text: "Do you want to update it?"
				font_size: 20
				size_hint: .2, None
				height: 50
		AnchorLayout:
			Button:
				size_hint: 1, 0.6
				background_color: .7, .7, .7, .8
				text: "Update"
				on_release:
					root.manager.current = "PasswordOptions"
		AnchorLayout:
			Button:
				size_hint: 1, 0.6
				background_color: .7, .7, .7, .8
				text: "Back"
				on_release:
					root.manager.current = "CreateCredential"

<EnterPasswordWindow>
	name: "EnterPassword"
	GridLayout:
		cols: 1
		rows: 4
		AnchorLayout:
			Label:
				text: "Enter Password: "
				font_size: 20
				size_hint: .2, None
				height: 50
		AnchorLayout:
			TextInput:
				id: passwordinput
				password: True
				multiline: False
				size_hint: 0.8, None
				height: 30
		AnchorLayout:
			Button:
				size_hint: 1, 0.6
				background_color: .7, .7, .7, .8
				text: "Submit"
				on_release:
					root.manager.password = passwordinput.text
					root.manager.save_credentials()
					root.manager.current = "FinalAccount"
		AnchorLayout:
			Button:
				size_hint: 1, 0.6
				background_color: .7, .7, .7, .8
				text: "Back"
				on_release:
					root.manager.current = "CreateCredential"

<PasswordOptionsWindow>
	name: "PasswordOptions"
	GridLayout:
		cols: 1
		rows: 4
		AnchorLayout:
			Label:
				text: "Choose:"
				font_size: 20
				size_hint: .2, None
				height: 50
		AnchorLayout:
			Button:
				size_hint: 1, 0.6
				background_color: .7, .7, .7, .8
				text: "Generate Password"
				on_release:
					root.manager.generate_password()
					root.manager.save_credentials()
					root.manager.current = "FinalAccount"
		AnchorLayout:
			Button:
				size_hint: 1, 0.6
				background_color: .7, .7, .7, .8
				text: "Enter Password"
				on_release:
					root.manager.current = "EnterPassword"
		AnchorLayout:
			Button:
				size_hint: 1, 0.6
				background_color: .7, .7, .7, .8
				text: "Back"
				on_release:
					root.manager.current = "CreateCredential"

<FinalAccountWindow>:
	name: "FinalAccount"
	GridLayout:
		cols: 1
		rows: 2
		AnchorLayout:
			Label:
				text: "Account Created Successfully."
				font_size: 20
				color: .4, .4, .8, 1
				size_hint: .2, None
				height: 50
		AnchorLayout:
			Button:
				size_hint: 1, 0.6
				background_color: .7, .7, .7, .8
				text: "OK"
				on_release:
					root.manager.current = "Options"

<FullWindow>
	name: "Full"
	GridLayout:
		cols: 1
		rows: 3
		AnchorLayout:
			Label:
				text: "Master Passwords out of Limit!"
				font_size: 20
				color: .4, .4, .8, 1
				size_hint: .2, None
				height: 50
		AnchorLayout:
			Button:
				size_hint: 0.6, 0.3
				background_color: .7, .7, .7, .8
				text: "Delete last master password"
				on_release:
					root.manager.delete_last()
					root.manager.current = "MasterPasswordInput"
		AnchorLayout:
			Button:
				size_hint: 0.6, 0.3
				background_color: .7, .7, .7, .8
				text: "Back"
				on_release:
					root.manager.current = "MasterPasswordInput"

<CopyCredentialWindow>:
	name: "CopyCredentials"
	GridLayout:
		id: grid
		cols: 1
		AnchorLayout:
			Button:
				text: ("Click here to Go Back\\nSelect account to copy:")
				font_size: 20
				color: .4, .4, .8, 1
				on_release:
					root.manager.current = "Options"
					root.delete_dropdown()

<NoCredentialsWindow>:
	name: "NoCredentials"
	GridLayout:
		cols: 1
		rows: 3
		AnchorLayout:
			anchor_y: 'bottom'
			Label:
				text: "There are no accounts stored"
				font_size: 20
				color: .4, .4, .8, 1
				size_hint: .2, None
				height: 50
		AnchorLayout:
			anchor_y: 'top'
			Label:
				text: "for that masterpassword."
				font_size: 20
				color: .4, .4, .8, 1
				size_hint: .2, None
				height: 50
		AnchorLayout:
			Button:
				text: "OK"
				font_size: 20
				size_hint: 1, 0.6
				on_release:
					root.manager.current = "Options"

<PopupContent>:
	size_hint: 1, 1
	cols: 1
	rows: 2
	AnchorLayout
		Label:
			text: f"Your password for that account is\\n'{app.displaypassword}'.\\nIt is copied to your clipboard."
	AnchorLayout:
		Button:
			size_hint_y: 0.2
			size_hint_x: 0.8
			id: closebutton
			text: 'OK'

<DeleteCredentialWindow>:
	name: "DeleteCredential"
	GridLayout:
		id: grid
		cols: 1
		AnchorLayout:
			Button:
				text: "Click here to Go Back\\nSelect account to Delete:"
				font_size: 20
				color: .4, .4, .8, 1
				on_release:
					root.manager.current = "Options"
					root.delete_dropdown()
'''
	)

if __name__ == "__main__":
	MyApp().run()
