#!/usr/bin/env python
import sys
import os
from DES import DES
from AES import AES
if sys.version[0] == '3':
	print("Warning: Python 3.X currently not supported.")
	print("Try again running Python 2.X")
	quit()

def main(*arguments):
	#Display instructions if improper argument length is given
	if len(arguments) != 6 and len(arguments) != 7:
		print("\nINVALID ARGUMENTS:")
		print("./cipher <CIPHER NAME> <KEY> <ENC/DEC> <INPUTFILE> <OUTPUT FILE> <--OPTIONS/-O>")
		print("\n\tSupported Ciphers:")
		print("\t- DES: Indicates the 64bit DES cipher")
		print("\t- DES-CBC: DES Cipher in CBC Mode\n\t- DES-CFB: DES Cipher in CFB Mode\n")
		print("\t- AES: Indicates 128bit AES cipher")
		print("\t- AES-CBC: AES Cipher in CBC Mode\n\t- AES-CFB: AES Cipher in CFB Mode")
		print("\n\t--OPTIONS - Optional setting: If enabled will ask for converting\n\t\tto lowercase and removing non-alpha characters\n")
		quit()
	
	cipherName = arguments[1].upper()
	key = arguments[2].replace(" ", "")
	encOrDec = arguments[3].upper()
	inFile = arguments[4]
	outFile = arguments[5]
	
	try:
		#Check if option is specified
		opt = arguments[6].upper()
	except:
		opt = None
	
	if opt == "--OPTIONS" or opt == "-O":
		#ask for options
		options = [None] * 2
		while options[0] != 'y' and options[0] != 'n':
			if sys.version[0] == '3':
				options[0] = input("Strip input file of non alphabetical characters? (Y/N): ").lower()
			elif sys.version[0] == '2':
				options[0] = raw_input("Strip input file of non alphabetical characters? (Y/N): ").lower() 
		while options[1] != 'y' and options[1] != 'n': 
			if sys.version[0] == '3':
				options[1] = input("Convert to lower case? (Y/N): ").lower()
			elif sys.version[0] == '2':
				options[1] = raw_input("Convert to lower case? (Y/N): ").lower()
	else:
		options = ['n', 'n'] #set options to no

	try:
		#Open data from inputString file
		with open(inFile,"r") as f:
			if options[0] == options[1] == 'n':
				#Both no
				inputString = f.read()
			elif options[0] == 'n':
				#lower case
				inputString = f.read().lower()
			elif options[1] == 'n':
				#strip non-alpha
				inputString = ''.join([c for c in f.read() if c.isalpha()])
			else:
				#strip non-alpha characters and lower case
				inputString = ''.join([c.lower() for c in f.read() if c.isalpha()])
	except:
		print("\nError: Input file \""+inFile+"\" doesn't exist")
		quit()
			
	if cipherName == "DES":
		cipher = DES()
		if cipher.setKey(key):
			if encOrDec == "ENC":
				output = cipher.encrypt(inputString)
			elif encOrDec == "DEC":
				output = cipher.decrypt(inputString)
			else:
				print("Invalid Encryption/Decryption Option")
				quit()
		else:
			print("Failure: Invalid Key")
			quit()
	
	elif cipherName == "DES-CBC":
		cipher = DES()
		if cipher.setKey(key):
			if encOrDec == "ENC":
				output = cipher.encryptCBC(inputString)
			elif encOrDec == "DEC":
				output = cipher.decryptCBC(inputString)
			else:
				print("Invalid Encryption/Decryption Option")
				quit()
		else:
			print("Failure: Invalid Key")
			quit()
	
	elif cipherName == "DES-CFB":
		cipher = DES()
		if cipher.setKey(key):
			if encOrDec == "ENC":
				output = cipher.encryptCFB(inputString)
			elif encOrDec == "DEC":
				output = cipher.decryptCFB(inputString)
			else:
				print("Invalid Encryption/Decryption Option")
				quit()
		else:
			print("Failure: Invalid Key")
			quit()
	
	elif cipherName == "AES":
		cipher = AES()
		if cipher.setKey(key):
			if encOrDec == "ENC":
				output = cipher.encrypt(inputString)
			elif encOrDec == "DEC":
				output = cipher.decrypt(inputString)
			else:
				print("Invalid Encryption/Decryption Option")
				quit()
		else:
			print("Failure: Invalid Key")
			quit()
	
	elif cipherName == "AES-CBC":
		cipher = AES()
		if cipher.setKey(key):
			if encOrDec == "ENC":
				output = cipher.encryptCBC(inputString)
			elif encOrDec == "DEC":
				output = cipher.decryptCBC(inputString)
			else:
				print("Invalid Encryption/Decryption Option")
				quit()
		else:
			print("Failure: Invalid Key")
			quit()
	
	elif cipherName == "AES-CFB":
		cipher = AES()
		if cipher.setKey(key):
			if encOrDec == "ENC":
				output = cipher.encryptCFB(inputString)
			elif encOrDec == "DEC":
				output = cipher.decryptCFB(inputString)
			else:
				print("Invalid Encryption/Decryption Option")
				quit()
		else:
			print("Failure: Invalid Key")
			quit()
			
	else:
		print("\nError: Cipher not supported. Please check the name again.")
		quit()
		
	print("\nINPUT: ")
	print(inputString)
		
	print("\nOUTPUT: ")
	print(output)
	with open(outFile, "w+") as f:
		f.write(output)
		print("\nSuccess!")

if __name__ == '__main__':
	main(*sys.argv)
