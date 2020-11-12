import sys
try:
	from Crypto.Cipher import DES as des
except ImportError as error:
	print("\nImport Error: Please install pycrypto")
	if sys.version[0] == '2':
		version = ""
	if sys.version[0] == '3':
		version = "3"
	print("Example: sudo pip"+version+ " install pycrypto")
	quit()
import binascii
import os

class DES():

	def setKey(self, key):
		if len(key) == 16:
			try:
				self.key = str(binascii.unhexlify(key))
				return True
			except:
				print("Error: Non-hexadecimal digit found")
				return False
		print("Error: Key length = "+str(len(key))+", Key length must be 16 hex characters long")
		return False

	def setIV(self, isEncryption):
		blockBytes = 8
		IVchoice = None
		while IVchoice != 'y' and IVchoice != 'n':
			IVchoice = raw_input("Do you want to enter your own Initialization Vector (Y/N): ").lower()
		if IVchoice == 'y':
			validIV = False
			while not validIV:
				self.IV = raw_input("Enter IV as "+str(blockBytes*2)+" hex characters: ").replace(" ", "")
				while len(self.IV) != blockBytes*2:
					self.IV = raw_input("Length of IV must be 16, try again: ").replace(" ", "")
				try:
					self.IV = binascii.unhexlify(self.IV)
					validIV = True
				except:
					print("Invalid IV: Non-hex character detected")
			return True
		else:
			if isEncryption:
				self.IV = os.urandom(blockBytes) #Get 8 random bytes
				print("Randomly Generated IV: " + binascii.hexlify(self.IV))
			return False

	def encrypt(self, plainText):
		cipherText = ""
		des_encrypt = des.new(self.key, des.MODE_ECB)

		#Padding in format of: '\x03 \x03 \x03
		padNum = 8 - len(plainText) % 8
		while len(plainText) % 8 != 0:
			plainText += chr(padNum) #Add padding character

		for index in range(0, len(plainText), 8):
			cipherText += des_encrypt.encrypt(plainText[index:index+8])

		return cipherText

	def decrypt(self, cipherText):
		plainText = ""
		des_decrypt = des.new(self.key, des.MODE_ECB)

		for index in range(0, len(cipherText), 8):
			plainText += des_decrypt.decrypt(cipherText[index:index+8])

		return self.removePadding(plainText)

	def encryptCBC(self, plainText):
		cipherText = ""
		if not self.setIV(True):
			#IV was generated so store in first bytes of cipherText
			cipherText += str(self.IV)

		des_encrypt = des.new(self.key, des.MODE_ECB)

		#Padding in format of: '\x03 \x03 \x03
		padNum = 8 - len(plainText) % 8
		while len(plainText) % 8 != 0:
			plainText += chr(padNum) #Add padding character

		plainTextBlock = ""
		for index in range(0, 8):
			#XOR IV with first block of Text (8 bytes)
			plainTextBlock += chr(ord(self.IV[index]) ^ ord(plainText[index]))

		for index in range(0, len(plainText), 8):
			cipherBlock = des_encrypt.encrypt(plainTextBlock)
			cipherText += cipherBlock

			if index+8 < len(plainText):
				XOR = [None] * 8
				plainTextBlock = plainText[index+8:index+16]
				#Next Round: XOR cipherBlock with plaintextBlock
				for element in range(0, len(cipherBlock)):
					XOR[element] = chr(ord(cipherBlock[element]) ^ ord(plainTextBlock[element]))

				plainTextBlock = "".join(XOR)

		return cipherText

	def decryptCBC(self, cipherText):
		plainText = ""
		if not self.setIV(False):
			#This means the IV is stored in the cipherText
			self.IV = cipherText[0:8] #Grab IV from cipherText
			cipherText = cipherText[8:] #Remove IV from cipherText

		des_decrypt = des.new(self.key, des.MODE_ECB)

		for index in range(0, len(cipherText), 8):
			plainTextBlock = des_decrypt.decrypt(cipherText[index:index+8])

			if index == 0:
				#Now take first block of IV and XOR with output of decryption
				XOR = [None] * 8
				for element in range(0, 8):
					XOR[element] = chr(ord(self.IV[element]) ^ ord(plainTextBlock[element]))
				plainText += "".join(XOR)

			elif index+8 <= len(cipherText):
				Block = [None] * 8
				#Next Round: XOR cipherBlock with plaintextBlock
				for element in range(0, len(cipherBlock)):
					Block[element] = chr(ord(cipherBlock[element]) ^ ord(plainTextBlock[element]))

				plainText += "".join(Block)

			cipherBlock = cipherText[index:index+8]

		return self.removePadding(plainText)

	def encryptCFB(self, plainText):
		cipherText = ""
		des_encrypt = des.new(self.key, des.MODE_ECB)
		if not self.setIV(True):
			#IV was generated so store in first bytes of cipherText
			cipherText += str(self.IV)

		for char in plainText:
			o = des_encrypt.encrypt(self.IV)
			cipherText += chr(ord(o[0]) ^ ord(char))
			self.IV = self.IV[1:] + cipherText[len(cipherText)-1]

		return cipherText


	def decryptCFB(self, cipherText):
		plainText = ""
		des_encrypt = des.new(self.key, des.MODE_ECB)
		if not self.setIV(False):
			#This means the IV is stored in the cipherText
			self.IV = cipherText[0:8] #Grab IV from cipherText
			cipherText = cipherText[8:] #Remove IV from cipherText

		for char in cipherText:
			o = des_encrypt.encrypt(self.IV)
			plainText += chr(ord(o[0]) ^ ord(char))
			self.IV = self.IV[1:] + char

		return plainText

	def removePadding(self, plainText):
		padNum = ord(plainText[-1])
		padChar = plainText[-1]
		isPadding = False
		if padNum > 0 and padNum < 8:
			if padNum == 1 and plainText[-2] != padChar:
				#If only one padding character
				return plainText[:len(plainText)-1]
			isPadding = True
			for index in range(2, padNum):
				if plainText[-index] != padChar:
					isPadding = False
		if isPadding:
			return plainText[:len(plainText)-padNum]
		return plainText