import sys
import collections

def createDict(key):
	od = collections.OrderedDict()
	keyStart = ord(key.lower())
	for num in range(26):
		if (keyStart + num) > 122:
			od[chr(97 + num)] = chr((keyStart + num) - 122 + 96)
		else: 
			od[chr(97 + num)] = chr(keyStart + num)
	return od

def encrypt(plainText, od):
	cipherText = []
	for character in plainText:
		characterLower = character.lower()
		if (ord(characterLower) > 97) and (ord(characterLower) < 122):
			cipherText.append(od[characterLower])
		elif (ord(character) == 32) or (ord(character) == 33 or \
			(ord(character) == 44) or (ord(character) == 63)):
			pass
		else:
			cipherText.append(character)
	return "".join(cipherText)

def decrypt(cipherText, od):
	plainText = []
	newDict = collections.OrderedDict((v,k) for k,v in od.iteritems())
	for character in cipherText:
		if (ord(character) > 97) and (ord(character) < 122):
			plainText.append(newDict[character])
		else:
			plainText.append(character)
	return "".join(plainText)

def unique(inString):
	newSet = set()
	for c in inString:
		newSet.add(c)
	return newSet

while(1):
	print "Welcome to the Caesarian Shift Encryption/Decryption device"
	print "(E/e) Encrypt | (D/d) Decrypt | (Ex/ex) Exit"
	line = raw_input("")

	if line == "E" or line == "e":
		key = raw_input("Input the key: ")
		od = createDict(key)
		plainText = raw_input("Input the message to be encrypted: ")
		print encrypt(plainText, od)
	elif line == "D" or line == "d":
		key = raw_input("Input the key: ")
		od = createDict(key)
		cipherText = raw_input("Input the message to be decrypted: ")
		plainText = []
		print decrypt(cipherText, od)
	elif line == "Ex" or line == "ex":
		exit() 

	else:
		print "Invalid command"