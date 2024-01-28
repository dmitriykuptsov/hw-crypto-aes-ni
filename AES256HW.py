import ctypes
from ctypes import cdll
from array import array

lib = cdll.LoadLibrary('./aeslib.so')

class Aes(ctypes.Structure):
    pass

lib.freeme.argtypes = ctypes.POINTER(ctypes.c_ubyte),
lib.AES256.argtypes = ctypes.POINTER(ctypes.c_ubyte), 
lib.AES256.restype = ctypes.c_void_p #ctypes.POINTER(Aes)
lib.AES256EncryptBlock.argtypes = ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)
lib.AES256EncryptBlock.restype = ctypes.POINTER(ctypes.c_ubyte)
lib.AES256DecryptBlock.argtypes = ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)
lib.AES256DecryptBlock.restype = ctypes.POINTER(ctypes.c_ubyte)

class AES256CBCCipher():

	BLOCK_SIZE = 16;
	
	"""
	Advanced Encryption Standard
	"""
	def __init__(self):
		pass

	def encrypt(self, key, iv, data):
		"""
		Encryptes the plaintext using
		"""
		v = array('B',key);pkey = (ctypes.c_ubyte * len(v)).from_buffer(v)
		obj = lib.AES256(pkey)
		v = array('B',data);pdata = (ctypes.c_ubyte * len(v)).from_buffer(v)
		v = array('B',iv);piv = (ctypes.c_ubyte * len(v)).from_buffer(v)
		addr = lib.AES256EncryptBlock(obj, len(data), pdata, piv)

		ciphertext = ctypes.string_at(addr, len(data))
		lib.freeme(addr);
		lib.freeme(ctypes.cast(obj, ctypes.POINTER(ctypes.c_ubyte)))
		return ciphertext

	def decrypt(self, key, iv, data):
		"""
		This method decryptes the ciphertext
		"""
		v = array('B',key);pkey = (ctypes.c_ubyte * len(v)).from_buffer(v)
		obj = lib.AES256(pkey)
		v = array('B',data);pdata = (ctypes.c_ubyte * len(v)).from_buffer(v)
		v = array('B',iv);piv = (ctypes.c_ubyte * len(v)).from_buffer(v)
		addr = lib.AES256DecryptBlock(obj, len(data), pdata, piv)
		plaintext = ctypes.string_at(addr, len(data))
		lib.freeme(addr);
		lib.freeme(ctypes.cast(obj, ctypes.POINTER(ctypes.c_ubyte)))
		return plaintext
