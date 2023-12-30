import ctypes
from ctypes import cdll
lib = cdll.LoadLibrary('./aeslib.so')

class Aes(ctypes.Structure):
    pass

lib.AES256.argtypes = ctypes.POINTER(ctypes.c_ubyte), 
lib.AES256.restype = ctypes.POINTER(Aes)
lib.AES256EncryptBlock.argtypes = ctypes.POINTER(Aes), ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)
lib.AES256EncryptBlock.restype = ctypes.POINTER(ctypes.c_ubyte)

class AES256HW(object):
    def __init__(self, key):
        raw_key = (ctypes.c_ubyte * len(key)).from_buffer(bytearray(key))
        self.obj = lib.AES256(raw_key)

    def encrypt(self, data, iv):
        raw_data = (ctypes.c_ubyte * len(data))(*data)
        raw_iv = (ctypes.c_ubyte * len(iv))(*iv)
        lib.AES256EncryptBlock(self.obj, len(data), raw_data, raw_iv)
    
    def decrypt(self, data, iv):
        lib.AES256DecryptBlock(self.obj, len(data), data, iv)