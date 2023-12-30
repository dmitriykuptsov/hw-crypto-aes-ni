from AES256HW import AES256HW
key  = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
cipher = AES256HW(key)
iv = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
data = [0] * 16 * 1024 * 1024
from time import time
s = time()
cipher.encrypt(data, iv)
e = time()
print((e-s))