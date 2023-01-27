from time import time

from aegis_128 import encrypt, decrypt

from enc_vectors import *
from dec_vectors import *


for c in range(len(ct)):
	for a in range(len(ad)):
		start = time()
		for k in range(len(key)):
			for i in range(len(iv)):
				decrypt(key[k], iv[i], ad[a], ct[k][i][a][c], tag[k][i][a][c])
		stop = time()
		print("Dł. szyfrogramu:", len(ct[0][0][0][c]), "\nDł. dodatkowych danych:", len(ad[a]), "\nCzas:", stop-start, "\nLiczba deszyfrowań:", len(iv)*len(key), "\nŚredni czas deszyforwania:", (stop-start)/(len(key)*len(iv)))
