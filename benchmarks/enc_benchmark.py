from time import time

from aegis_128 import encrypt, decrypt

from enc_vectors import *

for p in pt:
	for a in ad:
		start = time()
		for k in key:
			for i in iv:
				encrypt(k, i, a, p)
		stop = time()
		print("Dł. wiadomości:", len(p), "\nDł. dodatkowych danych:", len(a), "\nCzas:", stop-start, "\nLiczba szyfrowań:", len(iv)*len(key), "\nŚredni czas szyforwania:", (stop-start)/(len(iv)*len(key)))
