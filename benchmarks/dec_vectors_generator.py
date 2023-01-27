from aegis_128 import encrypt, decrypt

from enc_vectors import *

ct = []
tag = []
for k in range(len(key)):
	ct.append([])
	tag.append([])
	for i in range(len(iv)):
		ct[k].append([])
		tag[k].append([])
		for a in range(len(ad)):
			ct[k][i].append([])
			tag[k][i].append([])
			for p in range(len(pt)):
				tmp = encrypt(key[k], iv[i], ad[a], pt[p])
				ct[k][i][a].append(tmp[0])
				tag[k][i][a].append(tmp[1])
				
print("ct =", ct, "\ntag =", tag)
