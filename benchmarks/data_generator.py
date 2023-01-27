from random import choice
characters = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"]

def generate_hex(l):
	str1 = ""
	for _ in range(l):
		str1 += choice(characters)
	return str1

number = 5
iv = []
for _ in range(number):
	iv.append(generate_hex(32))	

key = []
for _ in range(number):
	key.append(generate_hex(32))

ad = []
for i in range(number):
	ad.append(generate_hex(choice(range(2, 1000, 2))))

pt = []
for i in range(number):
	pt.append(generate_hex(choice(range(2, 1000, 2))))

print("iv =", iv)
print("key =", key)
print("ad =", ad)
print("pt =", pt)
