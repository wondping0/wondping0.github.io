# WRITEUP TCP1PCTF 2023
## Crypto
### Cherry Leak
```python 
# cherry.py
from Crypto.Util.number import getPrime, bytes_to_long

p = getPrime(1024)
q = getPrime(512)
n = p * q
e = 65537

FLAG = b"TCP1P{???????????????????????????????????????}"

lock = False
while True:
    print("1. Get new prime")
    print("2. Get leak")
    print("3. Get flag")
    print("4. Exit")
    print("> ", end="")
    try:
        choice = int(input())
    except:
        break
    if choice == 1:
        if lock:
            print("You can't do that anymore!")
            continue
        print("which prime? (p/q)")
        print("> ", end="")
        prime = input()
        if prime == "p":
            p = getPrime(1024)
        elif prime == "q":
            q = getPrime(512)
        else:
            print("What?")
            continue
        n = p * q
        lock = True
    elif choice == 2:
        print("choose leak p ? q (+-*/%)")
        print("> ", end="")
        leak = input()
        if leak == "+":
            print(f"p + q = {pow(p + q, e, n)}") # nuh uh
        elif leak == "-":
            print(f"{p - q = }")
        elif leak == "*":
            print(f"p * q = {pow(p * q, e, n)}") # nuh uh
        elif leak == "/":
            print(f"p // q = {pow(p // q, e, n)}") # nuh uh
        elif leak == "%":
            print(f"{p % q = }")
        else:
            print("What?")
    elif choice == 3:
        print(f"c = {pow(bytes_to_long(FLAG), e, n)}")
        lock = True
    elif choice == 4:
        break
    else:
        print("What?")
```
Dari soal, kita bisa mendapatkan leak information dari $p-q$ dan $p{\space}mod{\space}q$. Kemudian kita juga bisa mengganti nilai $p$ sekali dan request $ciphertext$. Urutan $choice$ dan $input$ yaitu: $2, - , 2 , \% , 1 , p , 2 , - , 2 , \% , 3$. Kemudian untuk mendapatkan flag akan mencari nilai dari $q$.
$$x=p{\space}mod{\space}q$$$$p=kq+x$$$$y=p-q$$$$y=kq+x-q$$$$y-x=(ki-1)q$$$$ki-1=Integer$$
Untuk kasus $p$ yang berbeda akan mendapatkan nilai dari $k1$ dan $k2$ yang berbeda namun nilai $q$ sama. Jadi kita lakukan $gcd$ untuk mendapatkan nilai $q$.
$$q = gcd(y1-x1,y2-x2)$$
Setelah mendapatkan nilai $q$ bisa kita dapatkan flagnya.
```python
# solver.py
from pwn import *
import math
from Crypto.Util.number import *

io = remote("ctf.tcp1p.com","13339")

def getLeak():
    io.recvuntil(b'> ')
    io.sendline(b'2')
    io.recvuntil(b'> ')
    io.sendline(b'-')
    io.recvuntil(b"p - q = ")
    pminq = int(io.recvline().decode().strip())
    
    io.recvuntil(b'> ')
    io.sendline(b'2')
    io.recvuntil(b'> ')
    io.sendline(b'%')
    io.recvuntil(b"p % q = ")
    pmodq = int(io.recvline().decode().strip())
    return pminq, pmodq

if __name__ == "__main__":
    c1,m1 = getLeak()
    e = 65537
    io.recvuntil(b"> ")
    io.sendline(b'1')
    io.recvuntil(b"> ")
    io.sendline(b'p')
    c2,m2 = getLeak()
    # print(c1,m2)
    q = math.gcd(c1-m1, c2-m2)
    p = q+c2
    
    io.recvuntil(b"> ")
    io.sendline(b'3')
    io.recvuntil(b"c = ")
    cc = int(io.recvline().decode().strip())
    phi = (p-1)*(q-1)
    d = pow(e, -1, phi)
    flag = long_to_bytes(pow(cc, d, p*q))
    print(flag)
```
> TCP1P{in_life's_abundance_a_fragment_suffices}
---
### Final Consensus
```python
# chall.py
from Crypto.Cipher import AES
import random
from Crypto.Util.Padding import pad

a = b""
b = b""
FLAG = b"TCP1P{REDACTED}"

def generateKey():
	global a, b
	a = (str(random.randint(0, 999999)).zfill(6)*4)[:16].encode()
	b = (str(random.randint(0, 999999)).zfill(6)*4)[:16].encode()

def encrypt(plaintext, a, b):
	cipher = AES.new(a, mode=AES.MODE_ECB)
	ct = cipher.encrypt(pad(plaintext, 16))
	cipher = AES.new(b, mode=AES.MODE_ECB)
	ct = cipher.encrypt(ct)
	return ct.hex()

def main():
	generateKey()
	print("Alice: My message", encrypt(FLAG, a, b))
	print("Alice: Now give me yours!")
	plain = input(">> ")
	print("Steve: ", encrypt(plain.encode(), a, b))
	print("Alice: Agree.")


if __name__ == '__main__':
	main()
```
Dalam soal ini digunakan skema enkripsi AES dua kali dengan kunci $a$ dan $b$. Namun terdapat kelemahan pada generate kunci yaitu nilai $a$ dan $b$ cukup kecil yaitu urang dari 999999. Sehingga mudah dilakukan bruteforce. 
$$C1=AES(a, plaintext)$$$$C=AES(b, C1)$$
Jika dilakukan bruteforce masing-masing kunci akan lama maka digunakan meet in the middle attack.
$$x=Enc(a,plaintext)$$$$x=Dec(b,C)$$
kunci ditemukan ketika nilai x sama.
```python
# solver.py
from Crypto.Cipher import AES
import random
from Crypto.Util.Padding import pad
from pwn import *

io = remote("ctf.tcp1p.com","35257")

dcts = set()
mems = {}

plaintext = b'partai'

io.recvuntil(b"Alice: My message ")
flagcip = bytes.fromhex(io.recvline().decode().strip())
io.recvuntil(b">> ")
io.sendline(plaintext)
io.recvuntil(b"Steve: ")
cts = bytes.fromhex(io.recvline().decode().strip())

for i in range(999999):
    a = (str(i).zfill(6)*4)[:16].encode()
    cipher = AES.new(a, mode=AES.MODE_ECB)
    enc = cipher.encrypt(pad(plaintext, 16))
    dcts.add(enc)
    mems[enc] = i

print("ONes complete")

keya = -1
keyb = -1
for i in range(999999):
    a = (str(i).zfill(6)*4)[:16].encode()
    cipher = AES.new(a, mode=AES.MODE_ECB)
    dec = cipher.decrypt(cts)
    if(dec in dcts):
        print("Founds!!")
        keya = mems[dec]
        keyb = i
        break

print("Done!!")
aa = (str(keya).zfill(6)*4)[:16].encode()
bb = (str(keyb).zfill(6)*4)[:16].encode()
cipher1 = AES.new(bb, mode=AES.MODE_ECB)
ct = cipher.decrypt(flagcip)
cipher2 = AES.new(aa, mode=AES.MODE_ECB)
flag = cipher2.decrypt(ct)
print(flag)
```
> TCP1P{nothing_ever_lasts_forever_everybody_wants_to_rule_the_world}
### One Pad Time
```python
import os
from pwn import xor
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = os.urandom(16)
iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv)

pt = open("flag.txt", "rb").read()
ct = pad(cipher.encrypt(pt), 16)
ct = xor(ct, key)
print(f"{iv = }")
print(f"{ct = }")
```
Jika diperhatikan pada soal skema yang digunakan adalah menggunakan AES CBC kemudian dilakukan xor dengan kunci yang sama. Namun dilihat pada line:
```python
ct = pad(cipher.encrypt(pt), 16)
ct = xor(ct, key)
```
sebelum dilakukan xor untuk ciphertext ditambahkan padding, dari sini kita tahu untuk ciphertext sendiri sudah memiliki panjang 16 bytes karena output dari AES. Pada fungsi $pad$ jika panjang sudah 16 bytes padding yang dihasilkan adalah:
```python
padded = b'\x10'*16
```
karena panjang key juga 16 bytes maka kita bisa melakukan recover key dengan melakukan xor dari 16 byte terakhir dari ciphertext dengan padding.
$$key=xor(padded, ciphertext[:16])$$
```python
# solver.py
import os
from pwn import xor
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

iv = b'\xf5\x8e\x85ye\xc8j(%\xc4K\xc1g#\x86\x1a'
ct = b'h\x08\xafmDV\xaa\xcd\xea\xe9C\xdd7/\x1fF\xe2?\xcb\xb0\x1d F\xcc\xe5\xa6\x9dTJ\\\xd1\x90\xac\xe0\x1c\x891}\x83*\x86\xee\xc4~\xa0\x18\xa8\x06\xea"{|\x0b\x92[\x9a[\x91\xc8\x19\xb7FK\x01\xb5\xf98\x80\x9bR)2\x84`\xb3E\t\xd5\xe5\xf0[\x83\xc6\x19\x82\r\x7f\xfaGF\xdb\xcb\xab\xd5~\x95\t\xdd\xb5E>F\xdd\xa9\xa6\x82\x86\xee"\x99\xd9\xcc\xaf\xce\xf0\'\xb3\xf4~\xcf\xdb\xc8\xbd3\x01\xd0,}]\xd5V\xd3?\xb0\xe7\xb4[4\x8a\xa2[\xa1TV\xd16\x1f\xbd"\xc8\xa2\\K\x16I%\xdaL\xc6\xfb\xb7f.\x98\xc3\xf4J\x1b\xe9TT\x83-\x98BO\xb4\x00~\xb5w\xcf7m\xa1\xea\xa9\xf6\xa6\xee\x00Y\xdfE\x9c7\xe3\xa3\xa2\x1f=.\x85\x08l\xacN\xfb2\x89\x8bB\x7f\x94\x91p\x10ep\x9b\x06oz\x87&U]J\x019\x12W\xce<\xc8\xa8\xb4v\xaf,\xb1n\x8b\xf5\xfe\xf8\r\xa7:r\xe8\xe0fvKN\\\xea\xe0\xa1\xe3\x99\xcc\xfd\x1a\x99Q\x90\xdf}\xae\xad'

last_pad = b'\x10'*16
key = xor(ct[-16:],last_pad)

rt = unpad(xor(key, ct),16)

cipher = AES.new(key, AES.MODE_CBC, iv)
flag = cipher.decrypt(rt)
print(flag)
```
> TCP1P{why_did_the_chicken_cross_the_road?To_ponder_the_meaning_of_life_on_the_other_side_only_to_realize_that_the_road_itself_was_an_arbitrary_construct_with_no_inherent_purpose_and_that_true_enlightenment_could_only_be_found_within_its_own_existence_1234}
---
### Spider Shambles
```python
import os
from flask import Flask, flash, request, redirect, render_template, send_file
import io
import random
from Crypto.Util.number import long_to_bytes as l2b

app=Flask(__name__, template_folder='./template')

app.secret_key = "OFCOURSETHISISNOTHEREALSECRETKEYBOI"
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024


ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def xor(a, b):
    return b''.join([bytes([_a ^ _b]) for _a, _b in zip(a, b)])

def encropt(buff):
    rand = random.getrandbits(len(buff)*8)
    return xor(buff, l2b(rand))


@app.route('/', methods=['GET'])
def upload_form():
    return render_template('./upload.html')


@app.route('/', methods=['POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No file selected for uploading')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            buff = io.BytesIO()
            buff.write(encropt(file.read()))
            buff.seek(0)
            return send_file(
                buff,
                mimetype="text/plain",
                as_attachment=True,
                download_name='lalalalululu')
        else:
            flash('Allowed file types are txt, pdf, png, jpg, jpeg, gif')
            return redirect(request.url)

@app.route('/flago', methods=['GET'])
def send_flago():
    flago = open('sec.txt', 'rb')
    buff = io.BytesIO()
    buff.write(encropt(flago.read()))
    buff.seek(0)
    return send_file(
        buff,
        mimetype="text/plain",
        as_attachment=True,
        download_name='babababububu')

if __name__ == "__main__":
    app.run(host = '0.0.0.0',port = 5000, debug = False)
```
Diberikan sebuah web server dengan python dan kita bisa melakukan enkripsi file didalamnya. Fungsi encrypt dalam soal yaitu:
```python
def encropt(buff):
    rand = random.getrandbits(len(buff)*8)
    return xor(buff, l2b(rand))
```
Fungsi tersebut hanya melakukan xor dengan random number yang digenerate pada module random python. Module random pada python menggunakan pseudorandom Mersenne Twister. Algoritma ini bisa di predict setelah didapatkan 624 * 32 bit output.
Saya menggunakan randcracker untuk melakukan predict dari link https://github.com/tna0y/Python-random-module-cracker
Jadi pendekatan yang dilakukan adalah:
1. Input file sebanyak (624 * 32)/8 bytes
2. Mendapatkan random/output Mersenne dari $xor(inputFile, outputFile)$
3. Memasukkan hasil xor pada randcracker dan melakukan predict sebanyak: $len(flag) * 8$.
4. Flag = $xor(predict, Flagcipher)$
Untuk validasi dari langkah pertama jumlah bit yang dibutuhkan adalah sebanyak 19968 ~ 1024 * 19.
```python
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
```
karena rule diatas memenuhi maka bisa dilakukan satu kali mengirim file. Saya menggunakan format file txt dengan isi sbb:
```python
# dump.py > dump.txt
'a'*((624 * 32)//8)
```
Setelah membuat dump/txt dilakukan pengiriman dan mendapatkan predict number dan flag didapatkan.
```python
# solver.py
from randcrack import RandCrack
import requests
from Crypto.Util.number import bytes_to_long as btl, long_to_bytes as ltb
import random

rc = RandCrack()

def xor(a, b):
    return b''.join([bytes([_a ^ _b]) for _a, _b in zip(a, b)])

url = "http://ctf.tcp1p.com:54734"
# url = "http://127.0.0.1:5000"

flagurl = url + '/flago'

with open("dump.txt", "rb") as a_file:
    file_dict = {"file": a_file}
    response = requests.post(url, files=file_dict, allow_redirects=True)
    output = response.content
    print(output)
    db = []
    for j in range(0,len(output),4):
        less = output[j:j+4]
        db.append(btl(xor(less, b'aaaa')))
    db = db[::-1]
    for j in db:
        rc.submit(j)
    # checkpredict
    # latih = btl(xor(output, b'aaaa'))
    # if(i<624):
    #     rc.submit(latih)
    #     print(latih)
    # else:
    #     gues = rc.predict_getrandbits(32)
    #     assert latih == gues
    #     print(gues)
with open("dep.txt", "rb") as a_file:
    file_dict = {"file": a_file}
    response = requests.post(url, files=file_dict, allow_redirects=True)
    output = response.content
    latih = btl(xor(output, b'aaaa'))
    print(latih)
    print(rc.predict_getrandbits(32))

response = requests.get(flagurl, allow_redirects=True)
bdata = response.content
lls = len(bdata)*8
print(lls%32)
# ran = rc.predict_getrandbits(lls*8)
# print(ran)
key = ''
for i in range(lls//32):
    key = bin(rc.predict_getrandbits(32))[2:].zfill(32) + key
key = bin(rc.predict_getrandbits(lls%32))[2:].zfill(lls%32) + key
print(int(key,2))

print("key get out")
with open("flag.jpg","wb") as por:
    por.write(xor(ltb(int(key,2)), bdata))
# print(xor(ltb(int(key,2)), bdata))

print("Done all equipment")

```
Flag yang didapatkan berada pada sebuah image return.
![flag.jpg](https://hackmd.io/_uploads/Bkp1TmqZ6.jpg)
> TCP1P{life's_twisted_like_a_back_road_in_the_country}
---
### Shiftgner
```python
# shift.py
import os

flag = open('flag.txt','r').read()
assert flag.startswith('TCP1P{') and flag.endswith('}')
flag = flag[6:-1]
assert len(flag) == 32

class Shiftgner:
    def __init__(self, mask):
        self.mask = int.from_bytes(mask, byteorder='big')
        # print(self.mask)

    def next(self):
        c = self.state & self.mask
        x = 0
        while c:
            x ^= c & 1
            c >>= 1
        self.state = ((self.state << 1) ^ x) & 2**256-1
        return x
    
    def sign(self, msg):
        self.state = msg
        
        op  = self.next()
        for i in range(255):
            op <<= 1
            op ^= self.next()
        # print("leng op = ",len(bin(op)))
        op ^= msg
        return hex(op)

    def verify(self, msg, sig):
        return self.sign(msg) == sig

mask = os.urandom(32)
signer = Shiftgner(mask)

while True:
    print('1. Sign')
    print('2. Verify')
    print('3. Get Flag')
    print('4. Exit')
    op = int(input('> '))
    if op == 1:
        msg = int(input('Message (hex): '), 16)
        print('Signature:', signer.sign(msg))
    elif op == 2:
        msg = int(input('Message (hex): '), 16)
        sig = input('Signature: ')
        if signer.verify(msg, sig):
            print('OK')
        else:
            print('Invalid')
    elif op == 3:
        print(signer.sign(int.from_bytes(flag.encode(), byteorder='big')))
    elif op == 4:
        exit()
    else:
        print('Invalid')
```
Diberikan sebuah server penggunaan signature dengan menggunakan algoritma LFSR (class Shifter). Dalam fungsi sign diidentifikasi untuk state yang digunakan dari message yang diberikan, dari sini kita bisa menggunakan known plaintext attack untuk menebak mask dari LFSR karena kita mengetahui bit output dari LFSR = 2 * bit state. Saya menggunakan fungsi recover_mask_lsb dari link:
https://gist.github.com/badmonkey7/371c9c5b2dd4564646e2ecfe2d4403ac untuk melakukan recover mask. Persamaan yang digunakan:
$$Si=state[i]$$$$S0=message$$$$S1=xor(sign,message)$$$$output=S0{\space}|{\space}S1$$

Setelah mendapatkan flag saya bisa menyelesaikan persamaan linear flag pada GF(2) dengan jumlah variable adalah 256 variabel. Saya menggunakan fungsi rref pada matrix sage untuk mendapatkan hasilnya.

```python
# solver.py
from pwn import *
from Crypto.Util.number import bytes_to_long as btl, long_to_bytes as ltb
# from z3 import Solver, BitVec, sat
from sage.all import Matrix, GF, PolynomialRing, vector


# io = process("./shift.py")
io = remote("ctf.tcp1p.com","13342")

class Shiftgner:
    def __init__(self, mask):
        self.mask = mask

    def next(self):
        c = self.state & self.mask
        x = 0
        while c:
            x ^= c & 1
            c >>= 1
        self.state = ((self.state << 1) ^ x) & 2**256-1
        return x
    
    def sign(self, msg):
        self.state = msg
        
        op  = self.next()
        for i in range(255):
            op <<= 1
            op ^= self.next()
        op ^= msg
        return hex(op)

    def verify(self, msg, sig):
        return self.sign(msg) == sig

def xorbits(x):
    hasil = 0
    for i in x:
        hasil ^= int(i)
    return str(hasil)

# source from https://gist.github.com/badmonkey7/371c9c5b2dd4564646e2ecfe2d4403ac 
def recover_mask_lsb(output, bits):
    '''
    
    :param output: 由2*bits lsb位构成的输出
    :param bits: 级数
    :return:  返回掩码（素多项式）
    '''
    O = [int(i) for i in output]
    B = vector(GF(2), O[bits:2 * bits])
    X = Matrix(GF(2), bits, bits)
    for j in range(bits):
        X[j] = O[j:j + bits]
    mask = B * X.inverse()
    MASK = int(''.join([str(i) for i in list(mask)]), 2)
    return MASK

if __name__=="__main__":
    # mms = int(io.recvline().decode())
    io.recvuntil(b"> ")
    io.sendline(b"1")
    io.recvuntil(b"(hex): ")
    payload = int('1'*300,2)
    td = hex(payload)[2:].encode()
    io.sendline(td)
    # scsr = io.recvline().decode().strip()
    io.recvuntil(b"Signature: ")
    sg = int(io.recvline().decode().strip(),16)
    rets = payload^sg
    scs = bin(rets)[2:].zfill(256)
    print(scs)
    # print(scsr)
    # tabun
    ou = '1'*256 + scs
    print(ou)
    mask = recover_mask_lsb(ou, 256)
    # print(mms)
    print(mask)
    shifter = Shiftgner(mask)
    sg1 = shifter.sign(payload)
    print("checking")
    print(int(sg1,16))
    print(sg)
    io.recvuntil(b"> ")
    io.sendline(b"3")
    print("getout flag")
    # print(io.recvline())
    flagint = int(io.recvline().decode().strip(),16)
    print(flagint)
    fint = bin(flagint)[2:].zfill(256)
    tblmask = bin(mask)[2:].zfill(256)
    print(tblmask)


    asp = ["v"+str(i) for i in range(256)]
    vart = PolynomialRing(GF(2), asp).gens()

    mat = []

    ds = []
    for j in range(256):
        eq = 0
        bases = []
        for i in range(j, 256):
            bases.append(vart[i])
        for i in ds:
            bases.append(i)
        for i in range(256):
            if(tblmask[i]=='1'):
                eq += bases[i]
        ds.append(eq)
        eq += vart[j]
        pars = eq.variables()
        ton = []
        for i in range(256):
            if(vart[i] in pars): ton.append(1)
            else: ton.append(0)
        ton.append(int(fint[j]))
        mat.append(ton)

    mat = Matrix(GF(2), mat)
    out = mat.rref()
    opt = ''
    for i in out:
        opt+=str(i[-1])
    print(opt)
    hasil = int(opt,2)
    print(ltb(hasil))
```
>TCP1P{well_not_safe_enough_apparently!}

---
### Open the Noor
```python
#!/bin/env python3
from Crypto.Cipher import AES
import os
import random
import string

CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
KEY = os.urandom(16)

class Systems:
	def __init__(self):
		self.adminpass = self.gen_password()

	def pad(self, s):
	    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16).encode()
		
	def unpad(self, pt):
		pad_length = pt[-1]
		if not 1 <= pad_length <= 16:
			return None
		if self.pad(pt[:-pad_length]) != pt:
			return None
		return pt[:-pad_length]

	def encryption(self, msg):
		iv = os.urandom(16)
		cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
		return (iv + cipher.encrypt(msg)).hex()

	def decryption(self, msg):
		msg = bytes.fromhex(msg)
		ivnya = msg[:16]
		msg = msg[16:]
		cipher = AES.new(KEY, AES.MODE_CBC, iv=ivnya)
		return self.unpad(cipher.decrypt(msg))

	def gen_password(self):
		return ''.join([random.choice(CHARSET)for i in range(40)]).encode()

	def secured_password(self):
		return self.encryption(self.pad(self.adminpass))

def main():
	print('You are connected to:')
	print('=====================')
	print('   The Sacred Noor   ')
	print('=====================')
	systems = Systems()
	while True:
		try:
			print("")
			print("1. Login as Admin")
			print("2. Forgot password")
			print("3. Retrieve Encrypted Password")
			print("4. Exit")
			choice = input("> ")
			if choice == "1":
				print("Enter Admin Encrypted Password")
				userpass = input("[?] ")
				check = systems.decryption(userpass)
				if check != None:
					if check == b"nottheflagbutstillcrucialvalidation":
						print("Logged In!")
						print("Here's your flag: TCP1P{REDACTED}")
					else:
						print("[!] INTRUDER ALERT ",check)
				else:
					print("[!] Something's wrong.")
			elif choice == "2":
				systems.adminpass = systems.gen_password()
				print("Password Changed!")
			elif choice == "3":
				print("Secured Password")
				print("[+]", systems.secured_password())
			elif choice == "4":
				print("Bye then.")
				break
			else:
				print("Bzz error")
				exit()
		except:
			print("[!] Something's wrong.")

if __name__ == '__main__':
	main()
```
Hemm mungkin untuk problem yang ini cukup simple yaitu diberikan sebuah server AES encryption pada mode CBC. Berikut proses checking dan decryption:
```python
check = systems.decryption(userpass)
...
def decryption(self, msg):
    msg = bytes.fromhex(msg)
    ivnya = msg[:16]
    msg = msg[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv=ivnya)
    return self.unpad(cipher.decrypt(msg))
...
if check != None:
    if check == b"nottheflagbutstillcrucialvalidation":
        print("Logged In!")
        print("Here's your flag: TCP1P{REDACTED}")
    else:
        print("[!] INTRUDER ALERT ",check)
else:
    print("[!] Something's wrong.")
...
```
Bisa terlihat pada potongan tersebut digunakan fungsi padding dan pengecekan mendapatkan return yang berbeda untuk error decryption dan non admin decryption. Dari sinilah dapat dilakukan serangan Padding Oracle Attack untuk bisa mendapatkan ciphertext dari admin untuk kasus ini diharapkan dec(cipher) = 'nottheflagbutstillcrucialvalidation'.

```python
# solver.py
from pwn import *
from Crypto.Util.number import *

# io = process("./chall.py")
io = remote("ctf.tcp1p.com","2223")

def getRes(x):
    io.recvuntil(b"> ")
    io.sendline(b"1")
    io.recvuntil(b"[?] ")
    io.sendline(x.hex().encode())
    res = io.recvline().decode()
    if("INTRUDER" in res): 
        return 1
    elif("wrong" in res): return 0
    else: return 2

def repairKnown(last):
    known = b''
    for j in range(16):
        bef = b'a'*(16-j-1)
        peek = long_to_bytes(j+1) * (j)
        target = long_to_bytes(j+1)
        for i in range(256):
            bt = long_to_bytes(i)
            bets = bt + xor(known, peek)
            payload = bef+bets+last
            resp = getRes(payload)
            if(resp!=0):
                known = xor(bt, target) + known
                break
    return known

if __name__ == "__main__":
    targets = b'nottheflagbutstillcrucialvalidation'
    lastpad = 48-len(targets)
    pads = long_to_bytes(lastpad) * lastpad
    targets += pads
    tt = [targets[i:i+16] for i in range(0, 48, 16)]
    assert(len(targets)%16==0)
    c3 = b'a'*16
    rp3 = repairKnown(c3)
    c2 = xor(tt[2], rp3)
    rp2 = repairKnown(c2)
    c1 = xor(tt[1], rp2)
    rp1 = repairKnown(c1)
    iv = xor(tt[0], rp1)
    payload = iv + c1 + c2 + c3
    print(len(payload))
    hasil = getRes(payload)
    if(hasil==2):
        print("Founded flag!!")
        flag = io.recvline()
        print(flag)
```
> TCP1P{they_are_the_one_who_knocks}

---
### Eclairs
```python
#!/bin/env python3
from Crypto.Util.number import getPrime, bytes_to_long
from sympy.ntheory.modular import crt
from libnum.ecc import *
import random
import time

while (p:=getPrime(256)) % 4 != 3: pass
while (q:=getPrime(256)) % 4 != 3: pass
e = 3
n = p*q
a = getPrime(256)
b = getPrime(256)
E = Curve(a, b, n)
# print(n,a,b)
flag = bytes_to_long(open("flag.txt", "rb").read())

def sqrt_mod(a):
    assert p % 4 == 3
    assert q % 4 == 3
    r = int(crt([p,q],[pow(a,(p+1)//4,p), pow(a,(q+1)//4,q)])[0])
    n = p*q
    if pow(r,2,n) == a % n:
        return r
    return False

def lift_x(x):
    y = sqrt_mod(x**3 + a*x + b)
    if y:
        return (x, y)
    return False

def find_coordinates(x):
    P = lift_x(x)
    if P:
        x,y = P
        return (pow(x,e,n), pow(y,e,n))
    return False

def captcha():
    while True:
        x = random.randint(1, n)
        P = lift_x(x)
        if P : break
    k = random.randint(1,n)
    # print(str(E.power(P,k)))
    print("HOLD UP!!!!")
    print("YOU ARE ABOUT TO DO SOMETHING VERY CONFIDENTIAL")
    print("WE NEED TO MAKE SURE THAT YOU ARE NOT A ROBOT")
    print(f"Calculate {k} X {P}")
    ans = input("Answer: ")
    return ans == str(E.power(P,k))

while True:
    print("1. Check out my cool curve")
    print("2. Get flag")
    print("3. Exit")
    choice = input(">> ")

    if choice == "1":
        print("This point is generated using the following parameter:")
        # encrypted because I don't want anyone to steal my cool curve >:(
        print(pow(a,e,n))
        print(pow(b,e,n))
        x = int(input("x: "))
        P = find_coordinates(x)
        if P:
            print(P)
        else:
            print("Not found :(")

    elif choice == "2":
        if captcha():
            print(pow(flag, e, n))
        else:
            print("GO AWAY!!!")
            exit()
    elif choice == "3":
        exit()
    else:
        print("??")
        exit()
```
Dari program diatas bisa diketahui implementasi dari ECC dan RSA. Identifikasi kelemahan pada RSA:
```python
...
while (p:=getPrime(256)) % 4 != 3: pass
while (q:=getPrime(256)) % 4 != 3: pass
e = 3
n = p*q
...
elif choice == "2":
    if captcha():
        print(pow(flag, e, n))
    else:
        print("GO AWAY!!!")
        exit()
...
```
Dari potongan diatas kita karena nilai $e$ kecil kita bisa membangkitkan beberapa kali $n$ dan recover flag menggunakan CRT. Masalahnya kita harus melakukan bypass dari fungsi captcha. 
```python
...
def captcha():
    while True:
        x = random.randint(1, n)
        P = lift_x(x)
        if P : break
    k = random.randint(1,n)
    # print(str(E.power(P,k)))
    print("HOLD UP!!!!")
    print("YOU ARE ABOUT TO DO SOMETHING VERY CONFIDENTIAL")
    print("WE NEED TO MAKE SURE THAT YOU ARE NOT A ROBOT")
    print(f"Calculate {k} X {P}")
    ans = input("Answer: ")
    return ans == str(E.power(P,k))
...
if choice == "1":
    print("This point is generated using the following parameter:")
    # encrypted because I don't want anyone to steal my cool curve >:(
    print(pow(a,e,n))
    print(pow(b,e,n))
    x = int(input("x: "))
    P = find_coordinates(x)
    if P:
        print(P)
    else:
        print("Not found :(")
...
def find_coordinates(x):
    P = lift_x(x)
    if P:
        x,y = P
        return (pow(x,e,n), pow(y,e,n))
    return False
...
```
Dari potongan diatas fungsi captcha hanya melakukan pengecekan apakah kita bisa mendapatkan kurva yang dimaksut. Kurva yang dimaksut memiliki parameter pembangkit $a, b,$ dan $n$.
```python
...
a = getPrime(256)
b = getPrime(256)
E = Curve(a, b, n)
...
``` 
Pada choice 1 fitur kita bisa mendapatkan beberapa leak information diantaranya $a^3{\space}mod{\space}n$, $b^3{\space}mod{\space}n$, $x$, $x^3{\space}mod{\space}n$, dan $y^3{\space}mod{\space}n$ termasuk dari fungsi find_coordinates.
$$y^2=x^3 + a^x + b$$$$(y^2)^3=(x^3 + a^x + b)^3$$$$y^6= x^9 + 3x^7a + ... + 3xab^2 + b^3$$
Kemudian dilakukan subtitusi pada masing-masing leak information bisa mendapatkan persamaan beikut.
$$k1a+k2a^2+k3b+k3ab+k4a^2b+k5b^2-k6=0$$$$k7a+k8a^2+k9b+k10ab+k11a^2b+k12b^2-k13=0$$$$...$$
Dari persamaan diatas mungkin kita bisa mendapatkan nilai $a$ dan $b$ dengan menggunakan grobner basis. Setelah saya coba ternyata untuk hasil grobner juga bisa menhasilkan $a, b,$ bahkan $n$.
```python
...
def calc_A(rep):
    loki = []
    for a,b,r in rep[0:6]:
        fi = parseVal(r,a,b)
        loki.append(fi)
    I = Ideal(loki)
    # print(I)
    gb = I.groebner_basis()
    print(gb)
    exit(1)
...
```
![grobner-try.jpg](https://hackmd.io/_uploads/By-GpXqZ6.jpg)

Setelah itu tinggal menggunakan CRT untuk mendapatkan flag.

```python
# solver.py
from sympy.ntheory.modular import crt
from pwn import *
from sage.all import ZZ, PolynomialRing, factor, Ideal
from libnum.ecc import *
import math
from Crypto.Util.number import *
import gmpy2

def start():
    io = remote("ctf.tcp1p.com","13341")
    # io = process("./eclairs.py")
    # print(io.recvline())
    return io

def getparam(io, x):
    io.recvuntil(b">> ")
    io.sendline(b"1")
    io.recvuntil(b"parameter:\n")
    a3 = int(io.recvline().decode().strip())
    b3 = int(io.recvline().decode().strip())
    io.recvuntil(b"x: ")
    io.sendline(str(x).encode())
    hasil = io.recvline().decode().strip()
    if("Not" in hasil): return False
    else: 
        val = [int(i) for i in hasil[1:-1].split(",")]
        return a3, b3, val


# theory solved
# x^9 + 3*x^7*a + 3*x^5*a^2 + 3*x^6*b + x^3*a^3 + 6*x^4*a*b + 3*x^2*a^2*b + 3*x^3*b^2 + 3*x*a*b^2 + b^3
# -     x a       x^2 a^2	  b         -         x a b       x^2 a^2 b     b^2         x a b^2 	-   --- values
# x3^3  3*x3^2    3*x3        3*x3^2    x3*a3     6*x3        3             3*x3        3           b3  --- constant
def parseVal(resp, a3, b3):
    x3,y3 = resp
    # y^2
    y6 = y3**2
    # x div ^2
    x = int(gmpy2.iroot(x3,3)[0])
    a,b = PolynomialRing(ZZ, ['a','b']).gens()
    f = x3**3 + 3*x3**2*x*a + 3*x3*x**2*a**2 + 3*x3**2*b + x3*a3 + 6*x3*x*a*b + 3*x**2*a**2*b + 3*x3*b**2 + 3*x*a*b**2 + b3 - y6
    return f

def calc_A(rep):
    loki = []
    for a,b,r in rep[0:6]:
        fi = parseVal(r,a,b)
        loki.append(fi)
    I = Ideal(loki)
    # print(I)
    gb = I.groebner_basis()
    return gb[2], gb[2]-gb[0].coefficients()[1], gb[2]-gb[1].coefficients()[1]

if __name__ == "__main__":
    m = []
    c = []
    for i in range(5):
        io = start()
        rep = []
        repair = []
        for j in range(2,300):
            resp = getparam(io, j)
            if(resp!=False):
                # print("hehe")
                rep.append(resp)
                if(len(rep)==6): 
                    repair = calc_A(rep)
                    break
        # print(repair)
        E = Curve(int(repair[1]), int(repair[2]), int(repair[0]))
        io.recvuntil(b">> ")
        io.sendline(b"2")
        io.recvuntil(b'Calculate ')
        k = int(io.recvuntil(b" ").decode().strip())
        io.recvuntil(b'X ')
        pp = io.recvline().decode().strip()
        # print(pp)
        x = [int(i) for i in pp[1:-1].split(",")]
        P = (x[0], x[1])
        # print(P)
        poin = str(E.power(P,k))
        io.recvuntil(b'Answer: ')
        io.sendline(poin.encode())
        mm = int(io.recvline().decode().strip())
        print(mm)
        m.append(int(repair[0]))
        c.append(mm)
        io.close()
    roots = crt(m, c)[0]
    print(roots)
    flag = gmpy2.iroot(roots,3)[0]
    flag = long_to_bytes(flag)
    print(flag)
```

>TCP1P{yet_another_ecrsa_challenge_smh_my_head}
---