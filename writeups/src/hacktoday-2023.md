# WRITEUP HACKTODAY 2023 [IPB] - wondPing
## Reverse RSA **[cry]**
We are given the following script
``` python
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random
import os
import hashlib

def generate_prime():
    while True:
        a,b = random.getrandbits(512), random.getrandbits(512)
        if isPrime(pow(a+b,2) - 2*a*b):
            return pow(a+b,2) - 2*a*b,a,b

def encrypt(m: str, a: int, b: int):
    key1 = hashlib.sha256(long_to_bytes(a)).digest()[:16]
    key2 = hashlib.sha256(long_to_bytes(b)).digest()[:16]
    enc = AES.new((key1+key2), AES.MODE_ECB)
    return enc.encrypt(pad(m.encode(),16)).hex()

def hehe():
    e = 3
    m = open("flag.txt", "r").read()
    while True:
        p,a1,b1 = generate_prime()
        q,a2,b2 = generate_prime()
        phi = (p-1)*(q-1)
        d = inverse(e,phi)
        if d > 1:
            break
    return [encrypt(m[:len(m)//2],a1,b1), encrypt(m[len(m)//2:],a2,b2)],p,q,e,phi,d

def main():
    c = os.urandom(128)
    c = bytes_to_long(c)
    arr,p,q,e,phi,d = hehe()
    n = p*q
    c = pow(c,e,n)
    with open("output.txt", "w") as f:
        f.write(f"{arr = }\n")
        f.write(f"{n = }\n")
        f.write(f"hint1 = {pow(d,e,n)}\n")
        f.write(f"hint2 = {pow(phi,e,n)}\n")
        f.write(f"{c = }\n")
    
if __name__ == "__main__":
    main()
```
We are given some RSA algorithm than we must to recover secret key $p$ and $q$. Then the flag is encrypted using AES_ECB with the key is integer factor of Gaussian Number $p$ and $q$. Given leak information is: $$hint1= d^e{\space} mod {\space}N$$ $$hint2= {\phi}^e{\space} mod {\space}N$$ from $\phi$ and $d$ we have some relation that was: $$e*d=1{\space}mod{\space}{\phi}$$ $$e*d=1{\space}+{\space}{\phi}*k, 0{\space}{\le}{\space}k{\space}{\le}{\space}2$$ Then for $d$ we can get two equation, I choosen $k=2$
$$f=d^3{\space}-{\space}hint1^3$$ $$g=(1{\space}+{\space}3{d})^3{\space}-{\space}2hint2^3$$ Then the $GCD(f,g) = d$. For ${\space}GCD$ is greatest common divisor on Polynomial Equation.

After getting $d$ we can calculate $phi$ and also recover $p$ and $q$ using formula:
$$phi = pq+1-(p+q)$$ $$(p+q)^2 = p^2+q^2+2N$$ $$(p-q)^2 = p^2+q^2-2N$$
By finding the $p$ and $q$ we reach the next step that is factorization $p$ and $q$ on Gaussian integer. This happen because $p$ and $q$ is equal to $a^2+b^2$ based on **generate_prime** function. You can also look at [here](https://en.wikipedia.org/wiki/Gaussian_integer) for basic gaussian integer.

Then after getting $a$, $b$, $c$ and $d$ we can getting the flag by decrypt using AES_ECB algorithm. 
``` python
from sage.all import *
import gmpy2
from Crypto.Util.number import *
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

arr = ['157ac614902984894fdeebbfbb071706c567595ec75d8cfa15b4fa78daec262d', '595c471aa4f4fd674f1e3d2d92451989241fc1e5483943462f22139c40f60d26']
n = 9404723413794096840750486535785285876794535511361576853412894200845911829969003676331972051866542086573004196242231773112663882448836681678590616938532087370724012561834072457630073865001977238949966722341420654913634880863139275477367393205803942845700830842030060644879799392560716190756869979961824845241569993349385435448657207484771713611355411421946908145951836362023313860299870126918469757911219457349691268685976027977384948482194603575249579019596371390753132679691323416176793352309224255021352738424721594142218928582299260654395897260445353676685563521525892292706947334487897374797852951852040590439389
hint1 = 5593970872387902311836120769053146059030637049105040672773016542948942827846061455999241332211428748455532077139830258533039183282935580889489022458478819394933221299590803205851007751465773973836342968239451534638666681077174814829317144676304459890795587677431848130945816787248862202489625370728665219246850849531465607250163714577387028779607621513638179749977435710283251137169285937214422416793079706536196480336771593027324005441922899749335901149114578231558834425607409354371485716879130690793956769919193617810765575349163856434793328180751525777217810347087656060661898920296778852235014244784438117344389
hint2 = 5446652598623286373540740185691377562112378054932863691745388627532997381032665137705282537716393921078256974027879043372793432547277387313590701809091955164730657081027679538240032159050178309377831080023703981029646570666202553744157221928143089769909303226677755350033176487206293268111168110249714236854535547619145134751499925916881609808586089112703503905754591039632362196307354542415863425450459964401674662922169555148817289901559388128468293418026085799636986930902643463113147492211964426687699624427520381128316307257870691112821972197023935474933590589743664317514018607706611905278629337485988906164194
c = 7991692935236697018032616275905284758675867368654810481567580564749308850310725506266215536688476849984230374928184166120978180506053082631431754595409266497275709349357554657688080630449133131297573880508612520979731153956613071579120148934504905905315090298098968595822455136835559865077550164700254933008254821465581291331179132088699155913460035689547373957877694226375395571500546107153216033597413229256701114394855130478488829686504004068335094489957778744880851306446127916910072065064567410839868504156515259923671163421414490363540166073133737149154052626702175043043135891501264734754803452478400915979970

def GCD(f, g, n):
    g = g % f
    if g == 0:
        return f
    t = g.lc()
    if gcd(t, n) != 1:
        print(t)
        exit()
    tt = inverse_mod(Integer(t), n)
    g = g * tt
    return GCD(g, f, n)

def publicAttac(n, d3, phi3):
    PR = PolynomialRing(Zmod(n), 'x')
    x = PR.gen()
    f = x * x * x - Zmod(n)(hint1)
    h = (3 * x - 1) ** 3 - Zmod(n)(hint2) * 8
    eq = GCD(f, h, n)
    d = n-eq[0]
    phi = pow(hint2, int(d), n)
    pplusq = int(n+1-phi)
    p2q2 = pplusq**2 - 2*n
    pminq = gmpy2.iroot(int(p2q2 - 2*n), 2)[0]
    p = gcd(int(n), int(pplusq-pminq))
    q = int(n)//p
    assert n == p*q
    return p,q

def absol(x):
    if(x<0): return int(-x)
    else: return int(x)

def gaussianFactor(p):
    x = var('x')
    K = NumberField(x**2 + 1 , names=('I',))
    I = K.gen()
    fi, fj = K.factor(p)
    zi = fi[0].gens_reduced()[0]
    return absol(zi[0]), absol(zi[1])

def dec(m, a: int, b: int):
    key1 = hashlib.sha256(long_to_bytes(a)).digest()[:16]
    key2 = hashlib.sha256(long_to_bytes(b)).digest()[:16]
    enc = AES.new((key1+key2), AES.MODE_ECB)
    return enc.decrypt(m)

def tryflag(x):
    for i in x:
        try:
            flag = unpad(i, 16)
            return flag
        except:
            continue
    return None

if __name__ == "__main__":
    p,q = publicAttac(n, hint1, hint2)
    a, b = gaussianFactor(p)
    c, d = gaussianFactor(q)
    assert a**2 + b**2 == p
    assert c**2 + d**2 == q
    cip1 = bytes.fromhex(arr[0])
    cip2 = bytes.fromhex(arr[1])

    may_flag1 = [dec(cip1, a, b), dec(cip1, b, a), 16]
    may_flag2 = [dec(cip2, c, d), dec(cip2, d, c), 16]
    flag = tryflag(may_flag1) + tryflag(may_flag2)
    print(flag)
```
![](https://hackmd.io/_uploads/B1q6TYvah.jpg)
> flag = hacktoday{R3v3rS3_RS4_W1th_S0mE_Alg3brSa_1s_Aw3S0mE!!!}
## AES Enjoyer **[cry]**
We are given the following script
``` python
#!/usr/bin/python3

import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long
from Crypto.Util.Padding import pad

class Unbuffered(object):
  def __init__(self, stream):
    self.stream = stream
  def write(self, data):
    self.stream.write(data)
    self.stream.flush()
  def writelines(self, datas):
    self.stream.writelines(datas)
    self.stream.flush()
  def __getattr__(self, attr):
    return getattr(self.stream, attr)

sys.stdout = Unbuffered(sys.stdout)

with open("flag.txt", "rb") as f:
    flag = f.read()
    f.close()

def encrypt(pt: bytes, iv: bytes, key: bytes):
    aes = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
    pt = pt + flag[:len(flag)//2]
    pt = pad(pt, 16)
    ct = aes.encrypt(pt)
    return iv+ct

def generate_key():
    return bin(bytes_to_long(os.urandom(2)))[5:].zfill(16)

def gift(pt : bytes):
    key = generate_key()
    iv = b"hektoday"*2
    assert len(key) == 16 and len(iv) == 16
    print(key)
    aes = AES.new(key.encode(), AES.MODE_CBC, iv=iv)
    return aes.encrypt(pt)

def menu():
    print(
"""[1] Encrypt
[2] Flag
[3] Exit""")


def main():
    key = os.urandom(16)
    for _ in range(4):
        menu()
        op = input("[>] ")
        if op == "1":
            iv = bytes.fromhex(input("[>] IV (hex): "))
            pt = bytes.fromhex(input("[>] Plaintext (hex): "))
            iv = pad(iv, 16) if len(iv) < 0x10 else iv
            pt = pad(pt, 16)
            ct = encrypt(pt, iv, key)
            print("[*] Ciphertext:", ct.hex())
        elif op == "2":  
            print("[*] Encrypted Flag:", gift(gift(flag[16:])).hex())
        elif op == "3":
            break
        else:
            print("[?] Are you drunk?")
        print()

    return 0


if __name__ == "__main__":
    main()
```
The given program is implementation of AES mode CBC and CFB. The flag is divide into 2 part. The first part encrypted $flag[:16]$ is append into our input and encrypted with AES_CFB. The formula is: $$cipher = encrypt(pad(pad(input,16) + flag_1),16))$$
Given scheme AES_CFB mode decryption process: 
![](https://hackmd.io/_uploads/rySZ8Eu6h.jpg)
From that we have equation: $$P_i=Dec(C_i){\space}{\oplus}{\space}C_{i+1}$$ $$0\space{\le}{\space}i$$ on line 201 source code given before, plaintext is padding firstly. So we can use $i>0$ $$Dec(C_1)=P_1{\space}{\oplus}{\space}C_2$$ $$P_{flag}=Dec(C_i){\space}{\oplus}{\space}C_{flag+1}$$ We can recover the flag because we can use model Chosen-plaintext attack. The first part of flag is have length 16 bytes so we doesn't need some configuration on padding because have equal len with one block (on the second block).

The second part of flag is encrypted with AES_CBC but from the source code, key used in encryption is printed on line 181. So, we can just decrypt from given $iv$, $ciphertext$, and $key$.

``` python
from pwn import *
from binascii import unhexlify
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

io = remote("103.181.183.216","18002")

def decAEs(key, cipher):
    iv = b"hektoday"*2
    aes = AES.new(key.encode(), AES.MODE_CBC, iv=iv)
    return aes.decrypt(cipher)

def flag1():
    io.recvuntil(b'[>] ')
    io.sendline(b'2')
    key1 = io.recvline().decode().strip()
    key2 = io.recvline().decode().strip()
    io.recvuntil(b'[*] Encrypted Flag: ')
    cipher = unhexlify(io.recvline().decode().strip())
    hasil = decAEs(key1, decAEs(key2, cipher))
    return hasil

def stage1(message, iv):
    io.recvuntil(b'[>] ')
    io.sendline(b'1')
    io.recvuntil(b'IV (hex): ')
    io.sendline(iv.hex().encode())
    io.recvuntil(b'Plaintext (hex): ')
    io.sendline(message.hex().encode())
    io.recvuntil(b'Ciphertext: ')
    cipher = io.recvline().decode().strip()
    return cipher

def xxor(x,y):
    return long_to_bytes(bytes_to_long(x)^bytes_to_long(y))

def flag2():
    iv = b'aa'
    know1 = pad(b'a'*15,16)
    know2 = b'a'*16
    cip1 = unhexlify(stage1(know1+know2, iv))[32:48]
    cip2 = unhexlify(stage1(b'a'*15, iv))[32:48]
    key = xxor(cip1, know2)
    flag = xxor(key, cip2)
    return flag

if __name__ == "__main__":
    flag_1 = flag1()
    flag_0 = flag2()
    print(flag_0+flag_1)
```

![](https://hackmd.io/_uploads/ry7c0FP6h.jpg)
> flag = hacktoday{M0r3_A3S_D0esN't_Me4N_M0r3_S3cuR3!!_I_Th1nK_p4dp4dp4d}
## Unknown Cipher **[cry]**
We are given some Socat Connection Encryption Scheme
![](https://hackmd.io/_uploads/B17sAFPp2.jpg)
From those program we just have ciphertext only for cryptanalysis. Then i try to input some text like "aa", "aaa", "aaa..." and something interest happened. The ciphertext have some characteristics:
1. one letter on input is encrypted into 5 letter in ciphertext
2. every letter will same ciphertext per letter in one round
3. ciphertext formula is $cip = encrypt(input + flag)$

From the three of characteristics above i can make dictionary of all possible letter input then by send all possible letter on input and match with each ciphertext.
``` python
from pwn import *
import string


list_string = string.ascii_letters + string.digits + "}{_!#@"

io = remote("103.181.183.216","19000")

flag = ""

def olah(cipher):
    cipherflag = cipher[5*len(list_string):]
    dictionaries = cipher[:5*len(list_string)]
    dcts = {}
    for i in range(0, len(dictionaries), 5): dcts[dictionaries[i:i+5]] = list_string[i//5]
    flag = ""
    cip = [cipherflag[i:i+5] for  i in range(0, len(cipherflag), 5)]
    for i in cip:
        flag += dcts[i]
    return flag

if __name__ == "__main__":
    st = list_string.encode()
    io.recvuntil(b'> ')
    io.sendline(st)
    io.recvuntil(b'ciphertext: ')
    cipher = io.recvline().decode().strip()
    flag = olah(cipher)
    print(flag)


```
![](https://hackmd.io/_uploads/HJ6cAYPa3.jpg)
> flag = hacktoday{3NCrYpt_S4tU_S4tU_T1dAk_4m4N}
> ***save and late to send the flag during the competition***
## Spam **[cry]**
We are given the following script
``` python
#!/usr/bin/env python3

from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime, inverse, GCD
from random import sample, randint, shuffle

with open('spam.txt','r') as spam:
	spam = spam.read().splitlines()
	jumlah = randint(100, 200)
	email = sample(spam, jumlah)

with open('password.txt','r') as password:
	password = password.read().splitlines()
	full_password = ''.join(password)
	email.extend(password)
	shuffle(email)

with open('flag.txt','r') as flag:
	FLAG = flag.read().strip()

for idx in enumerate(email):
	indeks = idx[0]+1
	message = idx[1]
	while True:
		p = getPrime(512)
		q = getPrime(16)
		phi = (p-1)*(q-1)
		e = 65537
		d = inverse(e,phi)
		if GCD(e,phi) == 1 and d != -1:
			break

	m = bytes_to_long(message.encode())
	n = p*q
	c = pow(m,e,n)

	print(f'n{indeks} = {n}\n')
	print(f'c{indeks} = {c}\n')

answer = input('Input Full Password = ').strip()

if answer == full_password:
	print(f"Correct Password!\nHere's Your Flag\n{FLAG}\n")
else:
	print('Wrong Password!')

```
We know from those program is reading 2 file txt (password and spam) then shuffle all of them to encrypt with RSA algorithm each line. Then we must to input the correct password. The weakness of  algorithm is the value of $q$ is to small $1 < q < 2^{16}$. So we can use bruteforce attack to find $p$ and $q$. 

After decrypting all plaintext we get some information that was there are differents value of spam and password that was shuffle before. Spam text is contain "happy_birthday" value, but password value don't. Then we can filter it and get the password by arranging with correct order. Password is "1Nst1Tut_p3Rt4n14N_b0G0R".

``` python
from pwn import *
from Crypto.Util.number import *

io = remote("103.181.183.216","18001")
bunchdata = io.recvuntil(b'Input Full').decode().split("\n")
print("done getting data")
n = []
c = []

def att(c, n):
    p,q = getfactor(n)
    phi = (p-1)*(q-1)
    e = 65537
    d = pow(e, -1, phi)
    mes = long_to_bytes(pow(c,d,n))
    return mes

def getfactor(n):
    for i in range(2, 2**16):
        if(n%i==0):
            return i, n//i

for i in bunchdata:
    if('c' in i):
        num = int(i.split(' = ')[1])
        c.append(num)
    elif("n" in i):
        if("Input" in i): break
        num = int(i.split(' = ')[1])
        n.append(num)

plain = []
for i,j in zip(c,n):
    plain.append(att(i, j))
print(plain[:10])
passw = []
for i in plain:
    if(not b"happy_birthday" in i): passw.append(i)
print(passw)
io.interactive()
```
![](https://hackmd.io/_uploads/BJlaRFwp2.jpg)
> flag = hacktoday{H4pPy_b1Rthd4Y}
