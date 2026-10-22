# WRITEUP COMPFEST 15-2023 Quals [mirror] - wondPing
## Choose Exponent **[crypto]**
We are given this following code
```python
from Crypto.Util.number import getPrime, bytes_to_long

FLAG = b"COMPFEST15{REDACTED}".ljust(256, b"\x00")

class RSA:
    def __init__(self):
        self.p = getPrime(1024)
        self.q = getPrime(1024)
        self.n = self.p * self.q
        # you can choose your own public exponent
        # self.e = 65537

    def encrypt(self, m, e):
        return pow(m, e, self.n)

    def decrypt(self, c, d):
        return pow(c, d, self.n)


def main():
    print("Welcome to RSA challenge!")
    print("In this challenge you can choose your own public exponent")

    rsa = RSA()
    m = bytes_to_long(FLAG)
    count = 0
    while count < 3:
        print("What do you want to do?")
        print("1. Get encrypted flag")
        print("2. Exit")

        option = input(">> ")
        if option == "1":
            e = int(input("Enter your public exponent (e cannot be 1 and even): "))
            if e == 1 or e % 2 == 0:
                print("loh gak bahaya tah")
                continue
            c = rsa.encrypt(m, e)
            print(f"Here is your encrypted flag: {c}")
            count += 1
        elif option == "2":
            print("Bye!")
            exit()
        else:
            print("Invalid option")
            continue
    
    print("You have reached maximum number of public exponent")

if __name__ == "__main__":
    main()

```
We get some standard encryption scheme using RSA. From there we can get encrypted flag that use $e$ is from our input. The return just the encrypted flag. Our idea to get the flag is just input $e$ = $3$ and getting different Modulus or $n$ and different encrypted flag, then solve it using CRT. But, we need to get the value of $n$. On the program with same $n$ we get 3 chance to input $e$ so we can getting $n$ from it. The following equation will help:
$$Flag^3 = C1{\space}(Mod{\space}n)$$$$Flag^{9} = C2{\space}(Mod{\space}n)$$$$Flag^{15} = C3{\space}(Mod{\space}n)$$ we will use $Flag^3$ as base to reproduce equation from another 2 equation else.
$$Flag^{9}=(Flag^3)^3=C1=C2^3{\space}(Mod{\space}n)$$$$k1*n=C1^3-C2$$ $$Flag^{15}=(Flag^3)^5=C1=C3^5{\space}(Mod{\space}n)$$$$k2*n=C1^5-C3$$. we can get the $n$ value by calculating $GCD(C1^3-C2,C1^5-C3)$. Then after getting $enc(Flag)$ and $n$ we can just use CRT to get the flag.
Final Solver:
```python
from pwn import *
from sympy.ntheory.modular import crt
from Crypto.Util.number import *
import gmpy2
import math

def startIO():
    io = remote("34.101.68.243","10004")
    return io

def getCip(io, e):
    io.recvuntil(b'>> ')
    io.sendline(b'1')
    io.recvuntil(b'(e cannot be 1 and even): ')
    io.sendline(str(e).encode())
    io.recvuntil(b'encrypted flag: ')
    c = int(io.recvline().decode().strip())
    return c

def getnc():
    io = startIO()
    f3 = getCip(io, 3)
    f9 = getCip(io, 9)
    f15 = getCip(io, 15)
    io.close()
    n1 = f3**3 - f9
    n2 = f3**5 - f15
    n = math.gcd(n1, n2)
    for i in range(2, 100):
        if(n%i==0):
            n//=i
    assert(len(bin(4))<=2048)
    return f3, n

if __name__ == "__main__":
    m = []
    c = []
    for i in range(3):
        c1, n = getnc()
        m.append(n)
        c.append(c1)
    hasil = crt(m, c)[0]
    root = gmpy2.iroot(hasil, 3)
    flag = long_to_bytes(root[0])
    print(flag)
```
![](https://hackmd.io/_uploads/H1TXn2qJ6.jpg)
> COMPFEST15{gcd_is_too_powerful_to_get_factorization_78010ce551}
## Swusjack Encryption **[crypto]**
We are given this following code
```python
from Crypto.Util.number import long_to_bytes, bytes_to_long

p = 1179478847235411356076287763101027881
e = 0x10001


def bytes_to_block(msg: bytes):
    res = []
    msg_int = bytes_to_long(msg)
    while msg_int:
        res.append(msg_int % (p**2))
        msg_int //= p**2
    return res


def block_to_bytes(blocks: list[int]):
    res = 0
    for i in range(len(blocks) - 1, -1, -1):
        res *= p**2
        res += blocks[i]
    return long_to_bytes(res)


class MultiplicativeGroup:
    def __init__(self, p, a, b):
        self.a = a
        self.b = b
        self.p = p

    def __mul__(self, other) -> "MultiplicativeGroup":
        a = (self.a * other.a - 6969 * self.b * other.b) % self.p
        b = (self.a * other.b + self.b * other.a - 69 * self.b * other.b) % self.p
        return MultiplicativeGroup(self.p, a, b)

    def __pow__(self, n) -> "MultiplicativeGroup":
        res = MultiplicativeGroup(self.p, 1, 0)
        base = self
        while n:
            if n & 1:
                res *= base
            base *= base
            n >>= 1
        return res
    
    def __repr__(self):
        return f"({self.a}, {self.b})"


if __name__ == "__main__":
    FLAG = open("flag.png", "rb").read()
    blocks = bytes_to_block(FLAG)
    enc = []
    for block in blocks:
        assert block < p**2
        a = block % p
        b = block // p
        m = MultiplicativeGroup(p, a, b)
        c = m ** e
        enc.append(c.a + c.b * p)
        
    open("flag.enc", "wb").write(block_to_bytes(enc))
```
The source code is encrypting the image that contains the flag. Firstly divide the flag.png to some block and every block is multiplicate by $e$ on Multiplicative Group. To get back the flag we can just multiplicate the every cipher block with $d$ that is inverse of $e$ on multiplicative group. To find $d$ we need to calculate order of the group. I having some try to caltulate order of group.
```python
a,b = (97, 13)
p = 821
print(p)
m = MultiplicativeGroup(p, a, b)
for i in range(2, 2*p**2):
    hasil = [int(i) for i in str(m**i).replace(")","").replace("(","").split(',')]
    if(1==hasil[0] and 0==hasil[1]):
        print(i)
        continue
```
from the source code above i trying to get point $(1,0)$. From that i getting some output, that was on $i$ equals ${i=224680,449360,674040,898720,...}$
from that i know that on $p=821$, the 3 value of i is equal to $p*p-1=674040$. From that i think the order maybe has formula $p*p-1$.
```python
for i in range(200):
    p = getPrime(500)
    if(i!=1000):p = 1179478847235411356076287763101027881
    exc = p*(p-1)
    # print("trying on i",i+1,"when p =",p, "expect",exc)
    print("trying on i",i+1)
    # base = MultiplicativeGroup(p, 1, 0)
    a,b = randint(1, p), randint(1,p)
    m = MultiplicativeGroup(p, a, b)
    hasil = [int(i) for i in str(m**(p*p-1)).replace(")","").replace("(","").split(',')]
    if(1==hasil[0] and 0==hasil[1]):
        continue
    else: print("not Validd")
```
from source code above i trying to prove my formula and from 200 trying and bigger $p$, then the output all of that is valid. Then after it i going to write my solver code to getting the flag. The step is parse cipher to block then find $d$, after it just multiplicate every block and convert back block to bytes to get image file. 
Final Solver:
```python
from Crypto.Util.number import *

p = 1179478847235411356076287763101027881
e = 0x10001

def bytes_to_block(msg: bytes):
    res = []
    msg_int = bytes_to_long(msg)
    while msg_int:
        res.append(msg_int % (p**2))
        msg_int //= p**2
    return res


def block_to_bytes(blocks: list[int]):
    res = 0
    for i in range(len(blocks) - 1, -1, -1):
        res *= p**2
        res += blocks[i]
    return long_to_bytes(res)

class MultiplicativeGroup:
    def __init__(self, p, a, b):
        self.a = a
        self.b = b
        self.p = p

    def __mul__(self, other) -> "MultiplicativeGroup":
        a = (self.a * other.a - 6969 * self.b * other.b) % self.p
        b = (self.a * other.b + self.b * other.a - 69 * self.b * other.b) % self.p
        return MultiplicativeGroup(self.p, a, b)

    def __pow__(self, n) -> "MultiplicativeGroup":
        res = MultiplicativeGroup(self.p, 1, 0)
        base = self
        while n:
            if n & 1:
                res *= base
            base *= base
            n >>= 1
        return res
    
    def __repr__(self):
        return f"({self.a}, {self.b})"

if __name__ == "__main__":
    datas = open("flag.enc","rb").read()
    order = p*p-1
    d = pow(e, -1, order)
    blocks = bytes_to_block(datas)
    plain = []
    for block in blocks:
        assert block < p**2
        a = block % p
        b = block // p
        m = MultiplicativeGroup(p, a, b)
        c = m ** d
        plain.append(c.a + c.b * p)
        
    open("flag.png", "wb").write(block_to_bytes(plain))
```
Flag.png after running solver
file ![](https://hackmd.io/_uploads/SkWATtq1T.jpg)
> COMPFEST15{find_the_order_of_group_81ee36780a}
## Knapsack **[crypto]**
We are given this following code
```python=
from collections import namedtuple
import random
from Crypto.Util.number import isPrime, GCD
from secret import message, key_size

PrivateKey = namedtuple("PrivateKey", "W q r")
PublicKey = namedtuple("PublicKey", "B")

def to_bits(m):
    _bin = lambda b: [1 if b & (1 << n) else 0 for n in range(7)]
    return sum([_bin(b) for b in m], [])


def to_bytes(bits):
    _byte = lambda b: sum([b[i] << i for i in range(7)])
    return bytes([_byte(bits[i : i + 7]) for i in range(0, len(bits), 7)])


def pad(m):
    return m + b"\x00" * (-len(m) % (key_size // 7))


def unpad(m):
    return m.rstrip(b"\x00")


def gen_private_key(key_size):
    W = []
    s = 6969

    # generate W
    for _ in range(key_size):
        w_i = random.randint(s + 1, 2 * s)
        assert w_i > sum(W)
        W.append(w_i)
        s += w_i

    # generate q
    while True:
        q = random.randint(2 * s, 32 * s)
        if isPrime(q):
            break

    # generate r
    r = random.randint(s + 1, q - 1)

    assert q > sum(W)
    assert GCD(q, r) == 1
    return PrivateKey(W, q, r)


def gen_public_key(private_key):
    B = []
    for w_i in private_key.W:
        B.append((private_key.r * w_i) % private_key.q)
    return PublicKey(B)


def encrypt(msg, public_key):
    msg_bit = to_bits(pad(msg))
    key_size = len(public_key.B)
    enc = []
    for i in range(0, len(msg_bit), key_size):
        enc.append(sum([msg_bit[i + j] * public_key.B[j] for j in range(key_size)]))
    return enc


def decrypt(enc, private_key):
    dec = []
    for c in enc:
        c_ = (c * pow(private_key.r, -1, private_key.q)) % private_key.q
        bits = []
        for w_i in reversed(private_key.W):
            if c_ >= w_i:
                bits.append(1)
                c_ -= w_i
            else:
                bits.append(0)
        dec += bits[::-1]
    return unpad(to_bytes(dec))

private_key = gen_private_key(key_size)
public_key = gen_public_key(private_key)
enc = encrypt(message, public_key)
dec = decrypt(enc, private_key)


assert dec == message

with open("output.txt", "w") as f:
    # f.write(f"B = {public_key.B}\n")
    f.write(f"enc = {enc}\n")
    f.write(f"{message[:1194].decode()}")
```
From that source code we know that the we have some secret message that encrypted with Merkle-Hellman algorithm. I guess that the Flag is some part of secret message then i just to attack the Merkle-Hellman algorithm to recover the flag. After searching i know that Merkle-Hellman is crackable using LLL-reduction algorithm then i want to apply it quickly. But, the problem is we just given the part of message and doesn't has any information about the public key and also the length of public key. So, firstly i want to recover the public key and attack the algorithm using LLL. We use this following matrix to reduce.

$$\left[\begin{array}{ccc}
2 & 0 & 0 & 0 & 0 & ... & Pk[0]\\
0 & 2 & 0 & 0 & 0 & ... & Pk[1]\\
0 & 0 & 2 & 0 & 0 & ... & Pk[2]\\
0 & 0 & 0 & 2 & 0 & ... & Pk[0]\\
... & ... & ... & ... & ... & ... & ...\\
... & ... & ... & ... & ... & 2 & Pk[n]\\
-1 & -1 & -1 & - & ... & -1 & -Enc[j]\\
\end{array}\right]$$ Return value of the reduction as my expected is $(-1/1,...,...,0)$ that point to value $(Mb[0], Mb[1], ..., ...)$. $Mb$ = bit of plaintext $(-1 = 0, 1= 1)$. $Pk$ = PublicKey.
For recovering the public key we given part of message and also the ciphertext of it. We can make some equation on following line:
$$Pk[1]{\space}*{\space}Mb[1]{\space}+{\space}Pk[2]{\space}*{\space}Mb[2]{\space}+{\space}Pk[3]{\space}*{\space}Mb[3]{\space}+{\space}...{\space}Pk[n]{\space}*{\space}Mb[n]{\space}={\space}enc[0]$$$$Pk[1]{\space}*{\space}Mb[n+1]{\space}+{\space}Pk[2]{\space}*{\space}Mb[n+2]{\space}+{\space}Pk[3]{\space}*{\space}Mb[n+3]{\space}+{\space}...{\space}Pk[n]{\space}*{\space}Mb[2*n]{\space}={\space}enc[1]$$$$...$$$$Pk[1]{\space}*{\space}Mb[(k-1)n+1]{\space}+{\space}Pk[2]{\space}*{\space}Mb[(k-1)n+2]{\space}+{\space}...{\space}Pk[n]{\space}*{\space}Mb[k*n]{\space}={\space}enc[k]$$ With value of $k$ is length ciphertext of known plaintext and $n$ is length of $publicKey$. From all of equation above we can solve it as Linear Equation System. We will use z3 solver on python to solve the system. But before it we use bruteforce for guessing the value of $n$ that is length of publicKey. We can also reduce the possibility by this following equation:
$$len(knownMessage){\space}*{\space}8{\space}<enc{\space}*{\space}len(publicKey)$$$$1094{\space}*{\space}8{\space}<{\space}177{\space}*{\space}len(publicKey)$$$$len(publicKey){\space}>{\space}50$$ Then after it we make the final script and running it.
Final Solver:
```python
from z3 import *
from sage.all import matrix


def to_bits(m):
    _bin = lambda b: [1 if b & (1 << n) else 0 for n in range(7)]
    return sum([_bin(b) for b in m], [])


def to_bytes(bits):
    _byte = lambda b: sum([b[i] << i for i in range(7)])
    return bytes([_byte(bits[i : i + 7]) for i in range(0, len(bits), 7)])


def pad(m, key_size):
    return m + b"\x00" * (-len(m) % (key_size // 7))


def unpad(m):
    return m.rstrip(b"\x00")

enc = [11777743254884910867736071000802359, 9885367164484426877141712841289221, 10856960655537648470866892845455709, 12396844046310131327328676182785384, 10293406405260841919973448808441389, 7161552265897968311561098524910942, 10615787983784797652230739276445941, 8750996343125558087794309091207648, 9793482204040387456132647801296313, 10082519515116179234452192268207537, 11320102966402368083376899357909591, 12863315726661485156488840690651082, 11531046537784628833143256540008389, 9286560942760408224853358742306869, 12279582004149322390043290795184438, 11978789745490392114224327243767043, 12084485742145391797013212600989700, 11561154470121507020306698832744599, 13178456331567650213084024227496278, 10196086379552872917716585823999514, 10601541281173337913507909606005653, 9966399811463401202257751291120170, 10250511746568637708134548840731312, 11889575565127642830776977900408626, 10933709862860216194904138708336773, 10007593807392566080878720263508671, 10843011316705174491702117107785768, 12383694531221582253577117167915563, 9894583959533524041648917678111635, 10430518900617276344682533425679992, 10018475657312899961053882989990531, 12880429380373138445215696957506949, 10918434549436697161520320355333263, 11400042022902061481939614685122963, 11171610137545211187916226582376885, 7554940907108436037367038464198228, 9695912009774929988863012317171859, 9343496763562026180227665632657363, 12025067720426566083965241093256942, 9658955369440797726004826519759606, 9428833271132121009515800913622083, 10461484260876120487748327356785073, 10940612465536330800162700132905186, 10750467235934085792526359728596178, 10678873223029328852630062166689316, 10051894872077260074152880418222275, 10497008510500960013913178933854405, 10753394290126674824447926145896263, 10374556791613714702994629355809965, 10751549259077891899074410410421186, 10497129585037258904358709726525823, 11713351721867966767470659598304708, 9750904136088440351393297931807531, 12920557770888166933984079266544430, 9835518991386093395547202596319386, 10686991553601958185529117081292430, 10817714646369847390214302366874082, 11656133992050865158028442465948881, 9710481682340951577750560981814297, 9812463701289538441884338771424591, 10553500394965127205851299497413972, 9072662701494366982448390007849710, 10626852662537677429807153297591631, 10320557743814566446047834649298263, 10229033571571432213114817752122773, 10137091208657689466011904565821444, 9671296686420595758174214901621293, 11060629505422615215479089478068342, 9363787514709375187692683504126271, 9282781227753261317425876892013992, 9792647279730520129037413182534118, 11813869200575530803652104759262730, 9161928319229922257558038982128902, 10971796325720348232207258964788834, 9768861656419748162363181789101894, 10457965191293035226753206288146876, 11507982245405850634450464634589014, 10178640325420144331673938576834887, 10422017659145361826713838891135351, 9522927671377163131409738991653604, 10718579523969523227649591475908544, 12001115266350043980981379604813238, 10578812558562041805075262672497200, 9752859065974451382515905408025221, 11167987407122180703265457924178842, 9254029087396928912823658881409506, 10883479949880070871921870163374012, 11641336159459821580913821804515986, 9831976055167640701792299948722247, 9607326851652988564446116205180982, 11804616236914324707289980227637258, 8737658801206619958913982157263731, 9321117326771341614560384118866848, 12434262148233111040506390593441974, 9094596632057590879309101458194330, 10919870415301977737620426338392154, 9973779461746337777601698299498727, 13077097958532704050556386545741606, 10169545420422687603182882727171540, 11112798322767421119202274397188040, 9686860625851189937448816700040764, 11346835372920653632886580259127170, 9653724702297290643613793338823616, 11402239574264886427635550872788202, 9164717106755214577990540059670310, 10757982233067007899585898815139468, 11491931619173132257869978491641067, 10320404508097598075786619727003330, 10360404911242274038733003166681825, 11504881273300385090543651942681693, 10050497788566704765830589138400435, 9538999475912234600157681944493317, 11563463623586812255485232857599142, 8346901243091379690454826112441168, 10985123722502869338191643390313317, 9889419332627564614605267676475582, 9859008421534798027137238190169291, 8938108903576444037425026088417415, 11680785377217252765318352340278111, 11827065014133601933199138466286954, 10313025714965640595018569900420070, 11417267430337929136320784840421909, 8422584002870384136094081858383799, 10690359392494235886344438075661972, 10471344316033728097890752546524525, 10297237481194543096768525745798780, 11852784405095354362694442350929004, 11119778357967519776338637639047638, 9866655586941191421363196046299360, 10190115156307836485874719502143486, 12043225446675699386463230372571576, 10552241846308353818649522824971213, 9988028333155853144238651873306651, 10091392579705422187015420572382039, 10005842533804787157435320367039807, 10290501388089990847500605282087698, 10260079649840625499533386845655403, 9880687720157416551773806961186599, 12012537693823600317312532902550958, 8433167876202052583892538043499959, 11291163813180795239823826678637357, 8012971667935976011881461871593275, 13055895017385493902965307298758371, 10956829329131089932931803183795475, 10648023387171769092056689660527946, 9220397506426318617705668568380205, 9871207467819032200547465506808880, 10934669185660283455617271150287701, 9467876649386646296389087904618660, 13794160913300054581464395357038327, 9079301979125027938314870240165138, 12857015710047013040592592010876990, 11760789607847616802409107522171732, 12101202285031769352939345225180229, 11479374430179263163764851706844319, 9618684327449521603105661594573419, 11368851597362018368159187165305341, 10926103543543835056336767571733674, 12113712395211988433505262029083924, 8409110871996716684073156006373610, 10634854008206235974941650718127360, 11191821014173140552936341375666462, 11734220008676991656373171468230169, 11700550791405431460693949785169775, 11027471624758702087033927626502411, 10564827560525376313267401679415349, 10127201149696841461429643317101068, 10726399432872273049792997541701017, 10991865026417715013894334993971459, 10613123876559868339081376626812279, 8265705744262621901191334665843770, 8839978095214156480555512903831932, 11523816542334107733475885455187708, 11396931014886569225447187208304949, 9148460817006566054942492973353282, 11486944793732160981882091263330869, 7987682971004889468582279658369686]
output= 'The Merkle-Hellman Knapsack Cryptosystem, developed by Ralph Merkle and Martin Hellman, is a public-key encryption algorithm known for its resistance to attacks using conventional computers. It operates on the principle of the knapsack problem, making it difficult to solve without the private key.\nIn this cryptosystem, a superincreasing knapsack is created as the public key. Each element of the knapsack is generated using a specific algorithm, ensuring that the sum of any subset of elements is unique. This property makes it challenging to deduce the original combination used to create the knapsack.\nTo encrypt a message, the plaintext is divided into binary bits and combined with the public key. This process results in a ciphertext that obscures the original message. Decrypting the ciphertext requires the knowledge of the private key, which is a set of carefully selected parameters used to generate the knapsack.\nThe security of the Merkle-Hellman Knapsack Cryptosystem relies on the complexity of solving the subset sum problem, which is considered computationally difficult. Traditional methods, such as brute-force attacks, are ineffective due to the large search space involved.'

out_bit = to_bits(output.encode())

def to_block(bit, keysize):
    ret = []
    for i in range(0, len(bit), keysize):
        ret.append(bit[i:i+keysize])
    if(len(ret[-1])!=keysize): ret = ret[:-1]
    return ret

def blockToMatrix(bloks, enc):
    mat = []
    for i in range(len(bloks)):
        rest = bloks[i]
        rest.append(enc[i])
        mat.append(rest)
    return mat

def solvingLL(pub, enc):
    mat = []
    for i in range(len(pub)):
        race = [0 for _ in range(len(pub))]
        race[i] = 2
        race.append(pub[i])
        mat.append(race)
    race = [-1 for _ in range(len(pub))]
    race.append(-enc)
    mat.append(race)
    lft = matrix(mat).LLL()
    for i in lft:
        check = True
        for j in i[:-1]:
            if(j!=-1 and j!=1):
                check = False
                break
        if(check):
            hasil = [0 if k==-1 else 1 for k in i[:-1]]
            return hasil
    return None

public = []
lastenc = 0
ksize = 0

for keySize in range(50, 1000):
    solv = Solver()
    varr = [Int('var'+str(i)) for i in range(keySize)]
    # print(varr)
    print("trying on keysize:",keySize)
    port = to_block(out_bit, keySize)
    print(len(port))
    mat = blockToMatrix(port, enc)
    for j in mat:
        func = 0
        for k in range(len(j[:-1])):
            if(j[k]==1):
                func += varr[k]
        func = func - j[-1]
        solv.add(func==0)
    for var in varr:
        solv.add(var>=0)
    print("searching solution")
    print(len(mat))
    if solv.check() == sat:
        lastenc = len(mat)
        public = []
        print("Getting solution")
        mdl = solv.model()
        for i in varr:
            public.append(mdl[i].as_long())
        print(public[0]+public[1])
        print(public)
        ksize = keySize
        break

# getting following value after running source code above, to get faster running just command source code above
# public = [202268999244591785584566464753289, 429481650350982224726540148422072, 513970026512572516113525776325248, 28117338492482390640953333703346, 186478220980676412258710097278824, 462107941653161013119183689513668, 251033680402139409627861954081627, 387816645824497842897510344498537, 164216600494137571823429526298731, 71778558816306530276260088958157, 479183011393572102154187215734921, 188237385509602029366682887942757, 164510164493942220113929554143015, 351957897387419262141620439154413, 559564023232732499808238313579215, 132277552177561352557338493209814, 178940764650522512349239779345091, 18866483643001119992915813508719, 65129268506159449846196687577134, 167844715331905178809461440317639, 187057779217236112720777337188447, 255235457949798322226331129469322, 542112960942493765359209270647723, 114204524812950672204089546427243, 53252437125337397373227709083049, 247770731648992733096183772815536, 370278558235654291454711551198693, 204891318167558074435123111701205, 346727118758224765373461446521918, 383267401562421973802058492472223, 417343176245713459916869587269198, 402777959260550580969689993776134, 256182522762462197049974160316147, 12633876948394660593286916001351, 314759385142403326392078244802058, 263384123584500671540118032288133, 38650772398307717379496756747526, 306247616243715512386307466259185, 18476145088228804143170873686713, 117347060602402743026648839960226, 532135003875215013523423589192213, 48852380988000293381223282153612, 392265050642625455268293151465954, 476031692087751937639870601144694, 313629857431146857184719536982718, 401494270926634643978458681547252, 469566569599947139086905470473261, 35198969362337022791203043174857, 302866869873710554417387933256528, 568209519326416227422311570586209, 346972863738514859986014024700232, 228494377266333974424439321983382, 273276775819051056644733188417501, 375104893892478155799313329948322, 505185562312989073710257542456512, 487212675194015362273133188431578, 482365437683654780746878113745270, 431965489061014360035520964200531, 408258373241369446583858893702995, 470031010237858817507296825649368, 257013818984828645730461138618543, 54947842649555394131632787661575, 515120777972555489955179566266686, 221636118181162865445925087810764, 261861417553256248241702651575262, 292909311966757680411011941074079, 574982374582780447492152113881912, 558873603864855849876018552771791, 297055452910545368134149122366836, 10217264473676430559765113019100]
# lastenc = 119
# ksize = 70
# mess = output.encode()
mess = b''
otp = []
for i in range(lastenc,len(enc)):
    halo = solvingLL(public, enc[i])
    if(halo==None): 
        otp += [0 for _ in range(70)]
        print("failed on i",i)
    elif(i%20==0): print("Success until i:",i)
    else:otp+=halo
adding = to_bytes(otp[:len(otp)-len(otp)%7])
mess += adding
print(mess)
```
![](https://hackmd.io/_uploads/rk4ZUcc1a.jpg)
> COMPFEST15{D4ngerr_LLL_1s_Ev3ryWh3r3_ed2c699bb3}

## Crypto Vault **[crypto]**
We are given this following code
```python
#!/bin/env python3
from flask import Flask, jsonify, request, render_template
import ecdsa
import ecdsa.ellipticcurve as EC
from flask_cors import CORS
import binascii
import ecdsa.util
app = Flask(__name__)
CORS(app)

curve = ecdsa.SECP256k1
G = curve.generator
n = G.order()
x = int('ce205d44c14517ba33f3ef313e404537854d494e28fcf71615e5f51c9a459f42', 16)
y = int('6080e22d9a44a5ce38741f8994ac3a14a6760f06dd1510b89b6907dfd5932868', 16)
Q = EC.Point(curve.curve, x, y)
PUBKEY = ecdsa.VerifyingKey.from_public_point(Q, curve)

# Convert the public key to standard format
PUBKEY_str = binascii.hexlify(PUBKEY.to_string()).decode()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/verify_signature', methods=['POST'])
def verify_signature():
    data = request.get_json()
    signature_hex = data['signature']
    message_hash = int(data['message_hash'], 16)
    # print(message_hash)
        # Convert the signature from standard format
    signature_bin = binascii.unhexlify(signature_hex)
    r = int.from_bytes(signature_bin[:32], 'big')
    s = int.from_bytes(signature_bin[32:], 'big')
    sig = ecdsa.ecdsa.Signature(r, s)
    
    result = verify_ecdsa_signature(sig, message_hash)
    
    response = {'result': result, 'pubkey': PUBKEY_str}
    return jsonify(response)

def verify_ecdsa_signature(sig, message_hash):
    m = message_hash
    if PUBKEY.pubkey.verifies(m, sig):
        return "this is the flag"
    else:
        return "skill issue ( ͡° ͜ʖ ͡°)"

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=1984)
```
we given some service that just verifying ECDSA signature from input value $(r,s)$ and $hash(message)$. The source code doesn't has some filtering input then i think we can bypass the source code because we getting information about the $curve$ and also $publicKey$. The following line is formula on ECDSA Verify Signature: 
$$R'{\space}={\space}(h{\space}*{\space}s^{-1}){\space}*{\space}G{\space}+{\space}(r{\space}*{\space}s^{-1}){\space}*{\space}publicKey$$$$R'{\space}={\space}eq1{\space}+{\space}eq2$$$$eq1{\space}={\space}(h{\space}*{\space}s^{-1}){\space}*{\space}G{\space}$$$$eq2{\space}={\space}(r{\space}*{\space}s^{-1}){\space}*{\space}publicKey$$ we can make $eq1$ is equal to $(0,1)$ if $h$ = $curve.order()$. Then if we input $r$ = $s$ output is same as $publicKey$. $$eq2{\space}={\space}(r{\space}*{\space}r^{-1}){\space}*{\space}publicKey$$$$eq2{\space}={\space}1{\space}*{\space}publicKey$$ So we can input $r$ = $publicKey.x$ to satisfy $eq2$.
Solver:
```python
import ecdsa
import ecdsa.ellipticcurve as EC
import ecdsa.util

curve = ecdsa.SECP256k1
G = curve.generator
n = G.order()
x = int('ce205d44c14517ba33f3ef313e404537854d494e28fcf71615e5f51c9a459f42', 16)
y = int('6080e22d9a44a5ce38741f8994ac3a14a6760f06dd1510b89b6907dfd5932868', 16)
Q = EC.Point(curve.curve, x, y)
PUBKEY = ecdsa.VerifyingKey.from_public_point(Q, curve)
# print(n)

import requests
import binascii

# print(PUBKEY.pubkey)

# signature_hex = data['signature']
    # message_hash = int(data['message_hash'], 16)
m = n
r,s = x,1
sig = ecdsa.ecdsa.Signature(r, r)
hasil = PUBKEY.pubkey.verifies(m, sig)
assert hasil==True

rr = r.to_bytes(32, "big")
ss = r.to_bytes(32, "big")
sgrs = binascii.hexlify(rr+ss).decode()
mh = hex(m)[2:]

data = {"signature":sgrs,"message_hash":mh}
x = requests.post("http://127.0.0.1:1984/verify_signature",headers={"Content-Type": "application/json"},json=data)
print(x.content)
# print(hasil)
```
> I didn't get the flag because the Competition was over, the solver above is for local service