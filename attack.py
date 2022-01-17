def convertLiterralToSting(y):
    """helper for easy comparison with strings but calculation with python ints as hex-literal"""
    rr = ('%0256x'%y)
    return rr

def sO(y) -> bool:
    """simulated PKCS#1v1.5 Padding Oracle (no RSA-Encrypton or Decyption) with all pkcs#1 checks"""
    rr = convertLiterralToSting(y)
    if len(rr) != 256:
        return False
    if rr[0:4] == "0002":
        if "00" in rr[4:19]:
            return False
        elif "00" in rr[20:]:
            return True
    else:
        return False
    return False

def testO():
    print(sO("0002" + "1122334455667788" + "00"*1000))
    print(sO(m0))

def ceil(x,y):
    """helper-function: computes the ceil of math: x/y with python3"""
    return -(x//-y) # Converted floor to ceiling with negation

def floor(x,y):
    """helper-function: computes the floor of math: x/y python3"""
    return x//y

#-------------Bleichenbacher attack---------------
# message m0 as python3-litteral-hex-number which we want decyrpt with the PKCS#1 Padding Oacle 
    # (generated in privious experiment with openssl) 
m0 = 0x0002010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010074686973206973206120736563726574206d6573736167650a

#rsa modulus string from previous generated RSA-Key
previousModulus = '''
    00:b3:80:0c:c9:69:38:e5:60:7e:7f:df:07:2c:1c:
    6c:92:91:91:40:45:5c:1c:e7:c2:a2:d9:56:85:cc:
    31:c7:ad:9a:40:07:cc:25:40:20:a4:99:b4:6e:72:
    c3:ff:d4:b9:df:7c:50:c2:0a:0b:48:5a:88:76:9e:
    dd:b3:e7:d4:a3:14:da:62:f5:39:34:98:ce:e7:3e:
    fa:98:37:8e:51:fc:2d:3a:90:cf:da:09:6a:14:a0:
    fe:87:4e:64:d7:4e:52:91:77:83:15:a9:b9:72:9f:
    e9:f6:f6:c3:b0:f6:63:95:30:c3:cc:b1:5d:17:b9:
    0f:58:e5:25:3f:0b:21:12:b9
'''

def parseMod(mod):
    """converting the modulus-multi-line-string to int""" 
    res = previousModulus.replace('\n', '').replace(':', '').replace(' ', '')
    return int(res, 16) 

n= parseMod(previousModulus)

# definition of interval
B = 2**1008
B2, B3 = 2*B, 3*B

#start in middle of intervall [2B, 3B]
si = ceil(n,B3)-1 

newM = set([]) #collects new intervals
newM = newM | set([(B2, B3-1)]) #inital interval for m0
k = 128 # => number of bytes k of modulus => 1024 bits => 128 bytes
fk = '%0' + str(k*2) + 'x'

oracle_calls=1
while True:
    i=1
    if (len(newM)> 1 or (B2,B3-1) in newM):
        si= si + 1
        while True: #find a value for si such that m0*si is correctly padded
            m1=(m0*si)%n
            if (sO(m1)):
                found = True
                print("found si:", si)
                break
            si = si + 1
            i = i + 1

    #when there is only one interval left
    elif( len(newM) ==1 ):
        fst = newM.pop()
        newM.add(fst)
        a=fst[0]
        b=fst[1]
        r= ceil((b*si - B2)*2, n) # stating value for r
        
        found = False
        while not found:
            for si in range(ceil((B2 + r * n), b) , floor((B3-1 + r*n), a) +1):
                mi = (si * m0) % n
                if sO(mi):
                    found = True
                    break # we found si
                i = i + 1 
            if not found:
                r = r + 1

    print("[*] Search done in {} iterations".format(i))
    print("     si: ", si)
    oracle_calls = oracle_calls + i


    #for each r, find new range of m0
    newMM = set([])
    j = 0
    print("Number of interfalls for m0 = ", len(newM))

    for(a,b) in newM: # for all intervals
        r1 = ceil((a*si - B3 + 1), n)
        r2 = floor((b*si - B2), n) + 1
        j= j + 1
        print("interval {}: r ranges form {} to {}".format(j,r1,r2))
        
        for r in range(r1,r2):
            aa = ceil( B2 + r*n, si)
            bb = floor(B3 - 1 + r*n, si)
            newa = max(a,aa)
            newb = min(b,bb)
            if newa <= newb:
                newMM = newMM | set([ (newa, newb) ])
    
    if len(newMM) > 0:
        newM = newMM

    if len(newM) == 1:
        fst = newM.pop()
        if (fst[0] == fst[1]):
            print("\n", "-" *100)
            print("\n")
            print( "Found msg of m0:" +fk % fst[0] )
            if (fst[0] == m0):
                print("\n\n")
                print("Mesagge found matches orginal message.")
                print("Number of oracle calls:", oracle_calls) 
                print("\n\t\t ATTACK SUCCESSFUL!")
            break
        newM.add(fst)
    print("\n\n")
