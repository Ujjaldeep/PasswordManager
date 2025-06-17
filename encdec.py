import encryptionkey
import decryptionkey

def encryptor(raw_uid,raw_pwd):
    enc=""
    salt="989"
    enc+=salt
    for i in range(len(raw_uid)):
        if i%2==0:
            enc+=encryptionkey.ASCII(raw_uid[i])
        else:
            enc+=encryptionkey.bitconv(raw_uid[i])
    enc+=salt
    for i in range(len(raw_pwd)):
        if i%2==0:
            enc+=encryptionkey.ASCII(raw_pwd[i])
        else:
            enc+=encryptionkey.bitconv(raw_pwd[i])

    return enc[::-1]

def decryptor(rpwd):
    if not rpwd:
        return ""
    npwd=rpwd[::-1]
    dec_uid=""
    dec_pwd=""
    pwd=npwd[3::]
    t=pwd.find("989")
    flag=True
    toggle=0

    i=0
    while i<len(pwd):

        if i==t:
            i+=3
            flag=False
            toggle=0
        
        if flag:
            if toggle==0:
                dec_uid+=decryptionkey.CharfromASCII(pwd[i:i+3])
                i+=3
            else:
                dec_uid+=decryptionkey.CharfromBit(pwd[i:i+7])
                i+=7
        else:
            if toggle==0:
                dec_pwd+=decryptionkey.CharfromASCII(pwd[i:i+3])
                i+=3
            else:
                dec_pwd+=decryptionkey.CharfromBit(pwd[i:i+7])
                i+=7
        toggle=1-toggle
    
    return [dec_uid,dec_pwd]

if __name__=="__main__":
    exit(0)
