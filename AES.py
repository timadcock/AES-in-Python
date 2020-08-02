"""The AES algorithm module made by Tim Adcock

Globals:\n
subbyte,
inversesubbyte,
Rcon,

Utility Functions:\n
text_hex,
text_mat,
hex_matrix,
hex_text,
mat_text,
readFile,
enc,
dec,
usage,

Class:
    AES
        Class Functions:\n
        __init__,
        makeRoundKeys,
        makeRound,
        encrypt,
        decrypt,
        addRoundKey,
        roundEnc,
        roundDec,
        subByte,
        inverseSubByte,
        shiftRows,
        inverseShiftRows,
        xtime,
        mixSingleColumn,
        mixColumns,
        inverseMixColumns,

Usage:
    usage: python[3] AES [File] [D,E]\n
    [D] indicates Decrypt\n
    [E] indicates Encrypt\n
    [File] is the file that is to be decrypted or encrypted



"""

import sys


subbyte = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]
"""Chart used for the Sub Byte method"""

inversesubbyte = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
]
"""This is used for the inverse Sub Byte method"""


Rcon = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x000, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x000, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x000, 0x00, 0x00
]
"""This chart is used for the Rcon method"""

def text_hex(text):
    """
    This function is used to turn a string of size 16 or less into it's hexadecimal format

    Parameters
    ----------
    text : string
        The string to be converted.

    Returns
    -------
    test : list
        The hexadecimal list
    """

    test = 0
    tmp = text
    if len(text) < 16:
        for i in range(16 - len(text)):
            tmp += '\0'
    for c in range(16):
        test <<= 8
        test |= ord(tmp[c])
    return test

def text_mat(txt):
    """
    Turns a plaintext into a matrix that is used for the AES.

    Parameters
    ----------
    txt : string
        The string to be converted.

    Returns
    -------
    list
        The plaintext as a matrix
    """
    return hex_matrix(text_hex(txt))

def hex_matrix(hex1):
    """
    Turns a hex list into a matrix.

    Parameters
    ----------
    hex1 : List
        The list to be converted.

    Returns
    -------
    matrix : List
        The hex as a matrix
    """
    matrix = []
    tmp = hex1
    tmat = []
    for i in range(4):
        for j in range(4):
            byte = tmp >> (j * 8) & 0xff
            tmat.append(byte)
        tmat.reverse()
        matrix.append(tmat)
        tmat = []
        tmp >>= 32
    matrix.reverse()
    return matrix

def hex_text(hex1):
    """
    Turns a hex list into plaintext.

    Parameters
    ----------
    hex1 : List
        The list to be converted.

    Returns
    -------
    list
        The plaintext as a matrix
    """
    return mat_text(hex_matrix(hex1))


def mat_text(mat):
    """
    Turns a matrix into plaintext.

    Parameters
    ----------
    mat : List
        The matrix to be converted.

    Returns
    -------
    string : string
        The matrix as plaintext.
    """
    string = ""
    for r in mat:
        for c in r:
            string += chr(c)
    return string

def readFile(fileN):

    """
    Reads in a file and converts the text from the file into a many lists of size 16.

    Parameters
    ----------
    fileN : string
        The file that will be opened.

    Returns
    -------
    mats :  List
        The file as one large list.
    """



    file = open(fileN,'rb')
    mats = []

    txt = file.read()
    tmp = ""
    txt = txt.decode('utf')

    for b in range(0,len(txt),16):
        mats.append(txt[b:b+16])

    file.close()

    return mats

def enc(key, fileN):
    """
    Takes in a key and a file and will encrypt it. The name of the encrypted file is the file's name prefixed with "enc_".

    Parameters
    ----------
    fileN : string
        The file that will be encrypted.

    key : string
        The key that is 16bytes (characters) long.
    """
    aes = AES(key)
    enc = []
    mats = readFile(fileN)

    for s in mats:
        enc.append(aes.encrypt(s))

    out = open("enc_{}".format(fileN), 'wb')

    for m in enc:
        out.write(bytes(m,'utf'))

    out.close()

def dec(key, fileN):
    """
    Takes in a key and a file and will decrypt it. The name of the decrypted file is the file's name prefixed with "dec_".

    Parameters
    ----------
    fileN : string
        The file that will be decrypted.

    key : string
        The key that is 16bytes (characters) long.
    """
    aes = AES(key)
    dec = []
    mats = readFile(fileN)

    for s in mats:
        dec.append(aes.decrypt(s))

    out = open("dec_{}".format(fileN), 'wb')

    for m in dec:
        m = m.replace('\0', '')
        out.write(bytes(m,'utf'))

    out.close()

def usage():
    """
    Displays the usage of the program. Will Exit program if called.
    """
    print("usage: python[3] AES_Handler [File] [D,E]")
    print("[D] indicates Decrypt")
    print("[E] indicates Encrypt")
    print("[File] is the file that is to be decrypted or encrypted")
    exit()






class AES:
    """
    This is the AES algorithm. This will perform a encryption and decryption of a file with a 16bit(character) key given.

    Parameters
    ----------
    masterKey : string
        The key that is used to decrypt and encrypt the entire file.

    """

    def __init__(self, masterKey):
        """
        Initializes all of the needed variables, as well as translates the text that is given into a matrix so the algorithm can continue.

        Parameters
        ----------
        masterKey : string
            The key that is used to decrypt and encrypt the entire file.

        """
        self.masterKey = text_mat(masterKey)
        self.roundKeys = []
        self.roundKeys.append(self.masterKey)
        self.makeRoundKeys()

    def makeRoundKeys(self):
        """
        Prepares the keys used for all 10 rounds in the de/encrpytion.

        """
        for i in range(1,10):
            self.roundKeys.append(self.makeRound(self.roundKeys[i - 1], i))

    def makeRound(self, m, r):
        """teset
        Makes a single rounds key.

        Parameters
        ----------
        m : int
            The previous round key used, starting at the starting string.

        r : into
            The current round, not used in the key creation, can be used for debugging

        Returns
        -------
        tmp : List
            The new round key that will be used for round r.

        """
        c3 = [m[0][3], m[1][3], m[2][3], m[3][3]]

        rw = [c3[1],c3[2],c3[3],c3[0]]
        sb = [subbyte[rw[0]], subbyte[rw[1]], subbyte[rw[2]], subbyte[rw[3]]]

        ck0 = [m[0][0] ^ sb[0] ^ Rcon[r], m[1][0] ^ sb[1], m[2][0] ^ sb[2], m[3][0] ^ sb[3]]
        ck1 = [ck0[0] ^ m[0][1] , ck0[1] ^ m[1][1], ck0[2] ^ m[2][1], ck0[3] ^ m[3][1]]
        ck2 = [ck1[0] ^ m[0][2] , ck1[1] ^ m[1][2], ck1[2] ^ m[2][2], ck1[3] ^ m[3][2]]
        ck3 = [ck2[0] ^ m[0][3] , ck2[1] ^ m[1][3], ck2[2] ^ m[2][3], ck2[3] ^ m[3][3]]


        tmp = []

        for i in range(4):
            tmp.append([ck0[i], ck1[i], ck2[i], ck3[i]])

        return tmp

    def encrypt(self, plain):
        """
        Encrypts plaintext using the masterKey, the plaintext string must be 16 bytes (characters) long.

        Parameters
        ----------
        plaintext : string
            The string to be encrypted.

        Returns
        -------
        enc : string
            The encrypted plaintext string.

        """
        plain = text_mat(plain)
        enc = self.addRoundKey(plain, self.roundKeys[0])

        for i in range(1, 10):
            enc = self.roundEnc(enc, self.roundKeys[i])

        enc = self.subByte(enc)
        enc = self.shiftRows(enc)
        enc = self.addRoundKey(enc, self.roundKeys[9])
        enc = mat_text(enc)

        return enc

    def decrypt(self, ciphertext):
        """Decrypts plaintext using the masterKey, the plaintext string must be 16 bytes (characters) long.

        Parameters
        ----------
        plaintext : string
            The string to be decrypted.

        Returns
        -------
        dec : string
            The decrypted plaintext string.

        """
        dec = text_mat(ciphertext)

        dec = self.addRoundKey(dec, self.roundKeys[9])
        dec = self.inverseShiftRows(dec)
        dec = self.inverseSubByte(dec)

        for i in range(9, 0, -1):
            self.roundDec(dec, self.roundKeys[i])

        dec = self.addRoundKey(dec, self.roundKeys[0])
        dec = mat_text(dec)

        return dec

    def addRoundKey(self, s, k):
        """
        Adds in a round key for de/encryption.

        Parameters
        ----------
        s : List
            The curent encrypted text.

        k : List
            The round used to de/encrypt s more.

        Returns
        -------
        tmp : List
            The new round key that will be used or the final de/encrypted result.

        """
        tmp = s
        for i in range(4):
            for j in range(4):
                tmp[i][j] ^= k[i][j]
        return tmp

    def roundEnc(self, m, key):
        """
        Performs the steps needed to encrypt a single round.

        Parameters
        ----------
        m : List
            The current plaintext being encrypted.

        key : List
            The key used for this round.

        Returns
        -------
        r : List
            The plaintext that is encrypted after the round is finished.

        """
        r = self.subByte(m)
        r = self.shiftRows(m)
        r = self.mixColumns(m)
        r = self.addRoundKey(m, key)
        return r


    def roundDec(self, m, key):
        """
        Performs the steps needed to decrypt a single round.

        Parameters
        ----------
        m : List
            The current plaintext being decrypted.

        key : List
            The key used for this round.

        Returns
        -------
        r : List
            The plaintext that is decrypted after the round is finished.

        """
        self.addRoundKey(m, key)
        self.inverseMixColumns(m)
        self.inverseShiftRows(m)
        self.inverseSubByte(m)

    def subByte(self, e):
        """
        Does the subbyte function.

        Parameters
        ----------
        e : List
            The current plaintext that will used.

        Returns
        -------
        tmp : List
            The plaintext after the subbyte function was done.

        """
        tmp = e
        for i in range(4):
            for j in range(4):
                tmp[i][j] = subbyte[e[i][j]]
        return tmp


    def inverseSubByte(self, d):
        """
        Does the inverse subbyte function.

        Parameters
        ----------
        d : List
            The current plaintext that will used.

        Returns
        -------
        tmp : List
            The plaintext after the inverse subbyte function was done.

        """
        tmp = d
        for i in range(4):
            for j in range(4):
                tmp[i][j] = inversesubbyte[d[i][j]]
        return tmp


    def shiftRows(self, e):
        """
        Shifts the rows of the current plaintext.

        Parameters
        ----------
        e : List
            The current plaintext that will used.

        Returns
        -------
        tmp : List
            The plaintext after the rows were shifted.

        """
        tmp = e
        tmp[0][1], tmp[1][1], tmp[2][1], tmp[3][1] = tmp[1][1], tmp[2][1], tmp[3][1], tmp[0][1]
        tmp[0][2], tmp[1][2], tmp[2][2], tmp[3][2] = tmp[2][2], tmp[3][2], tmp[0][2], tmp[1][2]
        tmp[0][3], tmp[1][3], tmp[2][3], tmp[3][3] = tmp[3][3], tmp[0][3], tmp[1][3], tmp[2][3]
        return tmp

    def inverseShiftRows(self, d):
        """
        Shifts the rows of the current plaintext.

        Parameters
        ----------
        e : List
            The current plaintext that will used.

        Returns
        -------
        tmp : List
            The plaintext after the rows were shifted.

        """
        tmp = d
        tmp[0][1], tmp[1][1], tmp[2][1], tmp[3][1] = tmp[3][1], tmp[0][1], tmp[1][1], tmp[2][1]
        tmp[0][2], tmp[1][2], tmp[2][2], tmp[3][2] = tmp[2][2], tmp[3][2], tmp[0][2], tmp[1][2]
        tmp[0][3], tmp[1][3], tmp[2][3], tmp[3][3] = tmp[1][3], tmp[2][3], tmp[3][3], tmp[0][3]
        return tmp

    def xtime(self, m):
        """
        A special function used during the mix a columns part of the round, it helps with the entire mixing.

        Parameters
        ----------
        m : List
            The current plaintext column that will used.

        Returns
        -------
        List
            The plaintext column after the operation was completed.

        """
        if m & 0x80:
            return ((m << 1) ^ 0x1B) & 0xFF
        else:
            return (m << 1)

    def mixSingleColumn(self, c):
        """
        The procedure to mix a single column of the plaintext.

        Parameters
        ----------
        c : List
            The current plaintext column that will used.
        """
        a = c[0] ^ c[1] ^ c[2] ^ c[3]
        z = c[0]
        c[0] ^= a ^ self.xtime(c[0] ^ c[1])
        c[1] ^= a ^ self.xtime(c[1] ^ c[2])
        c[2] ^= a ^ self.xtime(c[2] ^ c[3])
        c[3] ^= a ^ self.xtime(c[3] ^ z)


    def mixColumns(self, e):
        """
        The procedure to mix the columns of the plaintext.

        Parameters
        ----------
        e : List
            The current plaintext that will used.
        """
        for i in e:
            self.mixSingleColumn(i)


    def inverseMixColumns(self, d):
        """
        The procedure to inverse the mixing of plaintext columns.

        Parameters
        ----------
        d : List
            The current plaintext that will used.
        """
        tmp = d
        for i in range(4):
            a = self.xtime(self.xtime(tmp[i][0] ^ tmp[i][2]))
            b = self.xtime(self.xtime(tmp[i][1] ^ tmp[i][3]))
            tmp[i][0] ^= a
            tmp[i][1] ^= b
            tmp[i][2] ^= a
            tmp[i][3] ^= b

        self.mixColumns(d)


def runP():
    """
    Runs encrpytion/decryption.
    """

    file = sys.argv[1]

    if file[0:2] == ".\\":
        file = file[2:]

    print(file)

    style = sys.argv[2]
    key = input("Enter the key: ")
    while(len(key) > 16 ):
        print("Key Too Large!!")
        key = input("Enter the key: ")

    if style == 'D':
        mats = readFile(file)
        dec(key, file)
        print("File", file, "Decrypted!")

    elif style == 'E':
        mats = readFile(file)
        enc(key,file)
        print("File",file,"Encrypted!")
    else:
        usage()



if __name__ == "__main__":
    runP()
