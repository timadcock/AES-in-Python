# AES-in-Python
## Description:
This is my code for AES encryption that I wrote in python 3. This does both encrryption of a file as well as decryption of a file. The file "test.txt" is the example document I used, the "enc_test.txt" is "test.txt" encrypted with the password "0123456789123456" and "dec_enc_test.txt" is "test.txt" being decrypted with the same password.

## Usage:
python[3] AES [File] [D,E]<br>
[D] indicates Decrypt<br>
[E] indicates Encrypt<br>
[File] is the file that is to be decrypted or encrypted

## Procedure Used:
1. Choose a key that is 128 bits in size.

2. The make rounds part creates 9 more “keys” based on the original key. This is done in a couple steps. The first being Rot word on the last column of the original key. Rot word takes the column and moves the first position to the last position moving everything else up. Next that column is replaced using the Sbyte pre-determined matrix also known as sub bytes. Then multiply (XOR) by the round’s column in Rcon which is another matrix that is pre-determined. This is multiplied with the first column of the original key. This is the first column of the next key. To get the remainder of the columns just multiply (XOR) the previous column by its corresponding column in the previous key. This is done until you have 10 keys. These are your round keys.

3. Next thing is the encryption steps. The first thing to do is make sure your plaintext you want to encrypt is in increments of 128 bits made into a matrix where each row column is 1 byte. Then Multiply (XOR) the first “round key”. Then send this matrix through the same Sbyte as the round keys. Then shift rows. This is done by leaving the first row the same, then shift the first item (column) of the second row to the end, the first and second in the third row then the first second and third in the fourth row. Then send that new matrix into Mix Columns. Mix columns takes the matrix and multiplies (XOR) it by another pre-determined matrix by columns. This is done for all columns. Then after mix columns the multiply (XOR) the next round key and repeat this process until the last round key. With this last matrix just do Sbyte then shift the rows then multiply (XOR) the last round key in. This leaves one 4x4 matrix of 128 bits as your encrypted plaintext.

4. To Decrypt it is the same process as encrypting but in reverse and using different pre-determined matrixes.


## References
https://www.youtube.com/watch?v=gP4PqVGudtg<br>
Rijndael.pdf<br>
NIST.FIPS.197.pdf
