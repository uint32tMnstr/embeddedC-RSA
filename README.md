实现了大数运算（32位/64位），并基于大数运算实现了RSA算法。
# CRSA
1. implementation of bignum operations(also between bignum and num): a+b, a-b, a*b, a/b, a % b, ((a)^n)mod d.    
2. implementation of rsa encryption and decryption in C language.


Example Code:
1. bignum_mock.c :
```
This is a example code for operations of great numbers. Such as:
1. great numbers A with numbers B: A+B, A-B, A*B, A/B;
   example refer to function: bn_num_mock().
2. operations between numbers A and B:
    a. compare value of A and B: =,<,>,<=,>=;
       example refer to function: bn_cmp_mock().
    b. basic operation as: +,-,*,/,%;
       example refer to function: bn_minus_mock(), bn_add_mock(), bn_mult_mock(), bn_mod_mock().
    c. (A^B)mod C for rsa suage, which A,B and C are all great numbers.
```
2. crsa_mock.c :
```
This is a example code for rsa encryption and descryption with a pair of 256 bits rsa-key.

example key (256 bits):
public key: (
             0x10001,
             0x1594951D8C88B135C5A80AB33B4B3FDD4826ED14209C925609DAD795E7C5A10B
            )
private key: (
             0x08A25B0AE88864467C5FA070577FE2FC3D7986E61078C61611A9728B618F5FF9,
             0x1594951D8C88B135C5A80AB33B4B3FDD4826ED14209C925609DAD795E7C5A10B
            )

Output of example code:
======encrypt by public key======
plain text: 
[CRSA MOCK]: This is a crsa test, encrypt by public key and decode by private key.
repeat: [CRSA MOCK]: This is a crsa test, encrypt by public key and decode by private key.

cipher[192] 
D0 EC 79 BF 1D E3 07 5E 8C 14 6A E4 2C E3 B2 4C A1 89 8B BB D3 B7 03 8D 78 15 29 00 D8 A3 B4 0C 37 C6 2F E2 DC 10 56 0A 4A 08 6D 80 F4 41 8B 84 3A F4 09 63 09 63 CD E2 07 C4 56 0C E8 65 49 0F 85 F5 B1 FF 11 20 98 46 96 20 CB 74 B5 0C F0 75 0A F5 50 E2 A9 46 96 FC 65 B9 A6 9E 75 C7 57 15 74 08 58 5D 10 61 C9 92 3C F6 CB 71 B4 79 00 27 4A 3E 1D 43 6A 6E 81 49 43 C6 56 A6 CD 96 62 06 B8 94 FC FA F4 94 B3 49 1A 79 0A 92 BA 78 CD C7 08 CF 67 99 DE E3 34 EE 72 BE 28 D0 1C 61 92 07 5C 1D 82 10 EF D1 95 0E 0C 31 2B 2C DE DA 2B 80 0D 0B 1A 27 2F 96 E3 17 F3 7D DB 37 43 9E 05 12

decode text: 
[CRSA MOCK]: This is a crsa test, encrypt by public key and decode by private key.
repeat: [CRSA MOCK]: This is a crsa test, encrypt by public key and decode by private key.

======encrypt by private key======
plain text:
[CRSA MOCK]: This is a crsa test, encrypt by private key and decode by public key.
repeat: [CRSA MOCK]: This is a crsa test, encrypt by private key and decode by public key.

cipher[192] 
3D 20 DC E0 C8 6E 28 62 B4 6A 7A C1 1C 06 C0 1F 20 EB 60 6C 5D C4 7F 11 15 A1 35 1A 34 7E A3 05 58 78 CD B1 EF C5 8D 9D BE D0 CF 18 BD 60 04 8F C3 1A 98 86 73 C6 33 76 D1 D9 F6 78 9C 62 16 11 4D 81 DA 63 AC 59 29 BC 31 48 CF C4 9E 87 32 B4 65 D2 BC B7 D7 77 A6 62 91 57 48 43 32 1B BE 0A F2 D2 F3 FC 84 E2 F6 21 7B A7 82 45 1A C8 35 E8 38 7D 53 DE 92 F7 7C 17 8E 1C E7 2A C8 5A 09 14 D7 2D D2 C8 D9 EA EE 75 13 46 EC 35 D8 F4 EC E7 19 12 40 DF BC EF F0 CF BB 7F 5E 62 40 9C 44 07 5B 3C BF D6 4F 1B C1 E1 AF C2 C2 06 84 4A 05 34 73 29 99 C9 9F 1F A6 C7 73 DF D5 21 A1 B4 A7 03

decode text:
[CRSA MOCK]: This is a crsa test, encrypt by private key and decode by public key.
repeat: [CRSA MOCK]: This is a crsa test, encrypt by private key and decode by public key.
```
