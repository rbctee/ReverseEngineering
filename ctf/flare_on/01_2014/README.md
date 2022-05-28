# Flare-On 1 (2014)

## Sources

You can download the relevant files on this page: <https://github.com/fareedfauzi/Flare-On-Challenges/tree/master/Challenges/2014/Flare-on%201>.

### Challenge 01

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

### Challenge 03

### Challenge 04

### Challenge 05

### Challenge 06

### Challenge 07
