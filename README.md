# Features
### Ciphers:
- Caesar cipher
- Caesar cipher breaking using frequency analysis
- Vigener cipher
- Vernam (XOR) cipher
- Files or terminal input and output
### Steganography:
- Identical chars steganography for texts (my own)

# Coming soon
- Client/server communication using ciphers with smart key exchange
- More complex ciphers
- More complex stegano
- More fun

# Installation
```
git clone https://github.com/lavawolfiee/python-project-1.1.git
cd python-project-1.1
pip install -r requirements.txt
```

# Usage
```
usage: main.py [-h] [-iF INPUT_FILE] [-oF OUTPUT_FILE]
               [-c {caesar,vigener,vernam,caesar_breaker}] [-k KEY]
               [-st {identical_chars}] [-mF MSG_FILE] [-e | -d] [-i | -ej]

Apply ciphers to files and texts

optional arguments:
  -h, --help            show this help message and exit
  -iF INPUT_FILE, --input-file INPUT_FILE
                        Input file. If doesn't set, will be used standard
                        input
  -oF OUTPUT_FILE, --output-file OUTPUT_FILE
                        Output file. If doesn't set, will be used standard
                        output
  -c {caesar,vigener,vernam,caesar_breaker}, --cipher {caesar,vigener,vernam,caesar_breaker}
                        Cipher to use
  -k KEY, --key KEY     Key for the cipher
  -st {identical_chars}, --stegano {identical_chars}
                        Stegano algorithm to use. Identical chars stegano
                        encrypts bitsof information using chars that looks
                        identical in Russian and Englishlayouts
  -mF MSG_FILE, --msg-file MSG_FILE
                        File containing the message for stegano. If doesn't
                        set, message will be read from standard input. Message
                        currently supports only ASCII chars
  -e, --encrypt         Encrypt using cipher
  -d, --decrypt         Decrypt using cipher
  -i, --inject          Inject message using stegano
  -ej, --eject          Eject message using stegano
```