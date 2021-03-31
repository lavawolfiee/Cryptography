import argparse
from collections import Counter
import numpy as np
import sys


class Caesar:
    def encrypt(self, data, shift):
        s = ""

        for c in data:
            if not c.isalpha():
                s += c
            elif c.lower() == c:
                s += chr(((ord(c) - 97 + shift) % 26 + 26) % 26 + 97)
            else:
                s += chr(((ord(c) - 65 + shift) % 26 + 26) % 26 + 65)

        return s

    def decrypt(self, data, shift):
        return self.encrypt(data, -shift)


class Vigener:
    def encrypt(self, data, key):
        s = ""

        for i, c in enumerate(data):
            k = ord(key[i % len(key)].lower()) - 97
            if not c.isalpha():
                s += c
            elif c.lower() == c:
                s += chr((ord(c) - 97 + k) % 26 + 97)
            else:
                s += chr((ord(c) - 65 + k) % 26 + 65)

        return s

    def decrypt(self, data, key):
        s = ""

        for i, c in enumerate(data):
            k = ord(key[i % len(key)].lower()) - 97
            if not c.isalpha():
                s += c
            elif c.lower() == c:
                s += chr(((ord(c) - 97 - k) % 26 + 26) % 26 + 97)
            else:
                s += chr(((ord(c) - 65 - k) % 26 + 26) % 26 + 65)

        return s


class Vernam:
    def encrypt(self, data, key):
        bytes_data = bytearray(data, encoding='utf-8')
        bytes_key = bytearray(key, encoding='utf-8')
        ans = bytearray()

        for i, b in enumerate(bytes_data):
            k = bytes_key[i % len(bytes_key)]
            ans.append(b ^ k)

        return ans.decode('utf-8')

    def decrypt(self, data, key):
        return self.encrypt(data, key)


class CaesarBreaker:
    def __init__(self):
        self.__target_freqs = {'e': 0.127, 't': 0.0906, 'a': 0.0817, 'o': 0.0751, 'i': 0.0697, 'n': 0.0675,
                               's': 0.0633, 'h': 0.0609, 'r': 0.0599, 'd': 0.0425, 'l': 0.0403, 'c': 0.0278,
                               'u': 0.0276, 'm': 0.0241, 'w': 0.0241, 'f': 0.0223, 'g': 0.0202, 'y': 0.0197,
                               'p': 0.0193, 'b': 0.0149, 'v': 0.0098, 'k': 0.0077, 'x': 0.0015, 'j': 0.0015,
                               'q': 0.001, 'z': 0.0005}

    def __get_freqs(self, data):
        n = len(data)
        ans = {}

        for k, v in Counter(data.lower()).items():
            ans[k] = v / n

        return ans

    def __freq_score(self, data):
        score = 0
        freqs = self.__get_freqs(data)

        for k, v in self.__target_freqs.items():
            if k in freqs:
                score += (v - freqs[k]) ** 2
            else:
                score += v ** 2

        return score

    def break_cipher(self, data):
        results = []
        c = Caesar()

        for i in range(0, 26):
            results.append(self.__freq_score(c.decrypt(data, i)))

        ind = np.argmin(results)
        return c.decrypt(data, ind), ind


class IdenticalCharsStegano:
    def __init__(self):
        self.__zeros = 'АаОоКТРрЕеСсХх'  # on Russian
        self.__ones = 'AaOoKTPpEeCcXx'  # on English
        self.__alphabet = self.__zeros + self.__ones

    def text_capacity(self, text):
        count = 0
        for c in text:
            if c in self.__alphabet:
                count += 1

        return count

    def int_to_bits(self, n):
        b = [n // 256, n % 256]
        result = []
        for i in b:
            bits = bin(i)[2:]
            bits = '00000000'[len(bits):] + bits
            result.extend([bool(int(b)) for b in bits])
        return result

    def str_to_bits(self, s):
        result = []
        for c in s:
            bits = bin(ord(c))[2:]
            bits = '0' * (8 - len(bits) % 8) + bits
            result.extend([bool(int(b)) for b in bits])
        return result

    def bits_to_str(self, bits):
        chars = []
        for b in range(len(bits) // 8):
            byte = bits[b * 8:(b + 1) * 8]
            chars.append(chr(int(''.join([str(int(bit)) for bit in byte]), 2)))
        return ''.join(chars)

    def bits_to_int(self, bits):
        bytes = []
        for b in range(len(bits) // 8):
            byte = bits[b * 8:(b + 1) * 8]
            bytes.append(int(''.join([str(int(bit)) for bit in byte]), 2))

        n = 0

        for i, b in enumerate(bytes):
            n += b * (2 ** (8 * (len(bytes) - 1 - i)))

        return n

    def inject(self, text, data):
        text = list(text)
        data_bits = self.str_to_bits(data)
        preamble = self.int_to_bits(len(data_bits))
        bits = preamble + data_bits
        bit = 0

        for i, c in enumerate(text):
            if bit == len(bits):
                break

            ind = self.__alphabet.find(c)
            if ind != -1:
                ind %= len(self.__zeros)
                if bits[bit]:
                    text[i] = self.__ones[ind]
                else:
                    text[i] = self.__zeros[ind]
                bit += 1

        return "".join(text)

    def eject(self, text):
        def reader(_text):
            for c in text:
                ind = self.__alphabet.find(c)

                if ind != -1:
                    if ind >= len(self.__zeros):
                        yield True
                    else:
                        yield False

        r = reader(text)
        n_bits = []

        for i in range(16):
            try:
                n_bits.append(next(r))
            except StopIteration:
                return ""

        n = self.bits_to_int(n_bits)

        msg_bits = []

        for i in range(n):
            try:
                msg_bits.append(next(r))
            except StopIteration:
                break

        return self.bits_to_str(msg_bits)


def main():
    parser = argparse.ArgumentParser(add_help=True, description='Apply ciphers to files and texts')
    parser.add_argument('-iF', '--input-file', action='store', type=str, dest='input_file',
                        help='Input file. If doesn\'t set, will be used standard input')
    parser.add_argument('-oF', '--output-file', action='store', type=str, dest='output_file',
                        help='Output file. If doesn\'t set, will be used standard output')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-c', '--cipher', action='store', type=str, dest='cipher',
                       choices=['caesar', 'vigener', 'vernam', 'caesar_breaker'], default=None,
                       help='Cipher to use')
    parser.add_argument('-k', '--key', action='store', type=str, dest='key',
                        help='Key for the cipher')
    group.add_argument('-st', '--stegano', action='store', type=str, dest='stegano',
                       choices=['identical_chars'], default=None,
                       help='Stegano algorithm to use.\nIdentical chars stegano encrypts bits'
                            'of information using chars that looks identical in Russian and English'
                            'layouts')
    parser.add_argument('-mF', '--msg-file', action='store', type=str, dest='msg_file',
                        help='File containing the message for stegano. If doesn\'t set, '
                             'message will be read from standard input. '
                             'Message currently supports only ASCII chars')
    group2 = parser.add_mutually_exclusive_group()
    group2.add_argument('-e', '--encrypt', action='store_true', dest='encrypt',
                        help='Encrypt using cipher')
    group2.add_argument('-d', '--decrypt', action='store_true', dest='decrypt',
                        help='Decrypt using cipher')
    group3 = parser.add_mutually_exclusive_group()
    group3.add_argument('-i', '--inject', action='store_true', dest='inject',
                        help='Inject message using stegano')
    group3.add_argument('-ej', '--eject', action='store_true', dest='eject',
                        help='Eject message using stegano')

    args = parser.parse_args()

    input_data = ""

    if args.input_file:
        try:
            with open(args.input_file, "r", encoding='utf-8') as f:
                input_data = f.read()
        except:
            print("Can't read input file " + args.input_file)
            sys.exit(1)
    else:
        input_data = input()

    output_data = input_data

    if args.cipher:
        if args.cipher == 'caesar':
            if not args.key:
                print("You must set the key for Caesar")
                sys.exit(1)
            else:
                try:
                    k = int(args.key)
                except:
                    print("Key for Caesar must be integer")
                    sys.exit()

                c = Caesar()
                if args.encrypt:
                    output_data = c.encrypt(input_data, k)
                elif args.decrypt:
                    output_data = c.decrypt(input_data, k)
        elif args.cipher == 'vigener':
            if not args.key:
                print("You must set the key for Vigener")
                sys.exit(1)
            else:
                if not args.key.isalpha():
                    print("Key for Vigener must be alphabetic")
                    sys.exit(1)
                else:
                    v = Vigener()
                    if args.encrypt:
                        output_data = v.encrypt(input_data, args.key)
                    elif args.decrypt:
                        output_data = v.decrypt(input_data, args.key)
        elif args.cipher == 'vernam':
            if not args.key:
                print("You must set the key for Vernam")
                sys.exit(1)
            else:
                v = Vernam()
                if args.encrypt:
                    output_data = v.encrypt(input_data, args.key)
                elif args.decrypt:
                    output_data = v.decrypt(input_data, args.key)
        elif args.cipher == 'caesar_breaker':
            cb = CaesarBreaker()
            output_data = cb.break_cipher(input_data)[0]
    elif args.stegano:
        if args.stegano == 'identical_chars':
            st = IdenticalCharsStegano()

            if args.inject:
                msg = ""

                if args.msg_file:
                    try:
                        with open(args.msg_file, 'r', encoding='utf-8') as f:
                            msg = f.read()
                    except:
                        print("Can't read message file " + args.msg_file)
                else:
                    msg = input()

                output_data = st.inject(input_data, msg)
                n = st.text_capacity(input_data) - 16
                print("[INFO] Text capacity is {} bits or {} bytes".format(n, n // 8))
            elif args.eject:
                output_data = st.eject(input_data)

    if args.output_file:
        try:
            with open(args.output_file, "w", encoding='utf-8') as f:
                f.write(output_data)
        except:
            print('Can\'t write output data to file ' + args.output_file)
            sys.exit(1)
    else:
        print(output_data)


if __name__ == "__main__":
    main()
