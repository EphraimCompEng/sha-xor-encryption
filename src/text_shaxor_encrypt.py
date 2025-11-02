#! usr/bin/env python3

"""
A simple program to XOR cipher text.

This program is to a tool to learn how to XOR cipher.
This is NOT a secure method of encryption.
Use at your own risk.

Text will be XOR ciphered using a SHA-3 hash
SHA3-256 ("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a

Sources:
https://en.wikipedia.org/wiki/SHA-3#Examples_of_SHA-3_variants
https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values#aHashing
"""

def sha_xor_encrypt(text :str, sha_string :str):
    if type(text) is str:
        text_bin = "".join(f"{ord(char):08b}" for char in text)  # converting text to binary via ascii(ord) encodings
        text_len = len(text_bin)
        repeat_len = text_len >> 8  # identical to x/256
        if repeat_len >= 1:
            # text is longer than SHA3-256 hash? -> hash repeated
            """TODO"""
            print("\nSorry something went wrong")
            raise IndexError
        else:
            # text is shorter than SHA3-256 hash? -> text repeated
            repeat_len = (256 / text_len)  # how many times the text, in binary, repeats within 256 bits

            # duplicate text_bin until it's length > 256 bits
            temp_text_bin = text_bin * int(repeat_len + 1) # +1 ensures text will overlap hash
            sha_bin = bin(int(sha_string, 16)) # convert sha_string from hex to binary
            cipher = int(temp_text_bin[:256], 2) ^ int(sha_bin, 2)  # binary characters XOR binary sha_string
            output_cipher = hex(cipher)

            # # debugging
            # print(temp_text_bin, len(temp_text_bin))
            # print(sha_bin, len(sha_bin))
            # print(temp_text[:256], len(temp_text[:256]))
            return output_cipher[2:]
    else:
        """
        TODO:

        Int edge case can progress once converted to binary and duplicated.
        Maybe int -> str -> dupe str -> XOR?
        Issue: converting back to the original integer returns str...
        Need data inside encrypted message to indicate type and length of data?
        """
        print("\nSorry something went wrong")
        raise ValueError


def sha_xor_decrypt(cipher :str, sha_string :str):
    if type(cipher) is str:
        if len(cipher) > 256 or len(cipher) != len(sha_string):
            # invalid cipher or (cipher, sha_string) pairs
            raise ValueError
        else:
            sha_bin = bin(int(sha_string, 16)) # convert sha_string from hex to binary
            reverse_cipher = int(cipher, 16) ^ int(sha_bin, 2) # binary cipher XOR binary sha_string
            original_text = reverse_cipher.to_bytes(len(bin(reverse_cipher)) // 8, 'big').decode() # convert bin to text, "//" divides and returns int(float)

            # # debugging
            # print(bin(reverse_cipher), len(bin(reverse_cipher)))
            # print(original_text)
            return original_text

    else:
        # cipher should always result in hex str
        print("\nInvalid data type.")
        raise TypeError


def main():
    sha3_256 = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    encrpyted_text = sha_xor_encrypt("testing", sha3_256)
    raw_text = sha_xor_decrypt(encrpyted_text, sha3_256)

    # # debugging
    # print(encrpyted_text, type(encrpyted_text), len(encrpyted_text), bin(int(encrpyted_text, 16)), len(bin(int(encrpyted_text, 16))))
    print(encrpyted_text)
    print(raw_text)
    return

main()
