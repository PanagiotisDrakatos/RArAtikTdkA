import binascii
import io


class PKCS7Encoder(object):
    def __init__(self, k=16):
        self.k = k

    def decode(self, text):
        nl = len(text)

        val = int(binascii.hexlify(text[-1]), 16)
        if val > self.k:
            raise ValueError('Input is not padded or padding is corrupt')

        l = nl - val
        return text[:l]


    def encode(self, text):
        l = len(text)
        output = io.StringIO()
        val = self.k - (l % self.k)
        for _ in range(val):
            output.write('%02x' % val)
        return text + binascii.unhexlify(output.getvalue())
