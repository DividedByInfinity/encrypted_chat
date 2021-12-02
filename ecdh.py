from secrets import token_bytes

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

FORMAT = 'utf-8'
BLOCK_SIZE = 16


class DH:
    def __init__(self):
        self.ECDH = ec.generate_private_key(ec.SECP384R1(), default_backend())  # PRIVATE KEY 384 BIT LONG
        self.public_key = self.ECDH.public_key()  # PUBLIC KEY : CHANGE BETWEEN CLIENTS

    def encrypt(self, public_key, plaintext):
        """
        IV = 16 bytes
        SALT = 16 bytes
        Shared key = 48 bytes
        Derived key = 32 bytes

        AES = 256 bits
        AES = 32 bytes

        Padder = 256 bits
        Padder = 32 bytes

        Ciphertext = IV + SALT + MSG

        :param public_key: another client public key
        :param plaintext: a text to be encrypted
        :return: encrypted ciphertext
        """
        IV = token_bytes(16)  # INITIALIZING VECTOR 16 BYTES : SEND WITH CIPHER TEXT
        SALT = token_bytes(16)  # SALT FOR DERIVATION A SHARED KEY
        shared_key = self.ECDH.exchange(ec.ECDH(), public_key)  # GEN SHARED KEY FROM ANOTHER CLIENT PUBLIC KEY

        derived_key = HKDF(  # DERIVE KEY FOR MORE STRENGTH
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            info=None
        ).derive(shared_key)

        encryptor = Cipher(
            algorithms.AES(derived_key),
            modes.CBC(IV)
        ).encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode(FORMAT)) + padder.finalize()

        # print('* # * ' * 10)
        # print('Encrypt info')
        # print('* # * ' * 10)
        print('enc IV', IV)

        print('enc SALT', SALT)
        # print('IV bytes\t\t', len(IV))
        print('enc Shared', shared_key)

        # print('Shared bytes\t', len(shared_key))
        print('enc Derived', derived_key)

        # print('Derived bytes\t', len(derived_key))
        # print('AES bits\t\t', aes.algorithm.key_size)
        # print('AES bytes\t\t', int(aes.algorithm.key_size / 8))
        # print('Padder bits\t\t', padder.block_size)
        # print('Padder bytes\t', int(padder.block_size / 8))
        print('enc Padded', padded_data)

        # print('Plaintxt bytes\t', len(bytes(plaintext.encode(FORMAT))))
        # print('Padded bytes\t', len(padded_data) - len(bytes(plaintext.encode(FORMAT))))

        # print('Cipher\t\t\t', prep_cipher)
        # print('Cipher bytes\t', len(prep_cipher))
        # print(prep_cipher[:16])
        # print(prep_cipher[16:32])
        # print(prep_cipher[32:])

        return IV + SALT + encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, public_key, ciphertext):
        IV = ciphertext[:16]
        SALT = ciphertext[16:32]
        ciphertext = ciphertext[32:]

        shared_key = self.ECDH.exchange(ec.ECDH(), public_key)  # GEN SHARED KEY FROM ANOTHER CLIENT PUBLIC KEY

        derived_key = HKDF(  # DERIVE KEY FOR MORE STRENGTH
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            info=None
        ).derive(shared_key)

        decryptor = Cipher(
            algorithms.AES(derived_key),
            modes.CBC(IV)
        ).decryptor()

        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()

        print('dec IV', IV)
        print('dec SALT', SALT)
        print('dec Ciphertext', ciphertext)
        print('dec Shared', shared_key)
        print('dec Derived', derived_key)
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        print('dec Unpadded', unpadded_data)

        return unpadded_data

    def serialize_public(self):
        serialized_public = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return serialized_public

    def unserialize_public(self, public_key):
        loaded_public_key = serialization.load_pem_public_key(
            public_key,
        )
        return loaded_public_key

# Client1 = DH()
# Client2 = DH()
#
# alice_ciphertext = Client1.encrypt(Client2.public_key, 'It works!')
#
# bob_plaintext = Client2.decrypt(Client1.public_key, alice_ciphertext)
#
# print('ciphertext\t', alice_ciphertext)
# print('plaintext\t', bob_plaintext)
