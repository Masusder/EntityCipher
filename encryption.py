from Crypto.Cipher import AES
import base64
import zlib
import config

class CDNEncryption:
    @staticmethod
    def encrypt_cdn(data, version_with_branch):
        if not data:
            raise ValueError("Input data cannot be empty.")

        decrypted_key = CDNEncryption.get_decrypted_key(version_with_branch)
        cipher = AES.new(decrypted_key, AES.MODE_ECB)

        utf16_data = data.encode('utf-16-le')
        compressed_data = zlib.compress(utf16_data)
        data_length_little_endian = len(utf16_data).to_bytes(4, byteorder='little')

        encoded_data = CDNEncryption.encode_with_zlib_prefix(compressed_data, data_length_little_endian)
        encrypted_data = CDNEncryption.encrypt_with_aes(cipher, encoded_data)

        base64_key_id = CDNEncryption.get_base64_key_id(version_with_branch)
        encrypted_content = CDNEncryption.construct_encrypted_content(encrypted_data, base64_key_id)

        return encrypted_content

    @staticmethod
    def get_decrypted_key(version_with_branch):
        encrypted_key = config.ENCRYPTED_KEYS.get(version_with_branch)
        if not encrypted_key:
            raise Exception(f"Not found matching keys inside Config file, key: {version_with_branch}")
        return base64.b64decode(encrypted_key)

    @staticmethod
    def encode_with_zlib_prefix(compressed_data, data_length_little_endian):
        zlib_base64 = data_length_little_endian + compressed_data
        zlib_with_prefix = config.ZLIB_COMPRESSION_PREFIX.encode() + base64.b64encode(zlib_base64)
        aes_ready_data = [(byte - 1) for byte in zlib_with_prefix]
        while len(aes_ready_data) % 16 != 0:
            aes_ready_data.append(0)
        return bytes(aes_ready_data)

    @staticmethod
    def encrypt_with_aes(cipher, data):
        encrypted_data = cipher.encrypt(data)
        base64_raw = b"d\x00" + encrypted_data # Add heading character
        return base64.b64encode(base64_raw)

    @staticmethod
    def get_base64_key_id(version_with_branch):
        key_id_buffer = bytes((byte - 1) % 256 for byte in version_with_branch.encode())
        key_id_buffer = key_id_buffer[:-1]
        return base64.b64encode(key_id_buffer).decode("ascii")

    @staticmethod
    def construct_encrypted_content(encrypted_data, base64_key_id):
        return (
                config.ASSET_ENCRYPTION_PREFIX +
                base64_key_id +
                encrypted_data.decode()
        )
