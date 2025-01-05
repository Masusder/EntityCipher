import base64
from Crypto.Cipher import AES
import zlib
import utils
import config

class CDNDecryption:
    @staticmethod
    def decrypt_cdn(input_text, version_with_branch):
        if not input_text:
            raise ValueError("Encrypted data cannot be empty.")

        if input_text.startswith(config.ASSET_ENCRYPTION_PREFIX):
            return CDNDecryption.decrypt_dbd_asset(input_text, version_with_branch)

        if input_text.startswith(config.PROFILE_ENCRYPTION_PREFIX):
            return CDNDecryption.decrypt_dbd_profile(input_text, version_with_branch)

        if input_text.startswith(config.ZLIB_COMPRESSION_PREFIX):
            return CDNDecryption.decompress_dbd_zlib(input_text, version_with_branch)

        if input_text and not utils.is_valid_json(input_text):
            raise Exception("Decrypted data is not a valid JSON. Most likely encryption key is invalid.")

        return input_text

    @staticmethod
    def decrypt_dbd_asset(input_text, version_with_branch):
        if not input_text.startswith(config.ASSET_ENCRYPTION_PREFIX):
            raise Exception(f"Input text does not start with {config.ASSET_ENCRYPTION_PREFIX}")

        input_text_no_prefix = input_text[len(config.ASSET_ENCRYPTION_PREFIX):]
        decoded_buffer_and_key_id = base64.b64decode(input_text_no_prefix)

        if not utils.is_valid_version(version_with_branch):
            raise Exception(f"Version {version_with_branch} is invalid")

        slice_length = len(version_with_branch) + 1 # Add 1 to compensate for heading character
        key_id_buffer = decoded_buffer_and_key_id[:slice_length]
        key_id_buffer = bytes((byte + 1) % 256 for byte in key_id_buffer)

        result_key_id = key_id_buffer.decode('ascii').replace("\u0001", "")
        encrypted_key = config.ENCRYPTED_KEYS.get(result_key_id)
        if not encrypted_key:
            raise Exception(f"Not found matching keys inside Config file, key: {result_key_id}")

        if result_key_id != version_with_branch:
            raise Exception(f"Version you passed down {version_with_branch} doesn't match to version data was encrypted with {result_key_id}")

        decrypted_key = base64.b64decode(encrypted_key)
        if not decrypted_key:
            raise Exception(f"Unknown AES key: {result_key_id}")

        decoded_buffer = decoded_buffer_and_key_id[slice_length:]
        return CDNDecryption.decrypt_dbd_symmetrical_internal(decoded_buffer, decrypted_key, version_with_branch)

    @staticmethod
    def decrypt_dbd_profile(input_text, branch):
        if not input_text.startswith(config.PROFILE_ENCRYPTION_PREFIX):
            raise Exception(f"Input text does not start with {config.PROFILE_ENCRYPTION_PREFIX}")

        input_text_no_prefix = input_text[len(config.PROFILE_ENCRYPTION_PREFIX):]
        decoded_buffer = base64.b64decode(input_text_no_prefix)
        return CDNDecryption.decrypt_dbd_symmetrical_internal(decoded_buffer, config.PROFILE_ENCRYPTION_AES_KEY,
                                                              branch)

    @staticmethod
    def decrypt_dbd_symmetrical_internal(buffer, encryption_key, branch):
        # print("Buffer Length:", len(buffer))
        # print("Encryption Key Length:", len(encryption_key))
        cipher = AES.new(encryption_key, AES.MODE_ECB)
        deciphered_buffer = cipher.decrypt(buffer)

        mutable_buffer = bytearray(deciphered_buffer)

        valid_non_padding_bytes = 0
        for i in range(len(mutable_buffer)):
            raw_byte_value = mutable_buffer[i]
            if raw_byte_value != 0:
                offset_byte_value = (raw_byte_value + 1) % 256
                mutable_buffer[i] = offset_byte_value
                valid_non_padding_bytes += 1
            else:
                break

        result_text = bytes(mutable_buffer[:valid_non_padding_bytes]).decode('ascii')
        return CDNDecryption.decrypt_cdn(result_text, branch)

    @staticmethod
    def decompress_dbd_zlib(input_text, branch):
        if not input_text.startswith(config.ZLIB_COMPRESSION_PREFIX):
            raise Exception(f"Input does not start with {config.ZLIB_COMPRESSION_PREFIX}")

        input_text_no_prefix = input_text[len(config.ZLIB_COMPRESSION_PREFIX):]
        decoded_buffer_and_deflated_length = base64.b64decode(input_text_no_prefix)
        expected_deflated_data_length = int.from_bytes(decoded_buffer_and_deflated_length[:4], byteorder='little')

        inflated_buffer = zlib.decompress(decoded_buffer_and_deflated_length[4:])
        if len(inflated_buffer) != expected_deflated_data_length:
            raise Exception(
                f"Inflated Data Length Mismatch: Expected {expected_deflated_data_length}, Received {len(inflated_buffer)}")

        result_text = inflated_buffer.decode('utf-16')
        return CDNDecryption.decrypt_cdn(result_text, branch)