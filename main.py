from decryption import CDNDecryption
from encryption import CDNEncryption
import utils

if __name__ == '__main__':
    decrypt_data = True # Choose whether to decrypt or encrypt

    data_to_decrypt = utils.read_file("input_data_decryption.txt")
    data_to_encrypt = utils.read_file("input_data_encryption.json")
    version_with_branch = "8.4.2_live"

    is_version_valid = utils.is_valid_version(version_with_branch)

    if not is_version_valid:
        raise Exception(f"Version {version_with_branch} is invalid.")

    if decrypt_data:
        decrypted_data = CDNDecryption.decrypt_cdn(data_to_decrypt, version_with_branch)
        decryption_output_file_name = "output_decrypted.json"

        print(decrypted_data)
        print(f"Decrypted data was saved to {decryption_output_file_name}")

        utils.write_to_file(decryption_output_file_name, decrypted_data)
    else:
        encrypted_data = CDNEncryption.encrypt_cdn(data_to_encrypt, version_with_branch)
        encryption_output_file_name = "output_encrypted.txt"

        print(encrypted_data)
        print(f"Encrypted data was saved to {encryption_output_file_name}")

        utils.write_to_file(encryption_output_file_name, encrypted_data)