import pytest
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import config
from encryption import CDNEncryption
from decryption import CDNDecryption

@pytest.fixture
def version_with_branch():
    return "8.4.2_live"

@pytest.fixture
def encrypted_data():
    """Fixture to provide encrypted test data."""
    return "DbdDAwACNy0zLTFea2h1ZAAbx+FVxVbsEyJN3925wq1WLoAyc0PBb6dCJ/es/SPhudYAzhySVIlPMPnlIxdv+OoobDhkK/hVV1JcOtm9YY3y5RSv4UnH+Lvyi4Ed65348f8HnLd0lzjY3b9sOxCgwnJi1Fm75ZL5WZYq4kNizYrYeUmJaD1ThVoZ0NB+DE/d3cMwn0mqed3r+r8L8sRm51gDpvxfZDj0ugL7Q+SWgy7SJHr4mhjH8uCtClGH+HgjlAaho2Mv6D7SlAJWsTC4ICaPXFCuObpBNl6+jSfRKe3akK4CV2cs72+ruz7ONh6RIqGelt5M3E/JMXKXDRiUcFOf9kWpgV7XrUcpUeO1ElGYgzJT/LYCt0uemXATRrM3ed5ddKXnS9EOn+dhLiKp4MBkZWeRYL9iZAssK5DHWnJgGK9nSvPKQmD5P7Lb3xIGmlioS3xQobTjMpKcToX7ssPvZrRgiDftwAniUOUIJc2X"


@pytest.fixture
def unencrypted_data():
    return "SomeUnencryptedData"


def test_encryption_with_empty_input(version_with_branch):
    """Test encryption with empty input data."""
    with pytest.raises(ValueError, match="Input data cannot be empty."):
        CDNEncryption.encrypt_cdn("", version_with_branch)

def test_encryption_decryption_consistency(encrypted_data, version_with_branch):
    """Test that decrypted data and re-encrypted data match the original."""

    decrypted_data = CDNDecryption.decrypt_cdn(encrypted_data, version_with_branch)

    re_encrypted_data = CDNEncryption.encrypt_cdn(decrypted_data, version_with_branch)

    assert re_encrypted_data == encrypted_data, "Re-encrypted data does not match the original encrypted data."

def test_encryption_of_unencrypted_data(unencrypted_data, version_with_branch):
    """Test encryption of non-encrypted (plaintext) data."""

    encrypted_result = CDNEncryption.encrypt_cdn(unencrypted_data, version_with_branch)

    assert encrypted_result != "", "Encrypted data should not be empty."
    assert encrypted_result.startswith(config.ASSET_ENCRYPTION_PREFIX)
    assert encrypted_result != unencrypted_data, "Encrypted data should be different from the original unencrypted data."

    print()
    print("Encrypted data:", encrypted_result)