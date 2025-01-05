import pytest
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import utils
from decryption import CDNDecryption

@pytest.fixture
def encrypted_data():
    """Fixture to provide encrypted test data."""
    return "DbdDAwACNy0zLTFea2h1ZAAbx+FVxVbsEyJN3925wq1WLoAyc0PBb6dCJ/es/SPhudYAzhySVIlPMPnlIxdv+OoobDhkK/hVV1JcOtm9YY3y5RSv4UnH+Lvyi4Ed65348f8HnLd0lzjY3b9sOxCgwnJi1Fm75ZL5WZYq4kNizYrYeUmJaD1ThVoZ0NB+DE/d3cMwn0mqed3r+r8L8sRm51gDpvxfZDj0ugL7Q+SWgy7SJHr4mhjH8uCtClGH+HgjlAaho2Mv6D7SlAJWsTC4ICaPXFCuObpBNl6+jSfRKe3akK4CV2cs72+ruz7ONh6RIqGelt5M3E/JMXKXDRiUcFOf9kWpgV7XrUcpUeO1ElGYgzJT/LYCt0uemXATRrM3ed5ddKXnS9EOn+dhLiKp4MBkZWeRYL9iZAssK5DHWnJgGK9nSvPKQmD5P7Lb3xIGmlioS3xQobTjMpKcToX7ssPvZrRgiDftwAniUOUIJc2X"

@pytest.fixture
def version_with_branch():
    """Fixture to provide the version and branch."""
    return "8.4.2_live"

def test_decryption(encrypted_data, version_with_branch):
    decrypted_data = CDNDecryption.decrypt_cdn(encrypted_data, version_with_branch)

    try:
        parsed_data = utils.parse_json(decrypted_data)

        assert isinstance(parsed_data, dict)
        print()
        print("Decrypted content is valid JSON and a dictionary.")
    except ValueError as e:
        print(f"Error: {e}")
        pytest.fail(f"Decrypted content is not valid JSON: {decrypted_data}")


def test_empty_data(version_with_branch):
    """Test decryption with empty encrypted data."""
    empty_data = ""

    with pytest.raises(ValueError, match="Encrypted data cannot be empty."):
        CDNDecryption.decrypt_cdn(empty_data, version_with_branch)


def test_decryption_with_invalid_version(encrypted_data):
    """Test decryption with an invalid version."""
    invalid_version_with_branch = "8.4.2_fakebranch"

    with pytest.raises(Exception, match=r"Version \S+ is invalid|Version you passed down \S+ doesn't match to version data was encrypted with \S+"):
        CDNDecryption.decrypt_cdn(encrypted_data, invalid_version_with_branch)