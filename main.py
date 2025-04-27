"""
Bitcoin Wallet Generator with Balance Checker

Generates BIP39/BIP32-compliant Bitcoin wallets and checks their balance using BlockCypher API.
Includes both direct API call and official SDK methods for balance checking.

Security Note: This generates real valid Bitcoin keys. Handle with extreme care!
"""

import hashlib
import hmac
from time import sleep

# Cryptographic utilities
import base58  # For Base58Check encoding
import bitcoin  # For address generation
from blockcypher import get_address_overview  # Blockchain API SDK
from pybip39 import Mnemonic, Seed  # BIP39 implementation


def bip32_derive_master_key(seed_bytes):
    """Derives BIP32 master private key from BIP39 seed using HMAC-SHA512.

    Args:
        seed_bytes (bytes): 64-byte BIP39 seed

    Returns:
        bytes: 32-byte master private key (first half of HMAC result)
    """
    hmac_result = hmac.new(
        key=b"Bitcoin seed",  # Standard BIP32 seed key
        msg=seed_bytes,
        digestmod=hashlib.sha512
    ).digest()

    return hmac_result[:32]  # Left half for private key


def hex_to_wif(hex_key):
    """Converts raw hexadecimal private key to Wallet Import Format (WIF).

    Process:
        1. Add mainnet prefix (0x80)
        2. Double SHA-256 checksum
        3. Base58Check encoding

    Args:
        hex_key (str): 64-character hexadecimal private key

    Returns:
        str: Base58Check encoded WIF private key
    """
    # Add Bitcoin mainnet prefix
    prefixed_key = "80" + hex_key

    # Calculate checksum
    sha256_1 = hashlib.sha256(bytes.fromhex(prefixed_key)).digest()
    sha256_2 = hashlib.sha256(sha256_1).digest()
    checksum = sha256_2[:4].hex()  # First 4 bytes as checksum

    # Assemble full payload
    full_key = prefixed_key + checksum

    # Base58Check encoding
    return base58.b58encode(bytes.fromhex(full_key)).decode("utf-8")


def get_balance(address):
    """Retrieves Bitcoin balance using BlockCypher's official SDK.

    Args:
        address (str): Bitcoin address to check

    Returns:
        float: Balance in BTC or None if error occurs
    """
    try:
        # Get address info from BlockCypher
        address_info = get_address_overview(address, coin_symbol='btc')
        # Convert satoshis to BTC (1 BTC = 100,000,000 satoshis)
        return address_info['final_balance'] / 1e8
    except Exception as e:
        print(f"Balance check failed for {address}: {str(e)}")
        return None


# Alternative implementation preserved for reference
# def get_balance(address):
#     """Retrieve balance using direct API calls (preserved as reference)."""
#     url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance"
#     response = requests.get(url)
#
#     if response.status_code == 200:
#         data = response.json()
#         return data["final_balance"] / 1e8  # Convert satoshis to BTC
#     else:
#         print(f"Error fetching balance: {response.status_code}")
#         return None


def generate_wallet():
    """Generates a complete Bitcoin wallet suite."""
    # Create BIP39 mnemonic
    mnemonic = Mnemonic()  # Generates 128-bit entropy by default
    print(f"\n--- Generated Seed Phrase ---\n{mnemonic}")

    # Derive BIP39 seed
    seed = Seed(mnemonic, "")  # Empty passphrase
    seed_bytes = bytes(seed)

    # BIP32 master key derivation
    private_key = bip32_derive_master_key(seed_bytes)

    # Generate Bitcoin address
    address = bitcoin.privkey_to_address(private_key)

    return private_key, address


if __name__ == "__main__":
    while True:
        # Generate new wallet
        priv_key, btc_address = generate_wallet()

        # Display key information
        print(f"Private Key (hex): {priv_key.hex()}")
        print(f"Bitcoin Address:  {btc_address}")
        print(f"Private Key (WIF): {hex_to_wif(priv_key.hex())}")

        # Check and display balance
        balance = get_balance(btc_address)
        if balance is not None:
            print(f"Current Balance:  {balance:.8f} BTC")

        # Rate limit to 1 request/sec (BlockCypher's free tier limit)
        sleep(1)
