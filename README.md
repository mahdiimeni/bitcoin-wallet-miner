# 🔐 Bitcoin Wallet Generator & Balance Checker  
![Python](https://img.shields.io/badge/Python-3.8%2B-blue) 
![License](https://img.shields.io/badge/License-MIT-green)  
**Secure BIP39/BIP32 Bitcoin Wallet Generator with Balance Verification**

---

## 📖 Table of Contents
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Technical Process](#-technical-process)
- [Security Warning](#%EF%B8%8F-security-warning)
- [License](#-license)

---

## 🚀 Features
- **BIP39 Compliance**: Generate 12/24-word mnemonics
- **Cryptographic Security**: HMAC-SHA512 key derivation
- **Multiple Formats**: HEX/WIF keys + legacy addresses
- **Blockchain Integration**: Real-time balance checks
- **Dual API Methods**: SDK + REST implementations

---

## 📦 Installation
```bash
git clone https://github.com/yourusername/bitcoin-wallet-generator.git
cd bitcoin-wallet-generator
pip install -r requirements.txt
```

#### requirements.txt
```
pybip39
bitcoin
blockcypher
base58
```

## 💻 Usage
```
python wallet_generator.py
```

#### Sample Output
```
--- Generated Seed Phrase ---
olympic wage cousin battle...  # 12 random words

Private Key (hex): 5d8a...f3e1
Bitcoin Address:  1CounterpartyXXXXXXXXXXXXXXXUWLpVr
Private Key (WIF): Kx983JD...S2RtHJy
Current Balance:  0.00000000 BTC
```
## 🔧 Technical Process
Wallet Generation Workflow
1. Mnemonic → BIP39 entropy generation
2. Seed → PBKDF2 derivation (empty passphrase)
3. Master Key → HMAC-SHA512("Bitcoin seed", seed)[:32]
4. Address → Legacy P2PKH derivation

#### WIF Conversion
```
def hex_to_wif(hex_key):
    # 1. Add 0x80 prefix
    # 2. Double SHA-256 checksum
    # 3. Base58Check encoding
    return base58.b58encode(...)
```
#### API Implementations
#### Active Method (SDK)
```
from blockcypher import get_address_overview
balance = get_address_overview(address, 'btc')['final_balance']/1e8
```

#### Alternative Method (Preserved in Code)
```
# import requests
# response = requests.get(f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance")
```

## ⚠️ Security Warning
### ‼️ Critical Notice ‼️
This software generates REAL BITCOIN PRIVATE KEYS.

#### Never:

- Use generated keys for real funds

- Share generated keys publicly

- Run on internet-connected devices

#### Features:

- Rate limited (1 req/sec)

- Educational use only

- No warranty provided
- Its JUST FOR FUN!

## 🔒 Why Brute-Force Attacks Are Impractical
### Mathematical Reality:
- Key Space Size: Bitcoin private keys use 256-bit cryptography (2²⁵⁶ possible combinations).

- Comparison: There are ≈10⁸⁰ atoms in the observable universe vs 10⁷⁷ possible keys.

### Computational Limits:
- Processing Power: Even with 1 trillion guesses/second, checking 0.0000001% of keys would take ≈3.8×10⁵⁷ years.

- Energy Cost: Brute-forcing one key would consume more energy than our sun will produce in its lifetime.

### Cryptographic Security:
- Algorithm Strength: SHA-256 and ECDSA remain quantum-resistant and unbroken.

- Address Randomness: Modern wallets use HD derivation (BIP32/BIP44) making pattern detection impossible.

### Practical Reality:
- Success Probability: Lower than randomly finding a specific atom on Earth... twice.

- Economic Incentive: Energy costs would exceed potential rewards by astronomical margins.

This explains why even nation-state attackers avoid brute-force methods against properly generated wallets. Always use strong seed phrases!

## 📜 License
MIT License - Full terms in LICENSE file

Disclaimer: This project is for EDUCATIONAL PURPOSES ONLY. Not responsible for lost funds or security breaches. Use at extreme caution.

Made with ❤️ by [Mahdi Imeni] - Blockchain Security Research






