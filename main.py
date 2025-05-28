import streamlit as st
from bip_utils import (
    Bip39MnemonicGenerator, Bip39SeedGenerator,
    Bip44, Bip44Coins, Bip44Changes,
    Bip32Slip10Ed25519
)
from solders.keypair import Keypair

# ----------------- Streamlit App Setup -----------------
st.set_page_config(page_title="Kiniun 🦁 Wallet", page_icon="🦁")
st.title("🦁 Kiniun Wallet Generator")
st.markdown("Securely create or import a **Solana + EVM** wallet using your seed phrase and optional passphrase.")

# ----------------- Input Fields -----------------
st.subheader("🧠 Mnemonic (Seed Phrase)")
mnemonic_input = st.text_area("Enter your 12 or 24-word mnemonic seed phrase:", placeholder="leave empty to generate a new one")

st.subheader("🔐 Optional Passphrase")
passphrase = st.text_input("Enter your passphrase (advanced users only):", type="password", placeholder="You can leave this empty")

st.caption("⚠️ Never share your seed phrase or passphrase with anyone. Anyone with access can control your funds.")

# ----------------- Generate / Import Wallet -----------------
if st.button("🚀 Generate / Import Wallet"):
    # Generate a new mnemonic if not provided
    if not mnemonic_input.strip():
        mnemonic = Bip39MnemonicGenerator().FromWordsNumber(12)
        st.success("✅ New 12-word seed phrase generated!")
    else:
        mnemonic = mnemonic_input.strip()

    st.code(mnemonic, language="text")
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)

    # ---------- Ethereum Wallet (BIP44) ----------
    bip44_eth = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM) \
        .Purpose() \
        .Coin() \
        .Account(0) \
        .Change(Bip44Changes.CHAIN_EXT) \
        .AddressIndex(0)

    eth_address = bip44_eth.PublicKey().ToAddress()
    eth_private_key = "0x" + bip44_eth.PrivateKey().Raw().ToHex()

    # ---------- Solana Wallet ----------
    def hardened_index(index): return index + 0x80000000

    solana_key = Bip32Slip10Ed25519.FromSeed(seed_bytes) \
        .ChildKey(hardened_index(44)) \
        .ChildKey(hardened_index(501)) \
        .ChildKey(hardened_index(0)) \
        .ChildKey(hardened_index(0))

    solana_private_key_bytes = solana_key.PrivateKey().Raw().ToBytes()
    solana_keypair = Keypair.from_seed(solana_private_key_bytes)
    solana_address = solana_keypair.pubkey()
    solana_private_key = solana_keypair

    # ----------------- Output Results -----------------
    st.subheader("📜 Seed Phrase Used")
    st.code(str(mnemonic), language="text")

    st.subheader("🦊 Ethereum (EVM) Wallet")
    st.caption("📬 Address")
    st.code(str(eth_address), language="text")
    st.caption("🔑 Private Key")
    st.code(str(eth_private_key), language="text")

    st.subheader("🛸 Solana Wallet")
    st.caption("📬 Address")
    st.code(str(solana_address), language="text")
    st.caption("🔑 Private Key")
    st.code(str(solana_private_key), language="text")

    st.caption("⚠️ Always store your seed phrase and passphrase securely. Avoid saving it in plaintext or online documents.")

    st.success("🦁 Wallet generated successfully! You can now use it to interact with Solana and Ethereum networks.")
