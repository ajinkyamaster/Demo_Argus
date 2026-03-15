"""
Blockchain anchor — stores PDF report hashes on Sepolia via a simple smart contract.
Uses web3.py with an Alchemy RPC endpoint and a server-side wallet.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from dotenv import load_dotenv
from web3 import Web3

load_dotenv()

# ── Configuration ────────────────────────────────────────────────────────────

RPC_URL = os.getenv("ALCHEMY_RPC_URL", "")
CONTRACT_ADDRESS = os.getenv("ANCHOR_CONTRACT_ADDRESS", "")
PRIVATE_KEY = os.getenv("ANCHOR_PRIVATE_KEY", "")

# Minimal ABI — only the functions we call
CONTRACT_ABI = [
    {
        "inputs": [{"internalType": "bytes32", "name": "reportHash", "type": "bytes32"}],
        "name": "storeHash",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "reportHash", "type": "bytes32"}],
        "name": "verifyHash",
        "outputs": [
            {"internalType": "bool", "name": "exists", "type": "bool"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
]

SEPOLIA_CHAIN_ID = 11155111


# ── Data types ───────────────────────────────────────────────────────────────


@dataclass
class AnchorResult:
    pdf_hash: str        # hex SHA-256 of the PDF bytes
    tx_hash: str         # Ethereum transaction hash (with 0x prefix)
    block_number: int    # block the tx was mined in
    block_timestamp: int # Unix timestamp of that block
    etherscan_url: str   # link to Sepolia Etherscan


# ── Helpers ──────────────────────────────────────────────────────────────────


def _get_web3() -> Web3:
    """Initialize and return a Web3 instance connected to Sepolia."""
    if not RPC_URL:
        raise RuntimeError("ALCHEMY_RPC_URL is not set in .env")
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        raise ConnectionError(f"Cannot connect to RPC at {RPC_URL}")
    return w3


def hash_pdf(pdf_bytes: bytes) -> bytes:
    """SHA-256 hash the PDF, return raw 32 bytes (suitable for bytes32)."""
    return hashlib.sha256(pdf_bytes).digest()


# ── Public API ───────────────────────────────────────────────────────────────


def anchor_hash(pdf_bytes: bytes) -> AnchorResult:
    """
    Hash the PDF and store the hash on Sepolia.
    Blocks until the tx is mined (~12-15 s). Call via asyncio.to_thread().
    """
    if not CONTRACT_ADDRESS or not PRIVATE_KEY:
        raise RuntimeError(
            "ANCHOR_CONTRACT_ADDRESS and ANCHOR_PRIVATE_KEY must be set in .env"
        )

    w3 = _get_web3()
    account = w3.eth.account.from_key(PRIVATE_KEY)
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(CONTRACT_ADDRESS),
        abi=CONTRACT_ABI,
    )

    pdf_hash = hash_pdf(pdf_bytes)

    # Build the transaction
    tx = contract.functions.storeHash(pdf_hash).build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "gas": 100_000,
            "gasPrice": w3.eth.gas_price,
            "chainId": SEPOLIA_CHAIN_ID,
        }
    )

    # Sign and send
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)

    # Wait for receipt (blocks until mined)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    block = w3.eth.get_block(receipt.blockNumber)

    tx_hash_hex = receipt.transactionHash.hex()
    return AnchorResult(
        pdf_hash=pdf_hash.hex(),
        tx_hash=f"0x{tx_hash_hex}" if not tx_hash_hex.startswith("0x") else tx_hash_hex,
        block_number=receipt.blockNumber,
        block_timestamp=block.timestamp,
        etherscan_url=f"https://sepolia.etherscan.io/tx/0x{tx_hash_hex}",
    )


def verify_hash_on_chain(pdf_hash_hex: str) -> dict:
    """
    Check if a hash exists on-chain.
    Returns {"exists": bool, "timestamp": int}.
    """
    if not CONTRACT_ADDRESS:
        raise RuntimeError("ANCHOR_CONTRACT_ADDRESS is not set in .env")

    w3 = _get_web3()
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(CONTRACT_ADDRESS),
        abi=CONTRACT_ABI,
    )
    raw_hash = bytes.fromhex(pdf_hash_hex.removeprefix("0x"))
    exists, timestamp = contract.functions.verifyHash(raw_hash).call()
    return {"exists": exists, "timestamp": timestamp}
