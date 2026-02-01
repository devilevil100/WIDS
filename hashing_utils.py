import hashlib
import json
from typing import Dict, Any

def hash_transaction(transaction_data: Dict[str, Any]) -> str:
    sorted_data = {k: transaction_data[k] for k in sorted(transaction_data.keys())}
    data_string = json.dumps(sorted_data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data_string.encode("utf-8")).hexdigest()

def hash_transaction_bytes32(transaction_data: Dict[str, Any]) -> bytes:
    return bytes.fromhex(hash_transaction(transaction_data))

def hash_string(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def verify_hash(transaction_data: Dict[str, Any], expected_hash: str) -> bool:
    return hash_transaction(transaction_data) == expected_hash

def format_hash_for_solidity(hex_hash: str) -> str:
    if hex_hash.startswith("0x"):
        return hex_hash
    return f"0x{hex_hash}"

if __name__ == "__main__":
    tx1 = {
        'from_address': '0xd551234ae421e3bcba99a0da6d736074f22192ff',
        'to_address': '0x002bf459dc58584d58886169ea0e80f3ca95ffaf',
        'value': 0.58626948,
        'timestamp': 1527017753
    }

    hash1 = hash_transaction(tx1)
    print(hash1)
    print(len(hash1))

    tx2 = tx1.copy()
    tx2['value'] = 0.58626949
    print(hash_transaction(tx2))

    print(format_hash_for_solidity(hash1))
    print(hash_transaction_bytes32(tx1).hex())

    print(verify_hash(tx1, hash1))
    print(verify_hash(tx1, hash_transaction(tx2)))