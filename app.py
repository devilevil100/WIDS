import os
import hashlib
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from web3 import Web3
from eth_account import Account
from web3.middleware import geth_poa_middleware as poa_middleware

from ml_classifier import FraudClassifier
from hashing_utils import hash_transaction, format_hash_for_solidity

load_dotenv(Path(__file__).parent / '.env')

class Config:
    PROVIDER_URL = os.getenv('PROVIDER_URL')
    PRIVATE_KEY = os.getenv('PRIVATE_KEY')
    CONTRACT_ADDRESS = os.getenv('CONTRACT_ADDRESS')
    CHAIN_ID = int(os.getenv('CHAIN_ID'))
    GAS_LIMIT = int(os.getenv('GAS_LIMIT'))

CONTRACT_ABI = [
    {"inputs": [], "stateMutability": "nonpayable", "type": "constructor"},
    {"anonymous": False, "inputs": [
        {"indexed": True, "internalType": "bytes32", "name": "dataHash", "type": "bytes32"},
        {"indexed": False, "internalType": "bool", "name": "isFraud", "type": "bool"},
        {"indexed": False, "internalType": "uint16", "name": "confidence", "type": "uint16"},
        {"indexed": True, "internalType": "address", "name": "recorder", "type": "address"}
    ], "name": "RecordAdded", "type": "event"},
    {"inputs": [{"internalType": "bytes32", "name": "_dataHash", "type": "bytes32"}],
     "name": "getPrediction", "outputs": [
        {"internalType": "bool", "name": "isFraud", "type": "bool"},
        {"internalType": "uint16", "name": "confidence", "type": "uint16"},
        {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
        {"internalType": "address", "name": "recorder", "type": "address"},
        {"internalType": "bool", "name": "exists", "type": "bool"}
    ], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "getRecordCount", "outputs": [
        {"internalType": "uint256", "name": "", "type": "uint256"}
    ], "stateMutability": "view", "type": "function"},
    {"inputs": [
        {"internalType": "bytes32", "name": "_dataHash", "type": "bytes32"},
        {"internalType": "bool", "name": "_isFraud", "type": "bool"},
        {"internalType": "uint16", "name": "_confidence", "type": "uint16"}
    ], "name": "recordPrediction", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "_dataHash", "type": "bytes32"}],
     "name": "recordExists", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
     "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "owner", "outputs": [{"internalType": "address", "name": "", "type": "address"}],
     "stateMutability": "view", "type": "function"}
]

class Web3Client:
    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(Config.PROVIDER_URL))
        self.w3.middleware_onion.inject(poa_middleware, layer=0)
        self.account = Account.from_key(Config.PRIVATE_KEY) if Config.PRIVATE_KEY else None
        self.contract = None
        if Config.CONTRACT_ADDRESS and self.w3.is_address(Config.CONTRACT_ADDRESS):
            self.contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(Config.CONTRACT_ADDRESS),
                abi=CONTRACT_ABI
            )

    def is_connected(self):
        return self.w3.is_connected()

    def record_prediction(self, data_hash: bytes, is_fraud: bool, confidence: int):
        if isinstance(data_hash, str):
            data_hash = bytes.fromhex(data_hash.replace('0x', ''))
        nonce = self.w3.eth.get_transaction_count(self.account.address)
        tx = self.contract.functions.recordPrediction(
            data_hash, is_fraud, min(10000, max(0, confidence))
        ).build_transaction({
            'from': self.account.address,
            'nonce': nonce,
            'gas': Config.GAS_LIMIT,
            'gasPrice': self.w3.eth.gas_price,
            'chainId': Config.CHAIN_ID
        })
        signed = self.w3.eth.account.sign_transaction(tx, Config.PRIVATE_KEY)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        return {
            'success': receipt['status'] == 1,
            'tx_hash': tx_hash.hex(),
            'block': receipt['blockNumber'],
            'gas_used': receipt['gasUsed']
        }

    def get_prediction(self, data_hash: bytes):
        if isinstance(data_hash, str):
            data_hash = bytes.fromhex(data_hash.replace('0x', ''))
        result = self.contract.functions.getPrediction(data_hash).call()
        if not result[4]:
            return None
        return {
            'is_fraud': result[0],
            'confidence': result[1] / 100,
            'timestamp': result[2],
            'recorder': result[3]
        }

    def get_record_count(self):
        return self.contract.functions.getRecordCount().call() if self.contract else 0

class TransactionData(BaseModel):
    from_address: str
    to_address: str
    value: float = Field(..., ge=0)
    timestamp: int

class RecordRequest(BaseModel):
    data_hash: str
    is_fraud: bool
    confidence: float = Field(..., ge=0, le=100)

app = FastAPI(title="Fraud Detection API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

classifier: Optional[FraudClassifier] = None
web3_client: Optional[Web3Client] = None

def get_classifier():
    global classifier
    if classifier is None:
        classifier = FraudClassifier()
        classifier.load_model()
    return classifier

def get_web3():
    global web3_client
    if web3_client is None:
        web3_client = Web3Client()
    return web3_client


@app.post("/predict")
async def predict(tx: TransactionData):
    clf = get_classifier()
    tx_data = tx.dict()
    result = clf.predict(tx_data)
    result['data_hash'] = format_hash_for_solidity(hash_transaction(tx_data))
    result['transaction_data'] = tx_data
    return result

@app.post("/record")
async def record(req: RecordRequest):
    w3 = get_web3()
    result = w3.record_prediction(req.data_hash, req.is_fraud, int(req.confidence * 100))
    return result

@app.get("/verify/{data_hash}")
async def verify(data_hash: str):
    w3 = get_web3()
    result = w3.get_prediction(data_hash)
    return {"exists": result is not None, "data": result}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)