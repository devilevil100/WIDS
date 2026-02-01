// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title FraudRecord
 * @dev Smart contract for storing immutable fraud detection predictions on the blockchain
 * @notice This contract stores SHA-256 hashes of transaction data along with ML predictions
 */
contract FraudRecord {
    
    // ============ Structs ============
    
    /**
     * @dev Structure to store a fraud prediction record
     * @param dataHash SHA-256 hash of the original transaction data
     * @param isFraud Whether the ML model predicted fraud (true) or legitimate (false)
     * @param confidence Confidence score from 0-10000 (representing 0.00% to 100.00%)
     * @param timestamp Block timestamp when the record was created
     * @param recorder Address of the account that recorded this prediction
     */
    struct FraudPrediction {
        bytes32 dataHash;
        bool isFraud;
        uint16 confidence;  // 0-10000 for 0.00% to 100.00%
        uint256 timestamp;
        address recorder;
    }
    
    // ============ State Variables ============
    
    /// @dev Mapping from data hash to fraud prediction
    mapping(bytes32 => FraudPrediction) private predictions;
    
    /// @dev Array of all recorded hashes for enumeration
    bytes32[] private recordedHashes;
    
    /// @dev Contract owner
    address public owner;
    
    /// @dev Total number of records
    uint256 public recordCount;
    
    // ============ Events ============
    
    /**
     * @dev Emitted when a new fraud prediction is recorded
     * @param dataHash The SHA-256 hash of the transaction data
     * @param isFraud Whether fraud was predicted
     * @param confidence Confidence score (0-10000)
     * @param recorder Address that recorded the prediction
     */
    event RecordAdded(
        bytes32 indexed dataHash,
        bool isFraud,
        uint16 confidence,
        address indexed recorder
    );
    
    /**
     * @dev Emitted when contract ownership is transferred
     */
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    
    // ============ Modifiers ============
    
    modifier onlyOwner() {
        require(msg.sender == owner, "FraudRecord: caller is not the owner");
        _;
    }
    
    // ============ Constructor ============
    
    constructor() {
        owner = msg.sender;
        recordCount = 0;
    }
    
    // ============ State-Changing Functions ============
    
    /**
     * @dev Record a new fraud prediction on the blockchain
     * @param _dataHash SHA-256 hash of the transaction data (bytes32)
     * @param _isFraud True if fraud detected, false if legitimate
     * @param _confidence Confidence score from 0 to 10000 (0.00% to 100.00%)
     * @notice This function costs gas as it modifies blockchain state
     */
    function recordPrediction(
        bytes32 _dataHash,
        bool _isFraud,
        uint16 _confidence
    ) external {
        require(_dataHash != bytes32(0), "FraudRecord: invalid hash");
        require(_confidence <= 10000, "FraudRecord: confidence must be <= 10000");
        require(predictions[_dataHash].timestamp == 0, "FraudRecord: record already exists");
        
        predictions[_dataHash] = FraudPrediction({
            dataHash: _dataHash,
            isFraud: _isFraud,
            confidence: _confidence,
            timestamp: block.timestamp,
            recorder: msg.sender
        });
        
        recordedHashes.push(_dataHash);
        recordCount++;
        
        emit RecordAdded(_dataHash, _isFraud, _confidence, msg.sender);
    }
    
    // ============ View Functions (Free - No Gas) ============
    
    /**
     * @dev Get the fraud prediction for a given data hash
     * @param _dataHash The SHA-256 hash to look up
     * @return isFraud Whether fraud was predicted
     * @return confidence Confidence score (0-10000)
     * @return timestamp When the record was created
     * @return recorder Who recorded the prediction
     * @return exists Whether a record exists for this hash
     */
    function getPrediction(bytes32 _dataHash) 
        external 
        view 
        returns (
            bool isFraud,
            uint16 confidence,
            uint256 timestamp,
            address recorder,
            bool exists
        ) 
    {
        FraudPrediction memory pred = predictions[_dataHash];
        exists = pred.timestamp != 0;
        return (pred.isFraud, pred.confidence, pred.timestamp, pred.recorder, exists);
    }
    
    /**
     * @dev Check if a record exists for a given hash
     * @param _dataHash The hash to check
     * @return True if a record exists
     */
    function recordExists(bytes32 _dataHash) external view returns (bool) {
        return predictions[_dataHash].timestamp != 0;
    }
    
    /**
     * @dev Get the total number of recorded predictions
     * @return The count of all predictions
     */
    function getRecordCount() external view returns (uint256) {
        return recordCount;
    }
    
    /**
     * @dev Get a recorded hash by index (for enumeration)
     * @param _index Index in the recorded hashes array
     * @return The data hash at that index
     */
    function getHashByIndex(uint256 _index) external view returns (bytes32) {
        require(_index < recordedHashes.length, "FraudRecord: index out of bounds");
        return recordedHashes[_index];
    }
    
    // ============ Owner Functions ============
    
    /**
     * @dev Transfer ownership to a new address
     * @param _newOwner Address of the new owner
     */
    function transferOwnership(address _newOwner) external onlyOwner {
        require(_newOwner != address(0), "FraudRecord: new owner is zero address");
        emit OwnershipTransferred(owner, _newOwner);
        owner = _newOwner;
    }
}
