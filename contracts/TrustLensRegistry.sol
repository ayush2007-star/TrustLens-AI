// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TrustLensRegistry
 * @dev Cryptographic Proof-of-Threat Registry Smart Contract.
 * Stores immutable SHA-256 fingerprints of verified threat reports on-chain.
 * 
 * Note: Never store sensitive personal data, OTPs, or passwords on-chain.
 * Only cryptographic SHA-256 fingerprints and categorical metadata are recorded.
 */
contract TrustLensRegistry {
    struct ThreatRecord {
        uint256 blockIndex;
        string reportId;
        bytes32 dataHash;
        bytes32 previousHash;
        bytes32 chainedHash;
        string targetDomain;
        string reportType;
        uint256 timestamp;
        address registrar;
    }

    address public owner;
    uint256 public totalRecords;
    bytes32 public latestChainedHash;

    // Mapping from reportId to ThreatRecord
    mapping(string => ThreatRecord) public recordsByReportId;
    // Mapping from blockIndex to ThreatRecord
    mapping(uint256 => ThreatRecord) public ledger;

    event ReportRegistered(
        uint256 indexed blockIndex,
        string indexed reportId,
        bytes32 indexed chainedHash,
        string targetDomain,
        uint256 timestamp
    );

    constructor() {
        owner = msg.sender;
        latestChainedHash = bytes32(0);
        totalRecords = 0;
    }

    /**
     * @dev Registers a new verified threat report fingerprint on the ledger.
     */
    function registerReport(
        string calldata reportId,
        bytes32 dataHash,
        string calldata targetDomain,
        string calldata reportType
    ) external returns (uint256) {
        require(bytes(reportId).length > 0, "Report ID cannot be empty");
        require(recordsByReportId[reportId].timestamp == 0, "Report already registered");

        uint256 currentIndex = totalRecords;
        bytes32 prevHash = latestChainedHash;

        // Compute cryptographic chained hash on-chain
        bytes32 currentChainedHash = keccak256(
            abi.encodePacked(currentIndex, prevHash, dataHash, block.timestamp)
        );

        ThreatRecord memory newRecord = ThreatRecord({
            blockIndex: currentIndex,
            reportId: reportId,
            dataHash: dataHash,
            previousHash: prevHash,
            chainedHash: currentChainedHash,
            targetDomain: targetDomain,
            reportType: reportType,
            timestamp: block.timestamp,
            registrar: msg.sender
        });

        recordsByReportId[reportId] = newRecord;
        ledger[currentIndex] = newRecord;
        latestChainedHash = currentChainedHash;
        totalRecords += 1;

        emit ReportRegistered(currentIndex, reportId, currentChainedHash, targetDomain, block.timestamp);
        return currentIndex;
    }

    /**
     * @dev Verifies whether a given report ID and data hash match the on-chain record.
     */
    function verifyReport(string calldata reportId, bytes32 computedDataHash)
        external
        view
        returns (bool isValid, uint256 blockIndex, bytes32 chainedHash, uint256 timestamp)
    {
        ThreatRecord memory record = recordsByReportId[reportId];
        if (record.timestamp == 0) {
            return (false, 0, bytes32(0), 0);
        }

        bool matchValid = (record.dataHash == computedDataHash);
        return (matchValid, record.blockIndex, record.chainedHash, record.timestamp);
    }
}
