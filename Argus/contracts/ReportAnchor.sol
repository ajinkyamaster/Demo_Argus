// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ReportAnchor — stores SHA-256 hashes of Argus PDF reports on-chain.
/// @notice Deploy on Sepolia via Remix IDE, then put the address in backend/.env.
contract ReportAnchor {
    mapping(bytes32 => uint256) public hashTimestamps;

    event HashStored(bytes32 indexed reportHash, address indexed sender, uint256 timestamp);

    /// @notice Store a report hash. Reverts if the same hash was already anchored.
    function storeHash(bytes32 reportHash) external {
        require(hashTimestamps[reportHash] == 0, "Hash already anchored");
        hashTimestamps[reportHash] = block.timestamp;
        emit HashStored(reportHash, msg.sender, block.timestamp);
    }

    /// @notice Check whether a hash exists on-chain and when it was stored.
    function verifyHash(bytes32 reportHash) external view returns (bool exists, uint256 timestamp) {
        uint256 ts = hashTimestamps[reportHash];
        return (ts != 0, ts);
    }
}
