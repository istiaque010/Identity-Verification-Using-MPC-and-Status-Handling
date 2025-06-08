// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract VerifiableCredentials {
    struct VCRoot {
        bytes32 issuerDID;
        bytes32 holderDID;
        bytes32 rootVC;
        bool exists;
    }

    struct VP {
        bytes32 vpID;            // ID generated off-chain (vpID)
        bytes32 holderDID;
        bytes32[] claims;        // aggregated claims from multiple VC roots
        bytes32[] vcRoots;       // list of associated VC roots
    }

    struct VPShare {
        bytes32 verifierDID;
        bytes32 vpID;
        bytes32[] sharedClaims;
        uint256 timestamp;
        bytes32 uniqueSaltHash;  // New field
        uint256 sessionDuration; // New field
    }

    mapping(bytes32 => bytes32[]) private holderToRoots;
    mapping(bytes32 => VCRoot) private roots;

    // Mapping holder DID => array of VPs
    mapping(bytes32 => VP[]) private vps;

    // Mapping holder DID => array of VP shares
    mapping(bytes32 => VPShare[]) private vpShares;

    event VCRootRegistered(bytes32 indexed issuerDID, bytes32 indexed holderDID, bytes32 indexed rootVC);
    event VCRootVerified(bytes32 indexed holderDID, bytes32 rootVC, bool verified);
    event VPUpdated(bytes32 indexed vpID, bytes32 indexed holderDID);
    event VPShared(bytes32 indexed vpID, bytes32 indexed holderDID, bytes32 indexed verifierDID);

    // Register a new VC root on-chain
    function registerVCRoot(bytes32 issuerDID, bytes32 holderDID, bytes32 rootVC) external {
        require(rootVC != bytes32(0), "Invalid rootVC");
        require(!roots[rootVC].exists, "rootVC already registered");

        roots[rootVC] = VCRoot({
            issuerDID: issuerDID,
            holderDID: holderDID,
            rootVC: rootVC,
            exists: true
        });

        holderToRoots[holderDID].push(rootVC);

        emit VCRootRegistered(issuerDID, holderDID, rootVC);
    }

    // Get all VC roots assigned to a holder DID
    function getVCRootsForHolder(bytes32 holderDID) external view returns (bytes32[] memory) {
        return holderToRoots[holderDID];
    }

    // Check if a rootVC is assigned to a holder
    function isRootAssignedToHolder(bytes32 holderDID, bytes32 rootVC) public view returns (bool) {
        bytes32[] memory rootsArr = holderToRoots[holderDID];
        for (uint i = 0; i < rootsArr.length; i++) {
            if (rootsArr[i] == rootVC) {
                return true;
            }
        }
        return false;
    }

    // Verify root and add/update VP with off-chain generated vpID
    function verifyRoot(
        bytes32 holderDID,
        bytes32[] calldata claimHashes,
        bytes32 rootSalt,
        bytes32 rootVC,
        bytes32 vpID   // ID generated off-chain (vpID)
    ) external returns (bool) {
        require(isRootAssignedToHolder(holderDID, rootVC), "Root not assigned to holder");

        bytes32 preRoot = computePreRoot(claimHashes);
        bytes32 computedRoot = sha256(abi.encodePacked(preRoot, rootSalt));
        bool verified = (computedRoot == rootVC);
        emit VCRootVerified(holderDID, rootVC, verified);

        if (verified) {
            (bool found, uint idx) = _findVPIndex(holderDID, vpID);
            if (!found) {
                // Create new VP with vcRoots array initialized with rootVC
                bytes32[] memory initialVcRoots = new bytes32[](1);
                initialVcRoots[0] = rootVC;

                vps[holderDID].push(VP({
                    vpID: vpID,
                    holderDID: holderDID,
                    claims: claimHashes,
                    vcRoots: initialVcRoots
                }));
            } else {
                // Update existing VP: append claims and VC root (duplicates allowed)
                VP storage existing = vps[holderDID][idx];

                // Append all claim hashes (duplicates allowed)
                for (uint i = 0; i < claimHashes.length; i++) {
                    existing.claims.push(claimHashes[i]);
                }

                // Append VC root
                existing.vcRoots.push(rootVC);
            }

            emit VPUpdated(vpID, holderDID);
        }

        return verified;
    }

    // Share subset of claims from VP to verifier
    function shareVPClaims(
        bytes32 holderDID,
        bytes32 vpID,
        bytes32 verifierDID,
        bytes32[] calldata claimsSubset,
        bytes32 uniqueSaltHash,  // New parameter
        uint256 sessionDuration  // New parameter
    ) external {
        // Verify VP exists and belongs to holder
        (bool found, uint idx) = _findVPIndex(holderDID, vpID);
        require(found, "VP not found for holder");

        VP storage vp = vps[holderDID][idx];

        // Check each claim in claimsSubset is part of vp.claims
        for (uint i = 0; i < claimsSubset.length; i++) {
            bool claimExists = false;
            for (uint j = 0; j < vp.claims.length; j++) {
                if (vp.claims[j] == claimsSubset[i]) {
                    claimExists = true;
                    break;
                }
            }
            require(claimExists, "Claim not in VP");
        }

        vpShares[holderDID].push(VPShare({
            verifierDID: verifierDID,
            vpID: vpID,
            sharedClaims: claimsSubset,
            timestamp: block.timestamp,
            uniqueSaltHash: uniqueSaltHash,   // Added new field
            sessionDuration: sessionDuration  // Added new field
        }));

        emit VPShared(vpID, holderDID, verifierDID);
    }

    // Get VP shares by holder
    function getVPShares(bytes32 holderDID) external view returns (VPShare[] memory) {
        return vpShares[holderDID];
    }

    // Get all VPs for a holder
    function getVPs(bytes32 holderDID) external view returns (VP[] memory) {
        return vps[holderDID];
    }

    // Internal: find VP index by vpID
    function _findVPIndex(bytes32 holderDID, bytes32 vpID) internal view returns (bool, uint) {
        VP[] storage holderVPs = vps[holderDID];
        for (uint i = 0; i < holderVPs.length; i++) {
            if (holderVPs[i].vpID == vpID) {
                return (true, i);
            }
        }
        return (false, 0);
    }

    // Internal: compute preRoot hash
    function computePreRoot(bytes32[] memory hashes) internal pure returns (bytes32) {
        bytes memory combined;
        for (uint i = 0; i < hashes.length; i++) {
            combined = abi.encodePacked(combined, hashes[i]);
        }
        return sha256(combined);
    }
}