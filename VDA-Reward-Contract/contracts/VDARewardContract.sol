//SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@verida/vda-verification-contract/contracts/VDAVerificationContract.sol";
import { IStorageNode } from "./IStorageNode.sol";
import "./IVDARewardContract.sol";

contract VDARewardContract is IVDARewardContract, VDAVerificationContract {

    /** ReardToken : ERC20 contract */
    IERC20Upgradeable internal rewardToken;
    /** StorageNodeRegistry contract */
    IStorageNode internal storageNodeContract;

    /** Mapping of claim ID => claim Type */
    mapping(string => ClaimType) internal claimTypes;

    /** Mapping of claim ID => Verida account */
    mapping(bytes => bool) internal claims;

    /**
     * @notice Gap for later use
     */
    uint256[20] private __gap;

    modifier onlyExistingClaimType(string calldata typeId) {
        ClaimType storage claimType = claimTypes[typeId];
        if (claimType.reward == 0 || bytes(claimType.schema).length == 0) {
            revert InvalidId();
        }
        _;
    }

    // Custom errors
    error InvalidId();
    error InvalidRewardAmount();
    error InvalidSchema();
    error DuplicatedRequest();

    function __VDARewardContract_init(IERC20Upgradeable token, IStorageNode nodeContract) public initializer {
        __Ownable_init();
        __VDARewardContract_init_unchained(token, nodeContract);
    }

    function __VDARewardContract_init_unchained(IERC20Upgradeable token, IStorageNode nodeContract) internal {
        rewardToken = token;
        storageNodeContract = nodeContract;
    }

    /**
     * @dev see {IVDARewardContract-getClaimType}
     */
    function getClaimType(string calldata typeId) external view virtual override onlyExistingClaimType(typeId) returns(uint reward, string memory schema) {
        ClaimType storage claimType = claimTypes[typeId];
        reward = claimType.reward;
        schema = claimType.schema;
    }

    /**
     * @dev see {IVDARewardContract-addClaimType}
     */
    function addClaimType(string calldata typeId, uint rewardAmount, string calldata schema) external virtual override payable onlyOwner {
        if (bytes(typeId).length == 0) {
            revert InvalidId();
        }
        if (rewardAmount == 0) {
            revert InvalidRewardAmount();
        }
        if (bytes(schema).length == 0) {
            revert InvalidSchema();
        }
        ClaimType storage claimType = claimTypes[typeId];
        if (claimType.reward != 0 || bytes(claimType.schema).length != 0) {
            revert InvalidId();
        }

        claimType.reward = rewardAmount;
        claimType.schema = schema;

        emit AddClaimType(typeId, rewardAmount, schema);
    }

    /**
     * @dev see {IVDARewardContract-removeClaimType}
     */
    function removeClaimType(string calldata typeId) external virtual override payable onlyOwner onlyExistingClaimType(typeId){
        delete claimTypes[typeId];

        emit RemoveClaimType(typeId);
    }

    /**
     * @dev see {IVDARewardContract-updateClaimTypeReward}
     */
    function updateClaimTypeReward(string calldata typeId, uint amount) external virtual override payable onlyOwner onlyExistingClaimType(typeId){
        if (amount == 0) {
            revert InvalidRewardAmount();
        }
        ClaimType storage claimType = claimTypes[typeId];
        claimType.reward = amount;

        emit UpdateClaimTypeReward(typeId, amount);
    }

    /**
     * @notice Internal function. Verify claim request and return reward amount
     * @param typeId - Unique ID of the ClaimType (ie: facebook)
     * @param hash - Uique hash from the credential (ie: 09c247n5t089247n90812798c14)
     * @param paramAddress - Recipient address or DIDAddress
     * @param signature - Signature from the credential that signed a combination of the hash and credential schema
     * @param proof - Proof that signature was verified by the trusted address
     */
    function verifyClaimRequest(
        string calldata typeId, 
        string calldata hash, 
        address paramAddress,
        bytes calldata signature,
        bytes calldata proof
    ) internal virtual onlyExistingClaimType(typeId) returns(uint)  {
        ClaimType storage claimType = claimTypes[typeId];
        bytes memory rawMsg = abi.encodePacked(
            hash,
            "|",
            claimType.schema
        );
        if (claims[rawMsg]) {
            revert DuplicatedRequest();
        }
        claims[rawMsg] = true;

        rawMsg = abi.encodePacked(rawMsg,paramAddress);
        verifyData(rawMsg, signature, proof);

        return claimType.reward;
    }

    /**
     * @dev see {IVDARewardContract-claim}
     */
    function claim(
        string calldata typeId, 
        string calldata hash, 
        address to,
        bytes calldata signature,
        bytes calldata proof
    ) external virtual override {
        uint amount = verifyClaimRequest(typeId, hash, to, signature, proof);
        rewardToken.transfer(to, amount);
        emit Claim(typeId, hash, to);
    }

    /**
     * @dev see {IVDARewardContract-claim}
     */
    function claimToStorage(
        string calldata typeId, 
        string calldata hash, 
        address didAddress,
        bytes calldata signature,
        bytes calldata proof
    ) external virtual override {
        uint amount = verifyClaimRequest(typeId, hash, didAddress, signature, proof);
        // Call function of StorageNodeRegistry contract
        rewardToken.approve(address(storageNodeContract), amount);
        storageNodeContract.depositTokenFromProvider(didAddress, address(this), amount);

        emit ClaimToStorage(typeId, hash, didAddress);
    }

    /**
     * @dev see {IVDARewardContract-claim}
     */
    function getTokenAddress() external view returns(address) {
        return address(rewardToken);
    }

    /**
     * @dev see {IVDARewardContract-claim}
     */
    function getStorageNodeContractAddress() external view returns(address) {
        return address(storageNodeContract);
    }
} 



//SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/StringsUpgradeable.sol";

import "@openzeppelin/contracts-upgradeable/utils/structs/EnumerableSetUpgradeable.sol";

error RegisteredSigner();
error UnregisteredSigner();
error NoSigners();
error InvalidSignature();

abstract contract VDAVerificationContract is OwnableUpgradeable {

    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.AddressSet;

    /** @notice Nonce for dids */
    mapping(address => uint) internal _nonce;

    /** @notice Trusted signer addresses */
    EnumerableSetUpgradeable.AddressSet internal _trustedSigners;

    /**
     * @notice Emitted when the contract owner adds a trusted signer
     * @param signerAddress Address of signer
     */
    event AddTrustedSigner(address signerAddress);

    /**
     * @notice Emitted when the contract owner removes a trusted signer
     * @param signerAddress Address of signer
     */
    event RemoveTrustedSigner(address signerAddress);
    
    /**
     * @notice Initializer for deploying the contract
     * @dev This contract can't be deployed directly. Should be used as a parent class only
     */
    function __VDAVerificationContract_init() internal onlyInitializing {
        __Ownable_init();
        __VDAVerificationContract_init_unchained();
    }

    /**
     * @notice Initializer for deploying the contract
     * @dev Initialze the necessary stuffs that are unique to this contract
     */
    function __VDAVerificationContract_init_unchained() internal onlyInitializing {
    }

    /**
     * @notice Add a trusted signer
     * @dev Only the contract owner can add
     * @param didAddress Trusted signer address
     */
    function addTrustedSigner(address didAddress) external virtual payable onlyOwner {
        if (_trustedSigners.contains(didAddress)) {
            revert RegisteredSigner();
        }
        _trustedSigners.add(didAddress);
        emit AddTrustedSigner(didAddress);
    }

    /**
     * @notice Remove a trusted signer
     * @dev Only the contract owner can remove
     * @param didAddress Trusted signer address
     */
    function removeTrustedSigner(address didAddress) external virtual payable onlyOwner {
        if (!_trustedSigners.contains(didAddress)) {
            revert UnregisteredSigner();
        }
        _trustedSigners.remove(didAddress);
        emit RemoveTrustedSigner(didAddress);
    }

    /**
     * @notice Check whether address is a trusted signer
     * @param didAddress DID address to be checked
     * @return bool true if registered, otherwise false
     */
    function isTrustedSigner(address didAddress) external view virtual onlyOwner returns(bool) {
        return _trustedSigners.contains(didAddress);
    }


    /**
     * @notice Get a nonce for DID
     * @dev This is used to sign the message. It's for against replay-attack of the transactions
     * @param did DID for nonce
     * @return uint Current nonce of the DID
     */
    function nonce(address did) external view  virtual returns(uint) {
        return _nonce[did];
    }

    /**
     * Verify any data is signed by a trusted signering DID address
     *
     * @param data Any type of raw data
     * @param signature Data signed by a Verida application context signing key
     * @param proof Signed proof that a Verida DID controls a Verida application context signing key
     */
    function verifyData(
        bytes memory data, 
        bytes memory signature,
        bytes memory proof
    ) internal virtual {
        if (_trustedSigners.length() == 0) {
            revert NoSigners();
        }

        if (data.length == 0 || signature.length == 0 || proof.length == 0) {
            revert InvalidSignature();
        }

        bytes32 dataHash = keccak256(data);
        address contextSigner = ECDSAUpgradeable.recover(dataHash, signature);
        string memory strContextSigner = StringsUpgradeable.toHexString(uint256(uint160(contextSigner)));

        bool isVerified;
        uint index;

        while (index < _trustedSigners.length() && !isVerified) {
            address account = _trustedSigners.at(index);

            string memory strAccount = StringsUpgradeable.toHexString(uint256(uint160(account)));
            bytes memory proofString = abi.encodePacked(
                strAccount,
                strContextSigner
            );
            bytes32 proofHash = keccak256(proofString);
            address didSigner = ECDSAUpgradeable.recover(proofHash, proof);

            if (didSigner == account) {
                isVerified = true;
                break;
            }
            unchecked { ++index; }
        }

        if (!isVerified) {
            revert InvalidSignature();
        }
    }
    
    /**
     * Verify any data is signed by a particular array of DID addresses
     *
     * @param data Any type of raw data
     * @param signature Data signed by a Verida application context signing key
     * @param proof Signed proof that a Verida DID controls a Verida application context signing key
     * @param validSigners Array of did addresses that are valid signers of data
     */
    function verifyDataWithSigners(
        bytes memory data, 
        bytes memory signature,
        bytes memory proof,
        address[] memory validSigners
    ) internal virtual {
        if (validSigners.length == 0) {
            revert NoSigners();
        }

        if (data.length == 0 || signature.length == 0 || proof.length == 0) {
            revert InvalidSignature();
        }

        bytes32 dataHash = keccak256(data);
        address contextSigner = ECDSAUpgradeable.recover(dataHash, signature);
        string memory strContextSigner = StringsUpgradeable.toHexString(uint256(uint160(contextSigner)));

        bool isVerified;
        uint index;

        while (index < validSigners.length && !isVerified) {
            address account = validSigners[index];

            string memory strAccount = StringsUpgradeable.toHexString(uint256(uint160(account)));
            bytes memory proofString = abi.encodePacked(
                strAccount,
                strContextSigner
            );
            bytes32 proofHash = keccak256(proofString);
            address didSigner = ECDSAUpgradeable.recover(proofHash, proof);

            if (didSigner == account) {
                isVerified = true;
                break;
            }
            unchecked { ++index; }
        }

        if (!isVerified) {
            revert InvalidSignature();
        }
    }
    
     /**
     * @notice Verify whether a given request is valid. Verifies the nonce of the DID making the request.
     * 
     * @dev Verify the signature & proof signed by valid signers
     * 
     * @param did DID that made the request. Nonce will be incremented against this DID to avoid replay attacks.
     * @param params Parameters of the message.
     * @param signature A signature that matches sign(${didSignAddress}, params)
     * @param proof Proof A signature that matches sign(did, `${didAddress}${didSignAddress}`)
     */
    function verifyRequest(
        address did, 
        bytes memory params, 
        bytes memory signature, 
        bytes memory proof
    ) internal virtual {
        // Verify the nonce is valid by including it in the unsignedData to be checked
        uint didNonce = _nonce[did];
        bytes memory unsignedParams = abi.encodePacked(
            params,
            didNonce
        );

        address[] memory signers = new address[](1);
        signers[0] = did;

        // Verify the params were signed by the DID making the request
        verifyDataWithSigners(
            unsignedParams,
            signature,
            proof,
            signers
        );

        // Increment the nonce to prevent replay attacks
        _nonce[did]++;
    }
}