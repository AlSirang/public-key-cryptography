const secp = require("ethereum-cryptography/secp256k1");
const { keccak256 } = require("ethereum-cryptography/keccak");
const { utf8ToBytes } = require("ethereum-cryptography/utils");

/**
 * @dev creates keccak256 hash for given `message`
 * @param {string} message is message to hash
 */
function hashMessage(message) {
  const bytes = utf8ToBytes(message);
  const hash = keccak256(bytes);
  return hash;
}

/**
 * @dev signs the given `msg` with private key and returns signature with recovered bit
 * @param {string} msg is message to sign
 */
async function signMessage(msg, privateKey) {
  const msgHash = hashMessage(msg);
  return await secp.sign(msgHash, privateKey, {
    recovered: true,
  });
}

/**
 * @dev it returns the public key from signed message using actual `message`, `signature` and `recoveryBit`
 * @param {string} message is message signed
 * @param {string} signature is signature of `message` signed
 * @param {string} recoveryBit is the recovery bit
 */
async function recoverKey(message, signature, recoveryBit) {
  const msgHash = hashMessage(message);

  return secp.recoverPublicKey(msgHash, signature, recoveryBit);
}

/**
 * @dev it creates ethereum address from public key
 * @param {string} publicKey 
 
 */
function getEthereumAddress(publicKey) {
  const pubKeySliced = publicKey.slice(1);
  const pubKeyHash = keccak256(pubKeySliced);
  const length = pubKeyHash.length;
  return pubKeyHash.slice(length - 20, length);
}

module.exports = { hashMessage, signMessage, recoverKey, getEthereumAddress };
