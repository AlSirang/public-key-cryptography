const { assert } = require("chai");
const secp = require("ethereum-cryptography/secp256k1");
const { toHex } = require("ethereum-cryptography/utils");
const { PUBLIC_KEY_WITHOUT_OX, PRIVATE_KEY } = require("../constants");
const {
  hashMessage,
  signMessage,
  recoverKey,
  getEthereumAddress,
} = require("../utils");

const helloWorldHex =
  "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad";

describe("Hash Message", () => {
  it("should return the keccak256 hash of hello world", () => {
    const messageHash = hashMessage("hello world");

    assert(toHex(messageHash), helloWorldHex);
  });
});

describe("Sign Message", () => {
  it("should return both a signature and a recovery bit", async () => {
    const response = await signMessage("hello world", PRIVATE_KEY);

    const errMessage =
      "expected signMessage to return both a signature and recovery bit!";
    assert(response.length, errMessage);
    assert(response.length === 2, errMessage);

    const [signature, recoveryBit] = response;
    assert(signature.length, "expected signature to be a Uint8Array");
    assert(
      typeof recoveryBit === "number",
      "expected the recovery bit to be a number"
    );
  });

  it("should have been signed by the same private key", async () => {
    const [sig, recoveryBit] = await signMessage("hello world", PRIVATE_KEY);
    const messageHash = hashMessage("hello world");
    const recovered = secp.recoverPublicKey(messageHash, sig, recoveryBit);

    const publicKey = secp.getPublicKey(PRIVATE_KEY);
    assert.equal(toHex(recovered), toHex(publicKey));
  });
});

describe("Recover Key", () => {
  it("should recover the public key from a signed message", async () => {
    const [sig, recoveryBit] = await signMessage("hello world", PRIVATE_KEY);

    const publicKey = secp.getPublicKey(PRIVATE_KEY);

    const recovered = await recoverKey("hello world", sig, recoveryBit);

    assert.equal(toHex(recovered), toHex(publicKey));
  });
});

describe("Get Address", () => {
  const EXPECTED_ADDRESS = PUBLIC_KEY_WITHOUT_OX;

  it("should get the address from a public key", async () => {
    const publicKey = secp.getPublicKey(PRIVATE_KEY);

    const address = toHex(getEthereumAddress(publicKey));
    assert.equal(address.toLowerCase(), EXPECTED_ADDRESS.toLowerCase());
  });
});
