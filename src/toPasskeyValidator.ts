import {
  type Module,
  type NexusAccount,
  type ToModuleParameters,
  toModule
} from "@biconomy/sdk"
import { startAuthentication } from "@simplewebauthn/browser"
import type { PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/typescript-types"
import { type SignableMessage, encodeAbiParameters } from "viem"
import { PASSKEY_VALIDATOR_ADDRESS } from "./constants"
import type { WebAuthnKey } from "./toWebAuthnKey"
import {
  b64ToBytes,
  base64FromUint8Array,
  findQuoteIndices,
  hexStringToUint8Array,
  isRIP7212SupportedNetwork,
  parseAndNormalizeSig,
  uint8ArrayToHexString
} from "./utils"

/**
 * Signs a message using WebAuthn.
 *
 * @param message - The message to be signed.
 * @param chainId - The chain ID for the network.
 * @param allowCredentials - Optional credentials for authentication.
 * @returns A promise that resolves to the encoded signature.
 */
const signMessageUsingWebAuthn = async (
  message: SignableMessage,
  chainId: number,
  allowCredentials?: PublicKeyCredentialRequestOptionsJSON["allowCredentials"]
) => {
  let messageContent: string
  if (typeof message === "string") {
    // message is a string
    messageContent = message
  } else if ("raw" in message && typeof message.raw === "string") {
    // message.raw is a Hex string
    messageContent = message.raw
  } else if ("raw" in message && message.raw instanceof Uint8Array) {
    // message.raw is a ByteArray
    messageContent = message.raw.toString()
  } else {
    throw new Error("Unsupported message format")
  }

  // remove 0x prefix if present
  const formattedMessage = messageContent.startsWith("0x")
    ? messageContent.slice(2)
    : messageContent

  const challenge = base64FromUint8Array(
    hexStringToUint8Array(formattedMessage),
    true
  )

  // prepare assertion options
  const assertionOptions: PublicKeyCredentialRequestOptionsJSON = {
    challenge,
    allowCredentials,
    userVerification: "required"
  }

  // start authentication (signing)

  const cred = await startAuthentication(assertionOptions)

  // get authenticator data
  const { authenticatorData } = cred.response
  const authenticatorDataHex = uint8ArrayToHexString(
    b64ToBytes(authenticatorData)
  )

  // get client data JSON
  const clientDataJSON = atob(cred.response.clientDataJSON)

  // get challenge and response type location
  const { beforeType } = findQuoteIndices(clientDataJSON)

  // get signature r,s
  const { signature } = cred.response
  const signatureHex = uint8ArrayToHexString(b64ToBytes(signature))
  const { r, s } = parseAndNormalizeSig(signatureHex)

  // encode signature
  const encodedSignature = encodeAbiParameters(
    [
      { name: "authenticatorData", type: "bytes" },
      { name: "clientDataJSON", type: "string" },
      { name: "responseTypeLocation", type: "uint256" },
      { name: "r", type: "uint256" },
      { name: "s", type: "uint256" },
      { name: "usePrecompiled", type: "bool" }
    ],
    [
      authenticatorDataHex,
      clientDataJSON,
      beforeType,
      BigInt(r),
      BigInt(s),
      isRIP7212SupportedNetwork(chainId)
    ]
  )
  return encodedSignature
}

export type ToPasskeyValidatorParameters = Omit<
  ToModuleParameters,
  "accountAddress" | "signer"
> & {
  account: NexusAccount
  webAuthnKey: WebAuthnKey
}

/**
 * Creates a passkey validator module
 *
 * @param params - The parameters for creating the passkey validator
 * @param params.webAuthnKey - The WebAuthn key data containing public key coordinates and authenticator info
 * @param params.chainId - The chain ID of the network
 * @param params.account - The Nexus account instance
 *
 * @returns A Promise that resolves to a Module instance configured for passkey validation through the @biconomy/sdk
 *
 * @example
 * ```typescript
 * import { createNexusClient, moduleActivator } from "@biconomy/sdk";
 * import { http } from "viem";
 * import { baseSepolia } from "viem/chains";
 * import { WebAuthnMode, toWebAuthnKey } from "@biconomy/passkey";
 *
 * // Initialize Nexus client
 * const nexusClient = await createNexusClient({
 *   signer: account,
 *   chain: baseSepolia,
 *   transport: http(),
 *   bundlerTransport: http("https://bundler.biconomy.io/api/v3/...")
 * });
 *
 * // Create WebAuthn credentials
 * const webAuthnKey = await toWebAuthnKey({
 *   passkeyName: "nexus",
 *   mode: WebAuthnMode.Register // Use Register for new passkey, Login for existing
 * });
 *
 * // Create and initialize the passkey validator
 * const passkeyValidator = await toPasskeyValidator({
 *   webAuthnKey,
 *   chainId: baseSepolia.id,
 *   account: nexusClient.account
 * });
 *
 * // Install the validator module
 * const opHash = await nexusClient.installModule({ module: passkeyValidator });
 * await nexusClient.waitForUserOperationReceipt({ hash: opHash });
 *
 * // Activate the passkey validator
 * nexusClient.extend(moduleActivator(passkeyValidator));
 *
 * // Use the passkey validator to sign and send transactions
 * const txHash = await nexusClient.sendTransaction({
 *   calls: [{
 *     to: "0x...",
 *     value: 0n
 *   }]
 * });
 *
 * // Wait for transaction confirmation
 * const receipt = await nexusClient.waitForTransactionReceipt({ hash: txHash });
 * ```
 */
export async function toPasskeyValidator({
  webAuthnKey,
  account
}: ToPasskeyValidatorParameters): Promise<Module> {
  return toModule({
    signer: account.signer,
    address: PASSKEY_VALIDATOR_ADDRESS,
    accountAddress: account.address,
    signUserOpHash: async (userOpHash: `0x${string}`) => {
      if (!account.client?.chain) {
        throw new Error("Chain ID is required but not found in account client")
      }
      return signMessageUsingWebAuthn(
        userOpHash,
        account.client.chain.id,
        [{ id: webAuthnKey.authenticatorId, type: "public-key" }]
      )
    },
    initData: encodeAbiParameters(
      [
        {
          components: [
            { name: "x", type: "uint256" },
            { name: "y", type: "uint256" }
          ],
          name: "webAuthnData",
          type: "tuple"
        },
        {
          name: "authenticatorIdHash",
          type: "bytes32"
        }
      ],
      [
        {
          x: webAuthnKey.pubX,
          y: webAuthnKey.pubY
        },
        webAuthnKey.authenticatorIdHash
      ]
    ),
    moduleInitData: {
      initData: encodeAbiParameters(
        [
          {
            components: [
              { name: "x", type: "uint256" },
              { name: "y", type: "uint256" }
            ],
            name: "webAuthnData",
            type: "tuple"
          },
          {
            name: "authenticatorIdHash",
            type: "bytes32"
          }
        ],
        [
          {
            x: webAuthnKey.pubX,
            y: webAuthnKey.pubY
          },
          webAuthnKey.authenticatorIdHash
        ]
      ),
      address: PASSKEY_VALIDATOR_ADDRESS,
      type: "validator"
    },
    deInitData: "0x", // Add this line, adjust if needed
    async getStubSignature() {
      return encodeAbiParameters(
        [
          { name: "authenticatorData", type: "bytes" },
          { name: "clientDataJSON", type: "string" },
          { name: "responseTypeLocation", type: "uint256" },
          { name: "r", type: "uint256" },
          { name: "s", type: "uint256" },
          { name: "usePrecompiled", type: "bool" }
        ],
        [
          "0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000",
          '{"type":"webauthn.get","challenge":"tbxXNFS9X_4Byr1cMwqKrIGB-_30a0QhZ6y7ucM0BOE","origin":"http://localhost:3000","crossOrigin":false, "other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}',
          1n,
          44941127272049826721201904734628716258498742255959991581049806490182030242267n,
          9910254599581058084911561569808925251374718953855182016200087235935345969636n,
          false
        ]
      )
    }
  })
}
