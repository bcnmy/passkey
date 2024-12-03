import { startAuthentication, startRegistration } from "@simplewebauthn/browser"
import { type Hex, concatHex, keccak256, pad, toHex } from "viem"
import { DEFAULT_PASSKEY_SERVER_URL } from "./constants.js"
import { b64ToBytes, uint8ArrayToHexString } from "./utils.js"

export enum WebAuthnMode {
  Register = "register",
  Login = "login"
}

export type WebAuthnKey = {
  pubX: bigint
  pubY: bigint
  authenticatorId: string
  authenticatorIdHash: Hex
}
type RequestCredentials = "include" | "omit" | "same-origin"

export type BaseWebAuthnAccountParams = {
  rpID?: string
  webAuthnKey?: WebAuthnKey
  credentials?: RequestCredentials
  passkeyServerHeaders?: Record<string, string>
}

export type RegisterWebAuthnAccountParams = BaseWebAuthnAccountParams & {
  mode?: WebAuthnMode.Register
  passkeyName: string
}

export type LoginWebAuthnAccountParams = BaseWebAuthnAccountParams & {
  mode: WebAuthnMode.Login
  passkeyName?: string
}

export type WebAuthnAccountParams =
  | RegisterWebAuthnAccountParams
  | LoginWebAuthnAccountParams

/**
 * Encodes a WebAuthn public key into a concatenated hex string.
 * The resulting hex string contains the X coordinate (32 bytes), Y coordinate (32 bytes),
 * and the authenticator ID hash (32 bytes) of the WebAuthn key.
 * 
 * @param pubKey - The WebAuthn key object containing public key coordinates and authenticator details
 * @returns A hex string of the concatenated key components
 */
export const encodeWebAuthnPubKey = (pubKey: WebAuthnKey) => {
  return concatHex([
    toHex(pubKey.pubX, { size: 32 }),
    toHex(pubKey.pubY, { size: 32 }),
    pad(pubKey.authenticatorIdHash, { size: 32 })
  ])
}

/**
 * Creates or retrieves a WebAuthn key for authentication or registration.
 * This function handles both registration of new passkeys and authentication with existing ones.
 * 
 * @param params - WebAuthn account parameters
 * @param params.passkeyName - Name identifier for the passkey (required for registration)
 * @param params.rpID - Relying Project ID (domain name)
 * @param params.webAuthnKey - Existing WebAuthn key (if available)
 * @param params.mode - Authentication mode ('register' or 'login')
 * @param params.credentials - Request credentials mode ('include', 'omit', or 'same-origin')
 * @param params.passkeyServerHeaders - Additional headers for passkey server requests
 * 
 * @returns Promise resolving to a WebAuthnKey object containing:
 *  - pubX: X coordinate of the public key
 *  - pubY: Y coordinate of the public key
 *  - authenticatorId: Original authenticator ID
 *  - authenticatorIdHash: Keccak256 hash of the authenticator ID
 * 
 * @throws Error if registration/login verification fails or if required key data is missing
 * 
 * @example
 * // Registration
 * const key = await toWebAuthnKey({
 *   passkeyName: "my-passkey",
 *   mode: WebAuthnMode.Register
 * });
 * 
 * // Login
 * const key = await toWebAuthnKey({
 *   mode: WebAuthnMode.Login
 * });
 */
export const toWebAuthnKey = async ({
  passkeyName,
  rpID,
  webAuthnKey,
  mode = WebAuthnMode.Register,
  credentials = "include",
  passkeyServerHeaders = {}
}: WebAuthnAccountParams): Promise<WebAuthnKey> => {
  if (webAuthnKey) {
    return webAuthnKey
  }
  let pubKey: string | undefined
  let authenticatorId: string | undefined
  if (mode === WebAuthnMode.Login) {
    // Get login options
    const loginOptionsResponse = await fetch(
      `${DEFAULT_PASSKEY_SERVER_URL}/login/options`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...passkeyServerHeaders
        },
        body: JSON.stringify({ rpID }),
        credentials
      }
    )
    const loginOptions: any = await loginOptionsResponse.json()

    // Start authentication (login)
    const loginCred = await startAuthentication(loginOptions)

    authenticatorId = loginCred.id

    // Verify authentication
    const loginVerifyResponse = await fetch(
      `${DEFAULT_PASSKEY_SERVER_URL}/login/verify`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...passkeyServerHeaders
        },
        body: JSON.stringify({ cred: loginCred, rpID }),
        credentials
      }
    )

    const loginVerifyResult: any = await loginVerifyResponse.json()

    if (!loginVerifyResult.verification.verified) {
      throw new Error("Login not verified")
    }
    // Import the key
    pubKey = loginVerifyResult.pubkey // Uint8Array pubkey
  } else {
    // Get registration options
    const registerOptionsResponse = await fetch(
      `${DEFAULT_PASSKEY_SERVER_URL}/register/options`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...passkeyServerHeaders
        },
        body: JSON.stringify({ username: passkeyName, rpID }),
        credentials
      }
    )
    const registerOptions: any = await registerOptionsResponse.json()

    // Start registration
    const registerCred = await startRegistration(registerOptions.options)

    authenticatorId = registerCred.id

    // Verify registration
    const registerVerifyResponse = await fetch(
      `${DEFAULT_PASSKEY_SERVER_URL}/register/verify`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...passkeyServerHeaders
        },
        body: JSON.stringify({
          userId: registerOptions.userId,
          username: passkeyName,
          cred: registerCred,
          rpID
        }),
        credentials
      }
    )

    const registerVerifyResult: any = await registerVerifyResponse.json()
    if (!registerVerifyResult.verified) {
      throw new Error("Registration not verified")
    }

    // Import the key
    pubKey = registerCred.response.publicKey
  }

  if (!pubKey) {
    throw new Error("No public key returned from registration credential")
  }
  if (!authenticatorId) {
    throw new Error("No authenticator id returned from registration credential")
  }

  const authenticatorIdHash = keccak256(
    uint8ArrayToHexString(b64ToBytes(authenticatorId))
  )
  const spkiDer = Buffer.from(pubKey, "base64")
  const key = await crypto.subtle.importKey(
    "spki",
    spkiDer,
    {
      name: "ECDSA",
      namedCurve: "P-256"
    },
    true,
    ["verify"]
  )

  // Export the key to the raw format
  const rawKey = await crypto.subtle.exportKey("raw", key)
  const rawKeyBuffer = Buffer.from(rawKey)

  // The first byte is 0x04 (uncompressed), followed by x and y coordinates (32 bytes each for P-256)
  const pubKeyX = rawKeyBuffer.subarray(1, 33).toString("hex")
  const pubKeyY = rawKeyBuffer.subarray(33).toString("hex")

  return {
    pubX: BigInt(`0x${pubKeyX}`),
    pubY: BigInt(`0x${pubKeyY}`),
    authenticatorId,
    authenticatorIdHash
  }
}
