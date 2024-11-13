import {
  type NexusClient,
  createNexusClient,
  moduleActivator
} from "@biconomy/sdk"
import { http, type Chain, type LocalAccount } from "viem"
import { privateKeyToAccount } from "viem/accounts"
import { baseSepolia } from "viem/chains"
import { beforeAll, describe, test } from "vitest"
import { toPasskeyValidator } from "./toPasskeyValidator"
import { WebAuthnMode, toWebAuthnKey } from "./toWebAuthnKey"

describe.skip("modules.passkeyValidator.dx", async () => {
  let bundlerUrl: string
  let chain: Chain

  let eoaAccount: LocalAccount
  let nexusClient: NexusClient

  beforeAll(async () => {
    // Initialize the network and account details
    chain = baseSepolia
    bundlerUrl =
      "https://bundler.biconomy.io/api/v3/6e2a2efc-f9ad-4b1a-931d-a5888eb0fdb5"
    eoaAccount = privateKeyToAccount("0x...")
  })

  test("should setup and use passkey validator to sign a transaction", async () => {
    /**
     * This test demonstrates the creation and use of an passkey module:
     *
     * 1. Setup and Installation:
     *    - Create a Nexus client for the main account
     *    - Create the credentials for the passkey validator
     *    - Install the passkey validator module on the smart contract account
     *    - Create a Nexus client with the passkey validator module
     *
     * 2. Use the passkey validator to sign a transaction
     *    - Send a transaction using the passkey validator
     *    - Wait for the transaction to be mined and retrieve the receipt
     *
     * This test showcases how to install and setup a passkey validator module on Nexus
     */
    nexusClient = await createNexusClient({
      signer: eoaAccount,
      chain,
      transport: http(),
      bundlerTransport: http(bundlerUrl)
    })

    // Create the credentials for the passkey validator, these values will be used as initData when installing the module
    const webAuthnKey = await toWebAuthnKey({
      passkeyName: "nexus", // Name of your passkey
      mode: WebAuthnMode.Register // Here we are creating a new passkey, if you want to use an existing passkey, use WebAuthnMode.Login
    })

    // Initialize the passkey validator with the WebAuthn key and account details
    const passkeyValidator = await toPasskeyValidator({
      webAuthnKey,
      chainId: chain.id,
      account: nexusClient.account
    })

    // Install the passkey validator module on the smart contract account
    const opHash = await nexusClient.installModule({ module: passkeyValidator })
    // Wait for the installation transaction to be mined
    await nexusClient.waitForUserOperationReceipt({ hash: opHash })

    // Set the passkey validator as the active module on the account
    nexusClient.extend(moduleActivator(passkeyValidator))

    // Sending a transaction will be signed by the passkey validator
    const txHash = await nexusClient.sendTransaction({
      calls: [
        {
          to: eoaAccount.address,
          value: 0n
        }
      ]
    })

    // Wait for the transaction to be mined and retrieve the receipt
    const receipt = await nexusClient.waitForTransactionReceipt({
      hash: txHash
    })
  })
})
