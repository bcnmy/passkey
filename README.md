[![Biconomy](https://img.shields.io/badge/Made_with_%F0%9F%8D%8A_by-Biconomy-ff4e17?style=flat)](https://biconomy.io) [![License MIT](https://img.shields.io/badge/License-MIT-blue?&style=flat)](./LICENSE) [![codecov](https://codecov.io/github/bcnmy/passkey/graph/badge.svg?token=DTdIR5aBDA)](https://codecov.io/github/bcnmy/passkey)

# @biconomy/passkey 🚀

A WebAuthn-based passkey validator module for Biconomy's SDK (@biconomy/sdk). Enable secure transaction signing using device biometrics in your Web3 applications.

## Key Features

- 🔐 WebAuthn-based transaction signing
- 📜 ERC-7579 compliant module implementation  
- 🤝 Seamless integration with Biconomy's Nexus smart accounts
- 🔄 Support for both registration and login flows
- 👆 Native device biometrics support

## Installation

Choose your preferred package manager:

```bash
# npm
npm i @biconomy/passkey

# yarn
yarn add @biconomy/passkey

# pnpm
pnpm i @biconomy/passkey

# bun
bun i @biconomy/passkey
```

# Quick Start Guide
### Here's a complete example showing how to set up and use the passkey validator:

```typescript
import { toWebAuthnKey, WebAuthnMode, toPasskeyValidator } from "@biconomy/passkey"
import { createNexusClient, moduleActivator } from "@biconomy/sdk"
import { http } from "viem"
import { baseSepolia } from "viem/chains"

// 1. Initial Setup
const account = privateKeyToAccount('0x...')
const chain = baseSepolia
const bundlerUrl = 'https://bundler.biconomy.io/api/v3/84532/nJPK7B3ru.dd7f7861-190d-41bd-af80-6877f74b8f44'

// 2. Create Nexus Client
const nexusClient = await createNexusClient({
  signer: account,
  chain,
  transport: http(),
  bundlerTransport: http(bundlerUrl)
})

// 3. Setup WebAuthn Credentials
const webAuthnKey = await toWebAuthnKey({
  passkeyName: "my-passkey",     // Your passkey identifier
  mode: WebAuthnMode.Register    // Use .Login for existing passkeys
})

// 4. Initialize Passkey Validator
const passkeyValidator = await toPasskeyValidator({
  webAuthnKey,
  signer: account,
  accountAddress: nexusClient.account.address,
  chainId: chain.id
})

// 5. Install Validator Module
const opHash = await nexusClient.installModule({ module: passkeyValidator })
await nexusClient.waitForUserOperationReceipt({ hash: opHash })

// 6. Activate the Validator
nexusClient.extend(moduleActivator(passkeyValidator))

// 7. Send a Transaction
const tx = await nexusClient.sendTransaction({
  to: "0x...",
  value: 1
})
```