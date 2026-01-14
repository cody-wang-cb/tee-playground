# TEE Attestation MVP

A minimal prototype demonstrating TEE (Trusted Execution Environment) attestation verification using the Flashtestation protocol.

## Architecture

```
┌─────────────┐                        ┌─────────────────────────┐
│   Client    │ ─── TLS request ────►  │      Mock TEE           │
│             │                        │  (serves TLS with       │
└─────────────┘                        │   attested key)         │
       │                               └─────────────────────────┘
       │ verify cert's pubkey                    │
       │ matches attested key                    │ register attestation
       │                                         │ (pubkey → registry)
       ▼                                         ▼
┌─────────────┐      watch events       ┌───────────────────┐
│   Indexer   │ ◄────────────────────── │  Registry Contract │
│   (API)     │                         └───────────────────┘
└─────────────┘
```

## Components

1. **Contracts** (Solidity/Foundry)
   - `MockAttestation.sol` - Mock DCAP verifier that accepts any quote
   - `FlashtestationRegistry.sol` - Stores TEE registrations
   - `BlockBuilderPolicy.sol` - Manages approved workloads

2. **Mock TEE** (Rust)
   - Generates TLS keypair
   - Creates mock TDX attestation quote
   - Registers with the on-chain registry
   - Serves HTTPS with the attested key

3. **Indexer** (Rust)
   - Watches registry events
   - Provides REST API for attestation queries

4. **Client** (Rust)
   - Fetches attestation from indexer
   - Connects to TEE with custom TLS verification
   - Verifies server cert matches attested public key

## Run Demo

**Terminal 1 - Start Anvil:**
```bash
make anvil
```

**Terminal 2 - Deploy & Run Mock TEE:**
```bash
# Deploy contracts
make deploy

# Note the addresses from output, then:
make mock-tee REGISTRY_ADDR=<registry> POLICY_ADDR=<policy>
```

**Terminal 3 - Start Indexer:**
```bash
make indexer REGISTRY_ADDR=<registry>
```

**Terminal 4 - Run Client:**
```bash
make client TEE_ADDR=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
```

## How It Works

### Registration Flow

1. Mock TEE generates a P-256 TLS keypair
2. Creates a mock TDX quote with:
   - `reportData[0:20]` = TEE's Ethereum address
   - `reportData[20:52]` = keccak256(TLS public key)
3. Calls `registerTEEService(quote, extendedData)` on the registry
4. Registry stores the parsed quote and emits `TEEServiceRegistered` event

### Verification Flow

1. Client queries indexer for TEE's attestation
2. Client initiates TLS connection to TEE
3. Custom TLS verifier extracts server cert's public key
4. Verifier checks pubkey matches attested TLS key
5. If match, connection proceeds; otherwise, rejected

### WorkloadId

The workload ID is computed from TDX measurements:
```
workloadId = keccak256(mrTd || rtMr0 || rtMr1 || rtMr2 || rtMr3 || mrConfigId || xFAM || tdAttributes)
```

This identifies the specific code/configuration running in the TEE. The policy contract maintains a list of approved workloadIds.

## Differences from Production

This is a minimal prototype. Production Flashtestation differs in:

1. **Real DCAP Verification** - Uses Automata's contracts to verify Intel signatures
2. **Real TDX Hardware** - Measurements come from actual TEE hardware
3. **Upgradeable Contracts** - Uses proxy pattern for upgrades
4. **EIP-712 Signatures** - Supports permit-style registration
5. **Quote Invalidation** - Handles endorsement changes

## References

- [Flashtestations Spec](https://github.com/flashbots/rollup-boost/blob/main/specs/flashtestations.md)
- [Flashtestations Contracts](https://github.com/flashbots/flashtestations)
- [CVM Reverse Proxy](https://github.com/flashbots/cvm-reverse-proxy)
- [Automata DCAP Attestation](https://github.com/automata-network/automata-dcap-attestation)
