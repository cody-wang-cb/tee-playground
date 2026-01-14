.PHONY: all build build-contracts build-rust anvil deploy mock-tee indexer client clean help

# Default Anvil account (first account)
PRIVATE_KEY ?= 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
RPC_URL ?= http://localhost:8545

# Contract addresses (set after deployment)
REGISTRY_ADDR ?=
POLICY_ADDR ?=

# TEE Address (derived from PRIVATE_KEY)
TEE_ADDR ?= 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

help:
	@echo "TEE Attestation MVP"
	@echo ""
	@echo "Usage:"
	@echo "  make build          - Build all components"
	@echo "  make anvil          - Start local Anvil node"
	@echo "  make deploy         - Deploy contracts to Anvil"
	@echo "  make mock-tee       - Run the mock TEE (requires REGISTRY_ADDR and POLICY_ADDR)"
	@echo "  make indexer        - Run the indexer (requires REGISTRY_ADDR)"
	@echo "  make client         - Run the client (requires TEE_ADDR)"
	@echo "  make demo           - Run full demo (requires separate terminals)"
	@echo ""
	@echo "Quick Start:"
	@echo "  Terminal 1: make anvil"
	@echo "  Terminal 2: make deploy"
	@echo "  Terminal 2: make mock-tee REGISTRY_ADDR=<addr> POLICY_ADDR=<addr>"
	@echo "  Terminal 3: make indexer REGISTRY_ADDR=<addr>"
	@echo "  Terminal 4: make client TEE_ADDR=<addr>"

all: build

build: build-contracts build-rust

build-contracts:
	@echo "Building Solidity contracts..."
	cd contracts && forge build

build-rust:
	@echo "Building Rust crates..."
	cargo build --release

anvil:
	@echo "Starting Anvil..."
	anvil --host 0.0.0.0

deploy:
	@echo "Deploying contracts..."
	cd contracts && forge script script/Deploy.s.sol:DeployScript \
		--rpc-url $(RPC_URL) \
		--private-key $(PRIVATE_KEY) \
		--broadcast
	@echo ""
	@echo "Contracts deployed! Check contracts/deployment.json for addresses"
	@cat contracts/deployment.json 2>/dev/null || echo "(deployment.json not found)"

mock-tee:
ifndef REGISTRY_ADDR
	$(error REGISTRY_ADDR is required. Run 'make deploy' first and set REGISTRY_ADDR)
endif
ifndef POLICY_ADDR
	$(error POLICY_ADDR is required. Run 'make deploy' first and set POLICY_ADDR)
endif
	@echo "Starting Mock TEE..."
	cargo run --release -p mock-tee -- \
		--rpc-url $(RPC_URL) \
		--registry $(REGISTRY_ADDR) \
		--policy $(POLICY_ADDR) \
		--private-key $(PRIVATE_KEY) \
		--setup-policy \
		--port 8443

mock-tee-skip-register:
ifndef REGISTRY_ADDR
	$(error REGISTRY_ADDR is required)
endif
ifndef POLICY_ADDR
	$(error POLICY_ADDR is required)
endif
	@echo "Starting Mock TEE (skip registration)..."
	cargo run --release -p mock-tee -- \
		--rpc-url $(RPC_URL) \
		--registry $(REGISTRY_ADDR) \
		--policy $(POLICY_ADDR) \
		--private-key $(PRIVATE_KEY) \
		--skip-register \
		--port 8443

indexer:
ifndef REGISTRY_ADDR
	$(error REGISTRY_ADDR is required. Run 'make deploy' first and set REGISTRY_ADDR)
endif
	@echo "Starting Indexer..."
	cargo run --release -p indexer -- \
		--rpc-url $(RPC_URL) \
		--registry $(REGISTRY_ADDR) \
		--port 8080

client:
ifndef TEE_ADDR
	$(error TEE_ADDR is required)
endif
	@echo "Running Client..."
	cargo run --release -p client -- \
		--indexer-url http://localhost:8080 \
		--tee-address $(TEE_ADDR) \
		--tee-host localhost \
		--tee-port 8443

test:
	@echo "Running tests..."
	cargo test
	cd contracts && forge test

clean:
	@echo "Cleaning..."
	cargo clean
	cd contracts && forge clean
	rm -f contracts/deployment.json

# Demo helper - prints instructions
demo:
	@echo "==============================================="
	@echo "TEE Attestation Demo"
	@echo "==============================================="
	@echo ""
	@echo "Run these commands in separate terminals:"
	@echo ""
	@echo "1. Start Anvil:"
	@echo "   make anvil"
	@echo ""
	@echo "2. Deploy contracts and start mock-tee:"
	@echo "   make deploy"
	@echo "   # Note the registry and policy addresses from output"
	@echo "   make mock-tee REGISTRY_ADDR=<registry> POLICY_ADDR=<policy>"
	@echo ""
	@echo "3. Start indexer:"
	@echo "   make indexer REGISTRY_ADDR=<registry>"
	@echo ""
	@echo "4. Run client:"
	@echo "   make client TEE_ADDR=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	@echo ""
	@echo "==============================================="
