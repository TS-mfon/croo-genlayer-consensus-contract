# CROO GenLayer Consensus Contract

Intelligent contract for immutable, consensus-backed CROO report and content attestations.

```bash
genvm-lint check contracts/consensus_verifier.py
pytest tests/direct -v
```

Deployment requires a configured GenLayer account and network. Record the finalized deployment receipt and contract address before configuring the CROO Consensus Verifier worker.

## Studionet

This contract is designed for a dedicated gasless service wallet. End users never sign
GenLayer transactions; the CROO worker validates paid orders and submits bounded
verification requests from the service wallet.

- Contract: `0x3895AEB8A2259729b954Dd7B27226f47230D231E`
- Service wallet: `0x5DC9080F23878117df370e93E52523312C0FC397`
- Deployment transaction: `0x7a40ae8d2638256ab2b651dcefd068250875ca67416f33d4a922e8dd491c7072`
- Public verification record: `deployment/studionet.json`

```bash
genlayer network set studionet
genvm-lint check contracts/consensus_verifier.py
pytest tests/direct -v
RUN_GENLAYER_INTEGRATION=1 gltest tests/integration -v -s --network studionet
```

The direct suite and live Studionet transactions are authoritative. The current
`gltest` integration client cannot create transactions against Studionet because its
installed Web3 adapter expects an obsolete `argument_types` field; this fails before
contract execution.
