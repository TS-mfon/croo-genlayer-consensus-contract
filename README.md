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

```bash
genlayer network set studionet
genvm-lint check contracts/consensus_verifier.py
pytest tests/direct -v
RUN_GENLAYER_INTEGRATION=1 gltest tests/integration -v -s --network studionet
```
