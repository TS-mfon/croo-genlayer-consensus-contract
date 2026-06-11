# CROO GenLayer Consensus Contract

Intelligent contract for immutable, consensus-backed CROO report and content attestations.

```bash
genvm-lint check contracts/consensus_verifier.py
pytest tests/direct -v
```

Deployment requires a configured GenLayer account and network. Record the finalized deployment receipt and contract address before configuring the CROO Consensus Verifier worker.
