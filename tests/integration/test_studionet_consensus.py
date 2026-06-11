import os

import pytest
from gltest import get_contract_factory
from gltest.assertions import tx_execution_succeeded


HASH = "sha256:" + ("a" * 64)
EVIDENCE_URI = os.getenv(
    "CROO_EVIDENCE_URI",
    "https://raw.githubusercontent.com/TS-mfon/croo-genlayer-consensus-contract/master/evidence/studionet-risk-report.json",
)


@pytest.mark.skipif(
    not os.getenv("RUN_GENLAYER_INTEGRATION"),
    reason="requires explicit Studionet integration opt-in",
)
def test_studionet_full_consensus_risk_assessment():
    contract = get_contract_factory("ConsensusVerifier").deploy(args=[])
    receipt = contract.submit_risk_assessment(
        args=[HASH, EVIDENCE_URI, "contract-risk", '["verify upgrade authority"]']
    ).transact()
    assert tx_execution_succeeded(receipt)

    stats = contract.get_stats(args=[]).call()
    assert stats["total_attestations"] == 1
    assert stats["contract_risk"] == 1

    ids = contract.get_attestations_for_report(args=[HASH]).call()
    assert len(ids) == 1
    attestation = contract.get_attestation(args=[ids[0]]).call()
    assert attestation["task_type"] == "contract-risk"
    assert attestation["verdict"] in (
        "supported",
        "partially_supported",
        "unsupported",
        "inconclusive",
    )
    assert 0 <= attestation["confidence"] <= 100


@pytest.mark.skipif(
    not os.getenv("RUN_GENLAYER_INTEGRATION"),
    reason="requires explicit Studionet integration opt-in",
)
def test_studionet_full_consensus_content_verification():
    contract = get_contract_factory("ConsensusVerifier").deploy(args=[])
    receipt = contract.submit_content_verification(args=[HASH, EVIDENCE_URI]).transact()
    assert tx_execution_succeeded(receipt)
    stats = contract.get_stats(args=[]).call()
    assert stats["content_verification"] == 1
