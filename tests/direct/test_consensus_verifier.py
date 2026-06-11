import json


HASH = "sha256:" + ("a" * 64)


def test_submit_and_lookup(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/consensus_verifier.py", sdk_version="v0.2.16")
    direct_vm.sender = direct_alice
    direct_vm.mock_llm(
        r".*Assess public evidence.*",
        json.dumps({"verdict": "supported", "risk_tier": "medium", "confidence": 82, "explanation": "Evidence supports the bounded finding."}),
    )
    attestation_id = contract.submit_risk_assessment(HASH, "https://example.com/evidence.json", "contract-risk", "[]")
    result = contract.get_attestation(attestation_id)
    assert result["verdict"] == "supported"
    assert result["confidence"] == 82
    assert contract.get_attestations_for_report(HASH) == [attestation_id]


def test_rejects_invalid_hash(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/consensus_verifier.py", sdk_version="v0.2.16")
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("Invalid report hash"):
        contract.submit_risk_assessment("bad", "https://example.com", "contract-risk", "[]")
