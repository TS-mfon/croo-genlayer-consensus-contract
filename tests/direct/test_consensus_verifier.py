import json


HASH_A = "sha256:" + ("a" * 64)
HASH_B = "sha256:" + ("b" * 64)
EVIDENCE = "https://evidence.example/report.json"
SDK_VERSION = "v0.2.16"


def deploy(direct_vm, direct_deploy, owner):
    direct_vm.sender = owner
    return direct_deploy("contracts/consensus_verifier.py", sdk_version=SDK_VERSION)


def mock_supported(direct_vm, disputed=None):
    direct_vm.mock_web(r".*evidence\.example.*", {"status": 200, "body": '{"finding":"upgrade authority exists","risk":"high"}'})
    direct_vm.mock_llm(
        r".*conservative consensus verifier.*",
        json.dumps(
            {
                "verdict": "supported",
                "risk_tier": "high",
                "confidence": 88,
                "disputed_findings": disputed or [],
                "explanation": "Public evidence supports the submitted finding.",
            }
        ),
    )


def test_risk_assessment_full_flow(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    mock_supported(direct_vm)
    attestation_id = contract.submit_risk_assessment(
        HASH_A, EVIDENCE, "contract-risk", '["verify upgrade authority"]'
    )
    result = contract.get_attestation(attestation_id)
    assert result["verdict"] == "supported"
    assert result["risk_tier"] == "high"
    assert result["confidence"] == 88
    assert result["requested_checks"] == ["verify upgrade authority"]
    assert contract.get_attestations_for_report(HASH_A) == [attestation_id]
    assert contract.get_stats()["contract_risk"] == 1


def test_content_verification_flow(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    mock_supported(direct_vm)
    attestation_id = contract.submit_content_verification(HASH_A, EVIDENCE)
    assert contract.get_attestation(attestation_id)["task_type"] == "content-verification"
    assert contract.get_stats()["content_verification"] == 1


def test_conflict_resolution_records_disputes(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    mock_supported(direct_vm, ["Report B lacks evidence for blacklist authority"])
    attestation_id = contract.submit_report_comparison(
        HASH_B, EVIDENCE, '["blacklist authority","upgrade authority"]'
    )
    result = contract.get_attestation(attestation_id)
    assert result["task_type"] == "conflict-resolution"
    assert len(result["disputed_findings"]) == 1
    assert contract.get_stats()["conflict_resolution"] == 1


def test_multiple_immutable_attestations_are_indexed(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    mock_supported(direct_vm)
    first = contract.submit_content_verification(HASH_A, EVIDENCE)
    second = contract.submit_content_verification(HASH_A, EVIDENCE)
    assert first != second
    assert contract.get_attestations_for_report(HASH_A) == [first, second]
    assert contract.get_stats()["total_attestations"] == 2


def test_non_owner_cannot_submit(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("only service wallet may submit"):
        contract.submit_content_verification(HASH_A, EVIDENCE)


def test_invalid_hashes_rejected(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    for bad_hash in ("bad", "sha256:" + ("z" * 64), "sha256:" + ("a" * 63)):
        with direct_vm.expect_revert("invalid report hash"):
            contract.submit_risk_assessment(bad_hash, EVIDENCE, "contract-risk", "[]")


def test_non_https_and_oversized_uri_rejected(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    for uri in ("http://example.com", "https://" + ("x" * 501)):
        with direct_vm.expect_revert("evidence URI"):
            contract.submit_content_verification(HASH_A, uri)


def test_invalid_task_and_checks_rejected(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    with direct_vm.expect_revert("invalid task type"):
        contract.submit_risk_assessment(HASH_A, EVIDENCE, "anything", "[]")
    with direct_vm.expect_revert("requested checks must be JSON"):
        contract.submit_risk_assessment(HASH_A, EVIDENCE, "contract-risk", "bad")
    with direct_vm.expect_revert("invalid requested checks"):
        contract.submit_risk_assessment(HASH_A, EVIDENCE, "contract-risk", json.dumps(["x"] * 21))
    with direct_vm.expect_revert("invalid requested check"):
        contract.submit_risk_assessment(HASH_A, EVIDENCE, "contract-risk", '[""]')


def test_external_and_transient_evidence_failures(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    direct_vm.mock_web(r".*evidence\.example.*", {"status": 404, "body": "missing"})
    with direct_vm.expect_revert("evidence source rejected"):
        contract.submit_content_verification(HASH_A, EVIDENCE)
    direct_vm.clear_mocks()
    direct_vm.mock_web(r".*evidence\.example.*", {"status": 503, "body": "down"})
    with direct_vm.expect_revert("evidence source unavailable"):
        contract.submit_content_verification(HASH_A, EVIDENCE)


def test_malformed_llm_output_rejected(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    direct_vm.mock_web(r".*evidence\.example.*", {"status": 200, "body": "{}"})
    direct_vm.mock_llm(r".*conservative consensus verifier.*", json.dumps({"verdict": "invented", "risk_tier": "high"}))
    with direct_vm.expect_revert("invalid verdict"):
        contract.submit_content_verification(HASH_A, EVIDENCE)


def test_missing_attestation_rejected(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    with direct_vm.expect_revert("attestation not found"):
        contract.get_attestation("attestation-999")
