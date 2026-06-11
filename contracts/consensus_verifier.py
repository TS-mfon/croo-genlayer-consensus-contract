# { "Depends": "py-genlayer:latest" }
from dataclasses import dataclass
import json
from genlayer import *


ERROR_LLM = "[LLM_ERROR]"


@allow_storage
@dataclass
class Attestation:
    attestation_id: str
    report_hash: str
    task_type: str
    verdict: str
    risk_tier: str
    confidence: u256
    explanation: str
    evidence_uri: str
    submitter: Address


class ConsensusVerifier(gl.Contract):
    owner: Address
    attestations: TreeMap[str, Attestation]
    report_attestations: TreeMap[str, str]
    attestation_order: DynArray[str]
    next_id: u256

    def __init__(self):
        self.owner = gl.message.sender_address
        self.next_id = u256(1)

    def _assess(self, report_hash: str, evidence_uri: str, task_type: str, checks_json: str) -> dict:
        prompt = f"""Assess public evidence for a CROO agent result.
Report hash: {report_hash}
Evidence URI: {evidence_uri}
Task: {task_type}
Requested checks: {checks_json}

Return bounded JSON only:
{{"verdict":"supported|partially_supported|unsupported|inconclusive",
"risk_tier":"low|medium|high|critical","confidence":0-100,
"explanation":"max 600 chars"}}"""

        def leader_fn():
            raw = gl.nondet.exec_prompt(prompt, response_format="json")
            if not isinstance(raw, dict):
                raise gl.vm.UserError(f"{ERROR_LLM} non-object response")
            verdict = str(raw.get("verdict", "inconclusive"))
            risk_tier = str(raw.get("risk_tier", "medium"))
            if verdict not in ("supported", "partially_supported", "unsupported", "inconclusive"):
                verdict = "inconclusive"
            if risk_tier not in ("low", "medium", "high", "critical"):
                risk_tier = "medium"
            try:
                confidence = max(0, min(100, int(raw.get("confidence", 0))))
            except Exception:
                raise gl.vm.UserError(f"{ERROR_LLM} invalid confidence")
            return {
                "verdict": verdict,
                "risk_tier": risk_tier,
                "confidence": confidence,
                "explanation": str(raw.get("explanation", ""))[:600],
            }

        def validator_fn(leaders_res: gl.vm.Result) -> bool:
            if not isinstance(leaders_res, gl.vm.Return):
                return False
            validation = leader_fn()
            leader = leaders_res.calldata
            return (
                validation["verdict"] == leader["verdict"]
                and validation["risk_tier"] == leader["risk_tier"]
                and abs(validation["confidence"] - leader["confidence"]) <= 20
            )

        return gl.vm.run_nondet_unsafe(leader_fn, validator_fn)

    def _store(self, report_hash: str, evidence_uri: str, task_type: str, assessment: dict) -> str:
        attestation_id = "attestation-" + str(self.next_id)
        self.next_id = u256(int(self.next_id) + 1)
        item = Attestation(
            attestation_id=attestation_id,
            report_hash=report_hash,
            task_type=task_type,
            verdict=assessment["verdict"],
            risk_tier=assessment["risk_tier"],
            confidence=u256(assessment["confidence"]),
            explanation=assessment["explanation"],
            evidence_uri=evidence_uri,
            submitter=gl.message.sender_address,
        )
        self.attestations[attestation_id] = item
        existing = json.loads(self.report_attestations.get(report_hash, "[]"))
        existing.append(attestation_id)
        self.report_attestations[report_hash] = json.dumps(existing, separators=(",", ":"))
        self.attestation_order.append(attestation_id)
        return attestation_id

    @gl.public.write
    def submit_risk_assessment(self, report_hash: str, evidence_uri: str, task_type: str, requested_checks_json: str) -> str:
        if not report_hash.startswith("sha256:") or len(report_hash) != 71:
            raise gl.vm.UserError("Invalid report hash")
        checks = json.loads(requested_checks_json)
        if not isinstance(checks, list) or len(checks) > 20:
            raise gl.vm.UserError("Invalid requested checks")
        assessment = self._assess(report_hash, evidence_uri, task_type, requested_checks_json)
        return self._store(report_hash, evidence_uri, task_type, assessment)

    @gl.public.write
    def submit_content_verification(self, content_hash: str, evidence_uri: str) -> str:
        if not content_hash.startswith("sha256:") or len(content_hash) != 71:
            raise gl.vm.UserError("Invalid content hash")
        assessment = self._assess(content_hash, evidence_uri, "content-verification", "[]")
        return self._store(content_hash, evidence_uri, "content-verification", assessment)

    @gl.public.view
    def get_attestation(self, attestation_id: str) -> dict:
        item = self.attestations[attestation_id]
        return {
            "attestation_id": item.attestation_id,
            "report_hash": item.report_hash,
            "task_type": item.task_type,
            "verdict": item.verdict,
            "risk_tier": item.risk_tier,
            "confidence": int(item.confidence),
            "consensus_explanation": item.explanation,
            "evidence_uri": item.evidence_uri,
            "submitter": str(item.submitter),
        }

    @gl.public.view
    def get_attestations_for_report(self, report_hash: str) -> list[str]:
        return json.loads(self.report_attestations.get(report_hash, "[]"))
