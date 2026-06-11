# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from dataclasses import dataclass
import json
from genlayer import *


ERROR_EXPECTED = "[EXPECTED]"
ERROR_EXTERNAL = "[EXTERNAL]"
ERROR_TRANSIENT = "[TRANSIENT]"
ERROR_LLM = "[LLM_ERROR]"

VERDICTS = ("supported", "partially_supported", "unsupported", "inconclusive")
RISK_TIERS = ("low", "medium", "high", "critical")
TASK_TYPES = ("contract-risk", "content-verification", "conflict-resolution")
MAX_EVIDENCE_BYTES = 24000
MAX_CHECKS = 20
MAX_CHECK_LENGTH = 240
MAX_EXPLANATION_LENGTH = 800
MAX_DISPUTED_FINDINGS = 12


def _bounded_int(value, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except Exception:
        raise gl.vm.UserError(f"{ERROR_LLM} invalid integer")
    return max(minimum, min(maximum, parsed))


def _bounded_strings(value, maximum_items: int, maximum_length: int) -> list[str]:
    if not isinstance(value, list):
        raise gl.vm.UserError(f"{ERROR_LLM} expected list")
    result = []
    for item in value[:maximum_items]:
        text = str(item).strip()
        if text:
            result.append(text[:maximum_length])
    return result


def _handle_leader_error(leaders_res, leader_fn) -> bool:
    leader_message = leaders_res.message if hasattr(leaders_res, "message") else ""
    try:
        leader_fn()
        return False
    except gl.vm.UserError as error:
        validator_message = error.message if hasattr(error, "message") else str(error)
        if validator_message.startswith(ERROR_EXPECTED) or validator_message.startswith(ERROR_EXTERNAL):
            return validator_message == leader_message
        if validator_message.startswith(ERROR_TRANSIENT) and leader_message.startswith(ERROR_TRANSIENT):
            return True
        return False
    except Exception:
        return False


def _fetch_evidence(uri: str) -> str:
    try:
        response = gl.nondet.web.get(uri)
        if response.status >= 500:
            raise gl.vm.UserError(f"{ERROR_TRANSIENT} evidence source unavailable")
        if response.status >= 400:
            raise gl.vm.UserError(f"{ERROR_EXTERNAL} evidence source rejected")
        body = response.body.decode("utf-8", errors="ignore")
        if not body.strip():
            raise gl.vm.UserError(f"{ERROR_EXTERNAL} empty evidence")
        return body[:MAX_EVIDENCE_BYTES]
    except gl.vm.UserError:
        raise
    except Exception:
        raise gl.vm.UserError(f"{ERROR_TRANSIENT} evidence fetch failed")


def _normalize_assessment(raw: dict) -> dict:
    if not isinstance(raw, dict):
        raise gl.vm.UserError(f"{ERROR_LLM} non-object response")
    verdict = str(raw.get("verdict", "inconclusive")).strip().lower()
    risk_tier = str(raw.get("risk_tier", "medium")).strip().lower()
    if verdict not in VERDICTS:
        raise gl.vm.UserError(f"{ERROR_LLM} invalid verdict")
    if risk_tier not in RISK_TIERS:
        raise gl.vm.UserError(f"{ERROR_LLM} invalid risk tier")
    return {
        "verdict": verdict,
        "risk_tier": risk_tier,
        "confidence": _bounded_int(raw.get("confidence", 0), 0, 100),
        "disputed_findings": _bounded_strings(
            raw.get("disputed_findings", []), MAX_DISPUTED_FINDINGS, 300
        ),
        "explanation": str(raw.get("explanation", "")).strip()[:MAX_EXPLANATION_LENGTH],
    }


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
    disputed_findings_json: str
    requested_checks_json: str
    submitter: Address


class ConsensusVerifier(gl.Contract):
    owner: Address
    attestations: TreeMap[str, Attestation]
    report_attestations: TreeMap[str, str]
    attestation_order: DynArray[str]
    next_id: u256
    task_counts: TreeMap[str, u256]

    def __init__(self):
        self.owner = gl.message.sender_address
        self.next_id = u256(1)

    def _require_owner(self) -> None:
        if gl.message.sender_address != self.owner:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} only service wallet may submit")

    def _validate_hash(self, value: str, label: str) -> None:
        if not value.startswith("sha256:") or len(value) != 71:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} invalid {label}")
        for char in value[7:]:
            if char not in "0123456789abcdef":
                raise gl.vm.UserError(f"{ERROR_EXPECTED} invalid {label}")

    def _validate_uri(self, uri: str) -> None:
        if not uri.startswith("https://") or len(uri) > 500:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} evidence URI must be bounded HTTPS")

    def _validate_checks(self, checks_json: str) -> list[str]:
        if len(checks_json) > 6000:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} requested checks too large")
        try:
            checks = json.loads(checks_json)
        except Exception:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} requested checks must be JSON")
        if not isinstance(checks, list) or len(checks) > MAX_CHECKS:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} invalid requested checks")
        result = []
        for check in checks:
            if not isinstance(check, str) or not check.strip() or len(check) > MAX_CHECK_LENGTH:
                raise gl.vm.UserError(f"{ERROR_EXPECTED} invalid requested check")
            result.append(check.strip())
        return result

    def _assess(self, report_hash: str, evidence_uri: str, task_type: str, checks: list[str]) -> dict:
        checks_json = json.dumps(checks, sort_keys=True, separators=(",", ":"))

        def leader_fn():
            evidence = _fetch_evidence(evidence_uri)
            prompt = f"""You are a conservative consensus verifier for paid agent outputs.
Use only the supplied evidence. Never invent facts or treat an assertion as evidence.

Task type: {task_type}
Submitted report/content hash: {report_hash}
Requested checks: {checks_json}
Evidence URI: {evidence_uri}
Evidence:
{evidence}

For contract-risk tasks, decide whether the evidence supports the findings and risk tier.
For content-verification tasks, decide whether every material factual claim is supported.
For conflict-resolution tasks, identify which disputed claims are unsupported or unresolved.

Return bounded JSON only:
{{
  "verdict": "supported|partially_supported|unsupported|inconclusive",
  "risk_tier": "low|medium|high|critical",
  "confidence": 0-100,
  "disputed_findings": ["max 12 concise strings"],
  "explanation": "max 800 characters"
}}"""
            return _normalize_assessment(gl.nondet.exec_prompt(prompt, response_format="json"))

        def validator_fn(leaders_res: gl.vm.Result) -> bool:
            if not isinstance(leaders_res, gl.vm.Return):
                return _handle_leader_error(leaders_res, leader_fn)
            validator = leader_fn()
            leader = leaders_res.calldata
            if leader["verdict"] != validator["verdict"]:
                return False
            if leader["risk_tier"] != validator["risk_tier"]:
                return False
            if abs(leader["confidence"] - validator["confidence"]) > 20:
                return False
            leader_disputed = len(leader["disputed_findings"]) > 0
            validator_disputed = len(validator["disputed_findings"]) > 0
            return leader_disputed == validator_disputed

        return gl.vm.run_nondet_unsafe(leader_fn, validator_fn)

    def _store(
        self,
        report_hash: str,
        evidence_uri: str,
        task_type: str,
        checks: list[str],
        assessment: dict,
    ) -> str:
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
            disputed_findings_json=json.dumps(
                assessment["disputed_findings"], sort_keys=True, separators=(",", ":")
            ),
            requested_checks_json=json.dumps(checks, sort_keys=True, separators=(",", ":")),
            submitter=gl.message.sender_address,
        )
        self.attestations[attestation_id] = item
        report_ids = json.loads(self.report_attestations.get(report_hash, "[]"))
        report_ids.append(attestation_id)
        self.report_attestations[report_hash] = json.dumps(report_ids, separators=(",", ":"))
        self.attestation_order.append(attestation_id)
        self.task_counts[task_type] = u256(int(self.task_counts.get(task_type, u256(0))) + 1)
        return attestation_id

    def _submit(self, report_hash: str, evidence_uri: str, task_type: str, checks_json: str) -> str:
        self._require_owner()
        self._validate_hash(report_hash, "report hash")
        self._validate_uri(evidence_uri)
        if task_type not in TASK_TYPES:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} invalid task type")
        checks = self._validate_checks(checks_json)
        assessment = self._assess(report_hash, evidence_uri, task_type, checks)
        return self._store(report_hash, evidence_uri, task_type, checks, assessment)

    @gl.public.write
    def submit_risk_assessment(
        self, report_hash: str, evidence_uri: str, task_type: str, requested_checks_json: str
    ) -> str:
        return self._submit(report_hash, evidence_uri, task_type, requested_checks_json)

    @gl.public.write
    def submit_content_verification(self, content_hash: str, evidence_uri: str) -> str:
        return self._submit(content_hash, evidence_uri, "content-verification", "[]")

    @gl.public.write
    def submit_report_comparison(
        self, comparison_hash: str, evidence_uri: str, disputed_claims_json: str
    ) -> str:
        return self._submit(
            comparison_hash, evidence_uri, "conflict-resolution", disputed_claims_json
        )

    @gl.public.view
    def get_attestation(self, attestation_id: str) -> dict:
        if attestation_id not in self.attestations:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} attestation not found")
        item = self.attestations[attestation_id]
        return {
            "attestation_id": item.attestation_id,
            "report_hash": item.report_hash,
            "task_type": item.task_type,
            "verdict": item.verdict,
            "risk_tier": item.risk_tier,
            "confidence": int(item.confidence),
            "disputed_findings": json.loads(item.disputed_findings_json),
            "requested_checks": json.loads(item.requested_checks_json),
            "consensus_explanation": item.explanation,
            "evidence_uri": item.evidence_uri,
            "submitter": str(item.submitter),
        }

    @gl.public.view
    def get_attestations_for_report(self, report_hash: str) -> list[str]:
        return json.loads(self.report_attestations.get(report_hash, "[]"))

    @gl.public.view
    def get_stats(self) -> dict:
        return {
            "owner": str(self.owner),
            "total_attestations": len(self.attestation_order),
            "contract_risk": int(self.task_counts.get("contract-risk", u256(0))),
            "content_verification": int(
                self.task_counts.get("content-verification", u256(0))
            ),
            "conflict_resolution": int(
                self.task_counts.get("conflict-resolution", u256(0))
            ),
        }
