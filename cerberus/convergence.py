"""
CERBERUS Convergence Loop

Instead of a linear pipeline (scan → analyze → test), this runs an
iterative loop until the three heads reach consensus:

  Round 1:
    Head 1 (scanner)     → raw findings
    Intent Analyzer      → intent mismatches
    Head 2 (AI)          → classifies each: confirmed / false_positive / needs_test
    Head 3 (Unity)       → generates + runs tests for confirmed + needs_test

  Round 2:
    Head 2 re-evaluates  → uses test results as evidence
    - Test PASSED on a "confirmed" bug? Bug is proven reachable. Stays confirmed.
    - Test FAILED on a "confirmed" bug? Bug may not be reachable. Reclassify.
    - Test PASSED on a "needs_test"? Now confirmed.
    - Test FAILED on a "needs_test"? Likely false positive. Suppress.
    Head 3 re-generates  → new tests for any reclassified findings

  Round N:
    Loop until:
    - No findings change classification between rounds, OR
    - Max iterations reached (default: 3)

The convergence criterion is STABILITY — when the findings stop changing,
all three heads agree on the final state of every finding.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
import json
import copy


class Classification(str, Enum):
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    NEEDS_TEST = "needs_test"
    SUPPRESSED = "suppressed"


class TestEvidence(str, Enum):
    PASS = "pass"           # Test proved the bug is reachable
    FAIL = "fail"           # Test could not trigger the bug
    COMPILE_ERROR = "compile_error"  # Test didn't compile (inconclusive)
    NOT_TESTED = "not_tested"


@dataclass
class TrackedFinding:
    """A finding tracked through the convergence loop."""
    finding: Dict[str, Any]  # Original finding data
    source_head: str         # "head1", "intent", "head2"
    classification: Classification = Classification.NEEDS_TEST
    test_evidence: TestEvidence = TestEvidence.NOT_TESTED
    test_name: Optional[str] = None
    round_classified: int = 0
    round_confirmed: int = 0
    history: List[str] = field(default_factory=list)  # Audit trail

    def reclassify(self, new_class: Classification, reason: str, round_num: int):
        old = self.classification
        self.classification = new_class
        self.round_classified = round_num
        if new_class == Classification.CONFIRMED:
            self.round_confirmed = round_num
        self.history.append(f"R{round_num}: {old.value} → {new_class.value} ({reason})")

    @property
    def id(self) -> str:
        return self.finding.get("id", "?")

    @property
    def severity(self) -> str:
        return self.finding.get("severity", "info")


@dataclass
class ConvergenceState:
    """Full state of the convergence loop."""
    tracked: List[TrackedFinding] = field(default_factory=list)
    round_num: int = 0
    converged: bool = False
    max_rounds: int = 3
    history: List[Dict[str, Any]] = field(default_factory=list)

    def snapshot(self) -> Dict[str, str]:
        """Capture current classification state for convergence check."""
        return {f.id: f.classification.value for f in self.tracked}

    def add_findings(self, findings: List[Dict[str, Any]], source: str):
        """Add new findings from a head."""
        for f in findings:
            self.tracked.append(TrackedFinding(
                finding=f,
                source_head=source,
                classification=Classification.NEEDS_TEST,
            ))

    @property
    def confirmed(self) -> List[TrackedFinding]:
        return [f for f in self.tracked if f.classification == Classification.CONFIRMED]

    @property
    def false_positives(self) -> List[TrackedFinding]:
        return [f for f in self.tracked if f.classification == Classification.FALSE_POSITIVE]

    @property
    def needs_test(self) -> List[TrackedFinding]:
        return [f for f in self.tracked if f.classification == Classification.NEEDS_TEST]

    @property
    def actionable(self) -> List[TrackedFinding]:
        return [f for f in self.tracked if f.classification in
                (Classification.CONFIRMED, Classification.NEEDS_TEST)]


def apply_head2_classifications(
    state: ConvergenceState,
    ai_classifications: List[Dict[str, Any]],
    round_num: int,
):
    """
    Apply Head 2 AI classifications to tracked findings.

    ai_classifications format:
    [
        {"id": "S001", "classification": "confirmed|false_positive|needs_test", "reason": "..."},
        ...
    ]
    """
    class_map = {c["id"]: c for c in ai_classifications}

    for tf in state.tracked:
        if tf.id in class_map:
            c = class_map[tf.id]
            new_class = Classification(c["classification"])
            tf.reclassify(new_class, c.get("reason", "Head 2 classification"), round_num)


def apply_test_results(
    state: ConvergenceState,
    test_results: List[Dict[str, Any]],
    round_num: int,
):
    """
    Apply Head 3 test results as evidence, then reclassify.

    test_results format:
    [
        {"finding_id": "A001", "test_name": "test_A001_...", "result": "pass|fail"},
        ...
    ]
    """
    result_map = {}
    for tr in test_results:
        fid = tr.get("finding_id", "")
        result_map[fid] = tr

    for tf in state.tracked:
        if tf.id in result_map:
            tr = result_map[tf.id]
            result = tr.get("result", "not_tested")

            if result == "pass":
                tf.test_evidence = TestEvidence.PASS
                tf.test_name = tr.get("test_name")

                if tf.classification == Classification.NEEDS_TEST:
                    tf.reclassify(Classification.CONFIRMED,
                                  f"Test {tf.test_name} PASSED — bug is reachable",
                                  round_num)
                elif tf.classification == Classification.CONFIRMED:
                    tf.history.append(f"R{round_num}: Test confirms — bug is proven reachable")

            elif result == "fail":
                tf.test_evidence = TestEvidence.FAIL
                tf.test_name = tr.get("test_name")

                if tf.classification == Classification.NEEDS_TEST:
                    tf.reclassify(Classification.SUPPRESSED,
                                  f"Test {tf.test_name} FAILED — bug not reachable in test context",
                                  round_num)
                elif tf.classification == Classification.CONFIRMED:
                    # Don't auto-suppress confirmed findings on test failure —
                    # the test might be insufficient. Flag for review.
                    tf.history.append(
                        f"R{round_num}: WARNING — Test failed but finding was previously confirmed. "
                        f"Test may be insufficient, not the finding.")

            elif result == "compile_error":
                tf.test_evidence = TestEvidence.COMPILE_ERROR
                tf.history.append(f"R{round_num}: Test compilation failed — inconclusive")


def check_convergence(state: ConvergenceState) -> bool:
    """
    Check if findings have stabilized between rounds.

    Convergence = no finding changed classification since last round.
    """
    if len(state.history) < 2:
        return False

    prev = state.history[-2]
    curr = state.history[-1]

    # Compare classification maps
    return prev == curr


def run_convergence_round(state: ConvergenceState) -> Dict[str, Any]:
    """
    Execute one round of the convergence loop.

    Returns a summary of what changed.
    """
    state.round_num += 1
    pre_snapshot = state.snapshot()

    # Record state
    state.history.append(state.snapshot())

    # Check convergence
    if check_convergence(state):
        state.converged = True

    return {
        "round": state.round_num,
        "total_tracked": len(state.tracked),
        "confirmed": len(state.confirmed),
        "false_positives": len(state.false_positives),
        "needs_test": len(state.needs_test),
        "converged": state.converged,
    }


def generate_convergence_report(state: ConvergenceState) -> Dict[str, Any]:
    """Generate the final consensus report."""
    return {
        "converged": state.converged,
        "rounds": state.round_num,
        "total_findings_reviewed": len(state.tracked),
        "consensus": {
            "confirmed": len(state.confirmed),
            "false_positive": len(state.false_positives),
            "needs_test": len(state.needs_test),
            "suppressed": len([f for f in state.tracked
                               if f.classification == Classification.SUPPRESSED]),
        },
        "confirmed_findings": [
            {
                **f.finding,
                "test_evidence": f.test_evidence.value,
                "test_name": f.test_name,
                "classification_history": f.history,
            }
            for f in state.confirmed
        ],
        "false_positives": [
            {
                "id": f.id,
                "title": f.finding.get("title", ""),
                "reason": f.history[-1] if f.history else "Classified by Head 2",
            }
            for f in state.false_positives
        ],
        "suppressed": [
            {
                "id": f.id,
                "title": f.finding.get("title", ""),
                "reason": f.history[-1] if f.history else "Suppressed by test evidence",
            }
            for f in state.tracked if f.classification == Classification.SUPPRESSED
        ],
    }
