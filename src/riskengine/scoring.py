"""scoring.py - Deterministic HARS (Hybrid Automated Risk Scoring) Model
Pure functions for vulnerability risk scoring with no external dependencies.
"""

import math
from typing import Dict, Any, Optional, Tuple
from datetime import datetime
from patch_context import resolve_patch_context
from typing import Literal

# ============================================================================
# PURE HELPER FUNCTIONS
# ============================================================================

def clamp(value: float, min_val: float = 0.0, max_val: float = 1.0) -> float:
    """
    Clamp a value between minimum and maximum bounds.
    
    Args:
        value: Value to clamp
        min_val: Minimum allowed value (default: 0.0)
        max_val: Maximum allowed value (default: 1.0)
    
    Returns:
        Clamped value within [min_val, max_val]
    
    Examples:
        >>> clamp(1.5)
        1.0
        >>> clamp(-0.5)
        0.0
        >>> clamp(0.75)
        0.75
    """
    return max(min_val, min(max_val, value))


def normalize_cvss(cvss_score: float) -> float:
    """
    Normalize CVSS score from 0-10 scale to 0-1 scale.
    
    Args:
        cvss_score: CVSS base score (0.0 to 10.0)
    
    Returns:
        Normalized score between 0.0 and 1.0
    
    Raises:
        ValueError: If cvss_score is outside valid range
    
    Examples:
        >>> normalize_cvss(9.8)
        0.98
        >>> normalize_cvss(5.5)
        0.55
    """
    if not 0.0 <= cvss_score <= 10.0:
        raise ValueError(f"CVSS score must be between 0.0 and 10.0, got {cvss_score}")
    
    return clamp(cvss_score / 10.0)


def exponential_decay(value: float, half_life: float = 0.5) -> float:
    """
    Apply exponential decay transformation to value.
    Useful for weighting recent/urgent factors more heavily.
    
    Args:
        value: Input value (0.0 to 1.0)
        half_life: Value at which decay reaches 0.5 (default: 0.5)
    
    Returns:
        Decayed value between 0.0 and 1.0
    
    Examples:
        >>> exponential_decay(0.5)
        0.7071067811865476
        >>> exponential_decay(0.9)
        0.9486832980505138
    """
    value = clamp(value)
    # Transform: f(x) = 1 - (1 - x)^(1/half_life)
    return 1.0 - math.pow(1.0 - value, 1.0 / half_life)


def weighted_average(values: Dict[str, float], weights: Dict[str, float]) -> float:
    """
    Calculate weighted average with validation.
    
    Args:
        values: Dictionary of values to average
        weights: Dictionary of weights for each value
    
    Returns:
        Weighted average
    
    Raises:
        ValueError: If weights don't sum to ~1.0 or if keys don't match
        KeyError: If value keys don't match weight keys
    
    Examples:
        >>> weighted_average({'a': 0.8, 'b': 0.4}, {'a': 0.7, 'b': 0.3})
        0.68
    """
    # Validate inputs
    if set(values.keys()) != set(weights.keys()):
        raise KeyError("Value and weight keys must match")
    
    weight_sum = sum(weights.values())
    if not math.isclose(weight_sum, 1.0, rel_tol=1e-9):
        raise ValueError(f"Weights must sum to 1.0, got {weight_sum}")
    
    # Calculate weighted average
    weighted_sum = sum(values[key] * weights[key] for key in values)
    return clamp(weighted_sum)


# ============================================================================
# HARS CORE SCORING FUNCTIONS
# ============================================================================

def calculate_r_score(
    cvss: float,
    epss: float,
    exploited: bool = False,
    poc_available: bool = False,
    ransomware_used: bool = False ) -> float:
    """
    Calculate R (Risk) Score based on threat characteristics.
    
    R Score = Threat Likelihood × Impact Severity
    
    Formula:
        R = 0.40 × EPSS (probability of exploitation)
           + 0.20 × Exploited (in wild)
           + 0.15 × PoC Available
           + 0.15 × Ransomware Associated
           + 0.10 × CVSS (normalized)
    
    Args:
        cvss: CVSS base score (0.0-10.0)
        epss: EPSS probability (0.0-1.0)
        exploited: Whether exploited in wild
        poc_available: Whether proof-of-concept exists
        ransomware_used: Whether associated with ransomware

    
    Returns:
        R Score between 0.0 and 1.0
    
    Examples:
        >>> calculate_r_score(9.8, 0.85, True, True, True)
        0.98
    """
    # Validate inputs
    cvss_norm = normalize_cvss(cvss)
    epss = clamp(epss)
    
    # Convert booleans to numeric
    exploited_val = 1.0 if exploited else 0.0
    poc_val = 1.0 if poc_available else 0.0
    ransomware_val = 1.0 if ransomware_used else 0.0
    
    # Apply exponential decay to threat indicators for urgency
    exploited_weighted = exponential_decay(exploited_val, half_life=0.3)
    ransomware_weighted = exponential_decay(ransomware_val, half_life=0.3)
    
    # Component values with weights from HARS v1 specification
    values = {
        'epss': epss,
        'exploited': exploited_weighted,
        'poc': poc_val,
        'ransomware': ransomware_weighted,
        'cvss': cvss_norm
    }
    
    weights = {
        'epss': 0.40,      # Primary indicator: exploitation probability
        'exploited': 0.20, # Active exploitation adds significant risk
        'poc': 0.15,       # Proof-of-concept enables easier exploitation
        'ransomware': 0.15, # Ransomware campaigns are high-impact
        'cvss': 0.10       # Base severity (weighted lower than EPSS)
    }
    
    r_score = weighted_average(values, weights)
    
    # Apply boost for critical combinations
    if exploited and ransomware_used:
        r_score = clamp(r_score * 1.15)  # 15% boost for exploited ransomware
    
    return clamp(r_score)


def calculate_a_score(
    patch_status: Literal[
        "PATCHED",
        "SUPERSEDED",
        "APPLICABLE_MISSING",
        "NOT_APPLICABLE",
        "MITIGATION_ONLY",
        "UNKNOWN"
    ],
    patch_missing: bool,
    mitigation_available: bool,
    system_role: str = "workstation"
) -> float:

    """
    Calculate A (Attack Surface) Score based on system exposure.
    
    A Score = System Vulnerability × Attack Feasibility
    
    Args:
        patch_status: Patch status ("MISSING", "COVERED", "MITIGATION_ONLY")
        patch_missing: Whether patch is missing (boolean)
        mitigation_available: Whether mitigation is available
        system_role: System role ("workstation", "server", "domain_controller")
    
    Returns:
        A Score between 0.0 and 1.0
    
    Examples:
        >>> calculate_a_score("MISSING", True, False, "server")
        1.0
        >>> calculate_a_score("COVERED", False, True, "workstation")
        0.5
    """
    # Base score based on patch status
    status_scores = {
        "PATCHED": 0.4,
        "SUPERSEDED": 0.6,
        "APPLICABLE_MISSING": 1.0,
        "MITIGATION_ONLY": 0.7,
        "NOT_APPLICABLE": 0.2,
        "UNKNOWN": 0.8,
    }
    
    base_score = status_scores.get(patch_status.upper(), 0.8)
    
    # Adjust based on boolean patch_missing for consistency
    if patch_missing:
        base_score = max(base_score, 0.9)
    else:
        base_score = min(base_score, 0.5)
    
    # Adjust for mitigation availability
    if mitigation_available:
        # Mitigation reduces attack surface but doesn't eliminate it
        base_score *= 0.7
    
    # System role multipliers
    role_multipliers = {
        "domain_controller": 1.5,  # Critical infrastructure
        "server": 1.3,            # Business-critical servers
        "database_server": 1.4,   # Data systems
        "web_server": 1.3,        # Internet-facing
        "file_server": 1.2,       # Data storage
        "workstation": 1.0,       # Standard endpoint
        "laptop": 0.9,            # Mobile, less predictable exposure
    }
    
    multiplier = role_multipliers.get(system_role.lower(), 1.0)
    a_score = base_score * multiplier
    
    return a_score


def calculate_c_score(
    detection_confidence: float,
    patch_confidence: float = 1.0,
    data_freshness: float = 1.0,
    verification_status: str = "unverified"
) -> float:
    """
    Calculate C (Confidence) Score based on data quality and verification.
    
    C Score = Data Confidence × Verification Level
    
    Args:
        detection_confidence: Confidence in vulnerability detection (0.0-1.0)
        patch_confidence: Confidence in patch mapping (0.0-1.0)
        data_freshness: How fresh the data is (1.0 = current, decays over time)
        verification_status: Verification level ("verified", "confirmed", "unverified")
    
    Returns:
        C Score between 0.0 and 1.0
    
    Examples:
        >>> calculate_c_score(0.9, 0.8, 1.0, "verified")
        0.81
    """
    # Validate inputs
    detection_confidence = clamp(detection_confidence)
    patch_confidence = clamp(patch_confidence)
    data_freshness = clamp(data_freshness)
    
    # Base confidence from detection and patch mapping
    base_confidence = (detection_confidence * 0.6 + patch_confidence * 0.4)
    
    # Apply data freshness decay
    # Data older than 30 days starts to lose confidence
    freshness_adjusted = base_confidence * data_freshness
    
    # Verification multipliers
    verification_multipliers = {
        "verified": 1.0,      # Manually verified
        "confirmed": 0.9,     # Multiple sources confirm
        "corroborated": 0.8,  # Evidence from 2+ sources
        "reported": 0.7,      # Single source report
        "unverified": 0.6,    # Automated detection only
        "suspected": 0.5,     # Heuristic match
    }
    
    multiplier = verification_multipliers.get(
        verification_status.lower(), 
        verification_multipliers["unverified"]
    )
    
    c_score = clamp(freshness_adjusted * multiplier)
    
    return c_score


def calculate_final_score(
    r_score: float,
    a_score: float,
    c_score: float,
    adjustment_factors: Optional[Dict[str, float]] = None
) -> Tuple[float, Dict[str, float]]:
    """
    Calculate final HARS score using multiplicative model.
    
    Final Score = R × A × C
    
    Args:
        r_score: Risk score (0.0-1.0)
        a_score: Attack surface score (0.0-1.0)
        c_score: Confidence score (0.0-1.0)
        adjustment_factors: Optional adjustment factors
    
    Returns:
        Tuple of (final_score, component_scores)
    
    Examples:
        >>> calculate_final_score(0.8, 0.9, 0.7)
        (0.504, {'r': 0.8, 'a': 0.9, 'c': 0.7, 'final': 0.504})
    """
    # Validate component scores
    r_score = clamp(r_score)
    a_score = clamp(a_score)
    c_score = clamp(c_score)
    
    # Apply any adjustment factors
    if adjustment_factors:
        r_adjust = adjustment_factors.get('r_adjust', 1.0)
        a_adjust = adjustment_factors.get('a_adjust', 1.0)
        c_adjust = adjustment_factors.get('c_adjust', 1.0)
        
        r_score = clamp(r_score * r_adjust)
        a_score = clamp(a_score * a_adjust)
        c_score = clamp(c_score * c_adjust)
    
    # Multiplicative model: R × A × C
    # This ensures low confidence or low attack surface reduces final score
    final_score = clamp(r_score * a_score * c_score)
    
    # Package results
    component_scores = {
        'r': r_score,
        'a': a_score,
        'c': c_score,
        'final': final_score
    }
    
    return final_score, component_scores


def determine_priority(final_score: float) -> str:
    """
    Determine priority level based on final score.
    
    Thresholds:
        HIGH: ≥ 0.70 (Critical/Immediate action)
        MEDIUM: ≥ 0.35 (Schedule for next patch cycle)
        LOW: < 0.35 (Monitor/Defer)
    
    Args:
        final_score: Final HARS score (0.0-1.0)
    
    Returns:
        Priority level: "HIGH", "MEDIUM", or "LOW"
    
    Examples:
        >>> determine_priority(0.85)
        'HIGH'
        >>> determine_priority(0.45)
        'MEDIUM'
        >>> determine_priority(0.2)
        'LOW'
    """
    final_score = clamp(final_score)
    
    if final_score >= 0.70:
        return "HIGH"
    elif final_score >= 0.35:
        return "MEDIUM"
    else:
        return "LOW"


def calculate_hars_scores(
    cve_id: str,
    cvss: float,
    epss: float,
    exploited: bool,
    poc_available: bool,
    ransomware_used: bool,
    detection_confidence: float,
    db_path: str,
    mitigation_available: bool = False,
    system_role: str = "workstation",
    data_freshness: float = 1.0,
    verification_status: str = "unverified",
    adjustment_factors: Optional[Dict[str, float]] = None
) -> Dict[str, Any]:

    """
    Calculate complete HARS scores from vulnerability data.
    
    This is the main entry point for HARS scoring.
    
    Args:
        cvss: CVSS base score (0.0-10.0)
        epss: EPSS probability (0.0-1.0)
        exploited: Whether exploited in wild
        poc_available: Whether proof-of-concept exists
        ransomware_used: Whether associated with ransomware
        patch_status: Patch status string
        patch_missing: Boolean if patch is missing
        detection_confidence: Confidence in detection (0.0-1.0)
        mitigation_available: Whether mitigation is available
        system_role: System role/type
        patch_confidence: Confidence in patch mapping
        data_freshness: Freshness of data (1.0 = current)
        verification_status: Data verification level
        adjustment_factors: Optional adjustment factors
    
    Returns:
        Dictionary with all scores and priority
    
    Examples:
        >>> scores = calculate_hars_scores(
        ...     cvss=9.8,
        ...     epss=0.85,
        ...     exploited=True,
        ...     poc_available=True,
        ...     ransomware_used=True,
        ...     patch_status="MISSING",
        ...     patch_missing=True,
        ...     detection_confidence=0.9,
        ...     system_role="server"
        ... )
        >>> scores['priority']
        'HIGH'
    """
    patch_status, patch_missing, patch_confidence = resolve_patch_context(
        db_path="E:/download/uni/FYP/code/cve_kb.db",
        cve_id=cve_id
)
    # Calculate component scores
    r_score = calculate_r_score(
        cvss=cvss,
        epss=epss,
        exploited=exploited,
        poc_available=poc_available,
        ransomware_used=ransomware_used)
    
    a_score = calculate_a_score(
        patch_status=patch_status,
        patch_missing=patch_missing,
        mitigation_available=mitigation_available,
        system_role=system_role
    )
    
    c_score = calculate_c_score(
        detection_confidence=detection_confidence,
        patch_confidence=patch_confidence,
        data_freshness=data_freshness,
        verification_status=verification_status
    )
    
    # Calculate final score
    final_score, components = calculate_final_score(
        r_score=r_score,
        a_score=a_score,
        c_score=c_score,
        adjustment_factors=adjustment_factors
    )
    
    # Determine priority
    priority = determine_priority(final_score)
    
    # Return complete results
    return {
        'r_score': r_score,
        'a_score': a_score,
        'c_score': c_score,
        'final_score': final_score,
        'priority': priority,
        'component_scores': components,
        'model_version': 'HARS-v1-deterministic',
        'calculated_at': datetime.utcnow().isoformat()
    }


# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

def validate_scoring_inputs(
    cvss: float,
    epss: float,
    detection_confidence: float,
    patch_confidence: Optional[float] = None,
    data_freshness: Optional[float] = None
) -> Tuple[bool, Optional[str]]:
    """
    Validate inputs for HARS scoring.
    
    Args:
        cvss: CVSS score to validate
        epss: EPSS probability to validate
        detection_confidence: Detection confidence to validate
        patch_confidence: Optional patch confidence
        data_freshness: Optional data freshness
    
    Returns:
        Tuple of (is_valid, error_message)
    
    Examples:
        >>> validate_scoring_inputs(9.8, 0.85, 0.9)
        (True, None)
        >>> validate_scoring_inputs(11.0, 0.85, 0.9)
        (False, 'CVSS score 11.0 outside valid range 0.0-10.0')
    """
    # Validate CVSS
    if not 0.0 <= cvss <= 10.0:
        return False, f"CVSS score {cvss} outside valid range 0.0-10.0"
    
    # Validate EPSS
    if not 0.0 <= epss <= 1.0:
        return False, f"EPSS probability {epss} outside valid range 0.0-1.0"
    
    # Validate detection confidence
    if not 0.0 <= detection_confidence <= 1.0:
        return False, f"Detection confidence {detection_confidence} outside valid range 0.0-1.0"
    
    # Validate optional parameters
    if patch_confidence is not None and not 0.0 <= patch_confidence <= 1.0:
        return False, f"Patch confidence {patch_confidence} outside valid range 0.0-1.0"
    
    if data_freshness is not None and not 0.0 <= data_freshness <= 1.0:
        return False, f"Data freshness {data_freshness} outside valid range 0.0-1.0"
    
    return True, None


# ============================================================================
# TEST FUNCTIONS (For validation only, not production)
# ============================================================================

def _test_hars_scoring() -> None:
    """Test HARS scoring with example data"""
    test_cases = [
        {
            'name': 'Critical ransomware exploit on server',
            'cvss': 9.8,
            'epss': 0.95,
            'exploited': True,
            'poc_available': True,
            'ransomware_used': True,
            'patch_status': 'MISSING',
            'patch_missing': True,
            'detection_confidence': 0.9,
            'system_role': 'server'
        },
        {
            'name': 'Medium severity with patch available',
            'cvss': 5.5,
            'epss': 0.3,
            'exploited': False,
            'poc_available': False,
            'ransomware_used': False,
            'patch_status': 'COVERED',
            'patch_missing': False,
            'detection_confidence': 0.8,
            'system_role': 'workstation'
        },
        {
            'name': 'Low confidence detection on legacy system',
            'cvss': 7.2,
            'epss': 0.1,
            'exploited': False,
            'poc_available': True,
            'ransomware_used': False,
            'patch_status': 'UNKNOWN',
            'patch_missing': True,
            'detection_confidence': 0.4,
            'system_role': 'workstation',
            'data_freshness': 0.6
        }
    ]
    
    print("HARS Scoring Test Results:")
    print("=" * 80)
    
    for test in test_cases:
        label = test.pop("name")                 # UI label only
        test.pop("patch_status", None)            # resolved internally
        test.pop("patch_missing", None)           # resolved internally

        # Inject required fields
        test["cve_id"] = "CVE-2023-0001"
        test["db_path"] = "E:/download/uni/FYP/code/cve_kb.db"

        scores = calculate_hars_scores(**test)

        print(f"\nTest: {label}")
        print(f"  R Score: {scores['r_score']:.3f}")
        print(f"  A Score: {scores['a_score']:.3f}")
        print(f"  C Score: {scores['c_score']:.3f}")
        print(f"  Final Score: {scores['final_score']:.3f}")
        print(f"  Priority: {scores['priority']}")

    
    print("\n" + "=" * 80)


if __name__ == "__main__":
    # Run tests if executed directly
    _test_hars_scoring()