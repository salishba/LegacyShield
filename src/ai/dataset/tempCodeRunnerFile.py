 -------------------------------------------------
# # CVSS EXTRACTION (NVD v1 + v2 Compatible)
# # -------------------------------------------------

# def extract_cvss_metrics(item: Dict[str, Any]) -> Dict[str, Any]:
#     metrics = item.get("metrics") or safe_get(item, ["cve", "metrics"]) or {}

#     # Try CVSS v3 first
#     for key in ["cvssMetricV31", "cvssMetricV30"]:
#         if key in metrics and metrics[key]:
#             cvss_block = metrics[key][0]
#             cvss = cvss_block.get("cvssData", {})
#             return {
#                 "cvss_version": "3",
#                 "cvss_score": cvss.get("baseScore"),
#                 "attack_vector": cvss.get("attackVector"),
#                 "attack_complexity": cvss.get("attackComplexity"),
#                 "privileges_required": cvss.get("privilegesRequired"),
#                 "user_interaction": cvss.get("userInteraction"),
#                 "scope": cvss.get("scope"),
#                 "confidentiality_impact": cvss.get("confidentialityImpact"),
#                 "integrity_impact": cvss.get("integrityImpact"),
#                 "availability_impact": cvss.get("availabilityImpact"),
#             }

#     # Fallback to CVSS v2
#     if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
#         cvss_block = metrics["cvssMetricV2"][0]
#         cvss = cvss_block.get("cvssData", {})
#         return {
#             "cvss_version": "2",
#             "cvss_score": cvss.get("baseScore"),
#             "attack_vector": cvss.get("accessVector"),
#             "attack_complexity": cvss.get("accessComplexity"),
#             "privileges_required": cvss.get("authentication"),
#             "user_interaction": None,
#             "scope": None,
#             "confidentiality_impact": cvss.get("confidentialityImpact"),
#             "integrity_impact": cvss.get("integrityImpact"),
#             "availability_impact": cvss.get("availabilityImpact"),
#         }

#     return {k: None for k in [
#         "cvss_version", "cvss_score", "attack_vector",
#         "attack_complexity", "privileges_required",
#         "user_interaction", "scope",
#         "confidentiality_impact", "integrity_impact",
#         "availability_impact"
#     ]}
