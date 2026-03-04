"""
label_generator.py - Deterministic Label Generator for Vulnerability Prioritization
Generates priority and action labels based on security rules.
"""

import pandas as pd
import numpy as np
import logging
from typing import Dict, List, Tuple, Optional,Any
from dataclasses import dataclass
from enum import IntEnum

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PriorityLabel(IntEnum):
    """Priority labels for ML classification"""
    LOW = 0
    MEDIUM = 1
    HIGH = 2


class ActionLabel(IntEnum):
    """Action labels for ML classification"""
    IGNORE = 0
    MITIGATE = 1
    PATCH_NOW = 2


@dataclass
class SecurityRule:
    """Security rule for deterministic labeling"""
    name: str
    priority_thresholds: Dict[str, float]  # Feature thresholds for priority
    action_conditions: List[Dict[str, Any]]  # Conditions for action
    description: str


class LabelGenerator:
    """
    Generates deterministic labels for vulnerability prioritization.
    Uses security rules based on industry best practices and organizational policies.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.rules = self._load_security_rules()
        logger.info("Initialized LabelGenerator with %d security rules", len(self.rules))
    
    def _load_security_rules(self) -> List[SecurityRule]:
        """Load security rules for deterministic labeling"""
        rules = [
            SecurityRule(
                name="Critical_Exploitation_Risk",
                priority_thresholds={
                    'cvss_score': 0.9,  # CVSS >= 9.0
                    'exploited_in_wild': 1.0,
                    'epss_probability': 0.5,
                },
                action_conditions=[
                    {
                        'condition': lambda row: row['patch_missing'] == 1.0 and row['patch_available'] == 1.0,
                        'action': ActionLabel.PATCH_NOW,
                        'reason': "Critical vulnerability with exploit available and patch exists"
                    },
                    {
                        'condition': lambda row: row['patch_missing'] == 1.0 and row['mitigation_available'] == 1.0,
                        'action': ActionLabel.MITIGATE,
                        'reason': "Critical vulnerability, mitigation available (no patch)"
                    }
                ],
                description="Critical CVSS with active exploitation"
            ),
            SecurityRule(
                name="Ransomware_Target",
                priority_thresholds={
                    'ransomware_associated': 1.0,
                    'cvss_score': 0.7,
                },
                action_conditions=[
                    {
                        'condition': lambda row: row['patch_missing'] == 1.0,
                        'action': ActionLabel.PATCH_NOW,
                        'reason': "Ransomware-associated vulnerability"
                    }
                ],
                description="Vulnerability associated with ransomware campaigns"
            ),
            SecurityRule(
                name="High_Risk_Server_Vulnerability",
                priority_thresholds={
                    'cvss_score': 0.7,
                    'system_role_score': 0.5,
                    'is_server': 1.0,
                },
                action_conditions=[
                    {
                        'condition': lambda row: row['patch_missing'] == 1.0,
                        'action': ActionLabel.PATCH_NOW,
                        'reason': "High risk vulnerability on server system"
                    }
                ],
                description="High CVSS on server systems"
            ),
            SecurityRule(
                name="Medium_Risk_With_Mitigation",
                priority_thresholds={
                    'cvss_score': 0.4,
                    'epss_probability': 0.1,
                },
                action_conditions=[
                    {
                        'condition': lambda row: row['patch_missing'] == 1.0 and row['mitigation_available'] == 1.0,
                        'action': ActionLabel.MITIGATE,
                        'reason': "Medium risk with available mitigation"
                    },
                    {
                        'condition': lambda row: row['patch_missing'] == 1.0 and row['patch_available'] == 1.0,
                        'action': ActionLabel.MITIGATE,
                        'reason': "Medium risk, patch available"
                    }
                ],
                description="Medium risk vulnerabilities"
            ),
            SecurityRule(
                name="Low_Risk_Legacy_System",
                priority_thresholds={
                    'cvss_score': 0.3,
                    'os_age_score': 0.8,
                },
                action_conditions=[
                    {
                        'condition': lambda row: row['patch_missing'] == 1.0,
                        'action': ActionLabel.IGNORE,
                        'reason': "Low risk on legacy system, risk acceptance"
                    }
                ],
                description="Low risk vulnerabilities on legacy systems"
            ),
            SecurityRule(
                name="Default_Rule",
                priority_thresholds={},  # Always matches
                action_conditions=[
                    {
                        'condition': lambda row: row['patch_missing'] == 0.0,
                        'action': ActionLabel.IGNORE,
                        'reason': "Patch already installed"
                    },
                    {
                        'condition': lambda row: row['threat_score'] < 0.3,
                        'action': ActionLabel.IGNORE,
                        'reason': "Very low threat score"
                    },
                    {
                        'condition': lambda row: True,  # Default catch-all
                        'action': ActionLabel.MITIGATE,
                        'reason': "Default: Apply mitigation if available"
                    }
                ],
                description="Default catch-all rule"
            ),
        ]
        return rules
    
    def _calculate_priority_score(self, row: pd.Series) -> float:
        """
        Calculate priority score based on weighted features.
        Higher score = higher priority.
        
        Scoring formula based on NIST SP 800-40 Rev.4 and MSRC severity guidelines:
        - CVSS: 40%
        - EPSS: 30%
        - Exploitation status: 15%
        - System context: 15%
        """
        try:
            score = (
                0.40 * row.get('cvss_score', 0.0) +
                0.30 * row.get('epss_probability', 0.0) +
                0.15 * row.get('exploited_in_wild', 0.0) +
                0.15 * row.get('system_role_score', 0.0)
            )
            
            # Bonus for ransomware
            if row.get('ransomware_associated', 0.0) == 1.0:
                score += 0.1
            
            # Bonus for proof of concept
            if row.get('proof_of_concept', 0.0) == 1.0:
                score += 0.05
            
            return min(1.0, score)  # Cap at 1.0
            
        except Exception as e:
            logger.warning(f"Error calculating priority score: {e}")
            return 0.5
    
    def _determine_priority_label(self, priority_score: float) -> PriorityLabel:
        """
        Determine priority label based on score.
        
        Thresholds based on security operations best practices:
        - HIGH: Score >= 0.7 (Immediate attention required)
        - MEDIUM: Score >= 0.4 (Schedule for next patch cycle)
        - LOW: Score < 0.4 (Monitor only)
        """
        if priority_score >= 0.7:
            return PriorityLabel.HIGH
        elif priority_score >= 0.4:
            return PriorityLabel.MEDIUM
        else:
            return PriorityLabel.LOW
    
    def _determine_action_label(self, row: pd.Series) -> Tuple[ActionLabel, str]:
        """
        Determine action label by evaluating security rules.
        Returns (action_label, reason)
        """
        for rule in self.rules:
            # Check if row meets priority thresholds
            rule_matches = True
            for feature, threshold in rule.priority_thresholds.items():
                if feature in row and row[feature] < threshold:
                    rule_matches = False
                    break
            
            if rule_matches:
                # Evaluate action conditions
                for condition_config in rule.action_conditions:
                    try:
                        if condition_config['condition'](row):
                            return condition_config['action'], f"{rule.name}: {condition_config['reason']}"
                    except Exception as e:
                        logger.warning(f"Error evaluating condition in rule {rule.name}: {e}")
                        continue
        
        # Fallback default
        return ActionLabel.IGNORE, "No matching rule found, default to ignore"
    
    def generate_labels(self, features_df: pd.DataFrame) -> pd.DataFrame:
        """
        Generate priority and action labels for all CVEs.
        
        Args:
            features_df: DataFrame from FeatureExtractor
            
        Returns:
            DataFrame with original features plus labels
        """
        if features_df.empty:
            logger.warning("Empty features DataFrame provided")
            return pd.DataFrame()
        
        logger.info(f"Generating labels for {len(features_df)} CVEs")
        
        # Make a copy to avoid modifying original
        labeled_df = features_df.copy()
        
        priority_scores = []
        priority_labels = []
        action_labels = []
        action_reasons = []
        
        for idx, row in labeled_df.iterrows():
            try:
                # Calculate priority
                priority_score = self._calculate_priority_score(row)
                priority_label = self._determine_priority_label(priority_score)
                
                # Determine action
                action_label, reason = self._determine_action_label(row)
                
                priority_scores.append(priority_score)
                priority_labels.append(priority_label.value)
                action_labels.append(action_label.value)
                action_reasons.append(reason)
                
            except Exception as e:
                logger.error(f"Error generating labels for row {idx}: {e}")
                priority_scores.append(0.5)
                priority_labels.append(PriorityLabel.MEDIUM.value)
                action_labels.append(ActionLabel.IGNORE.value)
                action_reasons.append(f"Error: {str(e)}")
        
        # Add labels to DataFrame
        labeled_df['priority_score'] = priority_scores
        labeled_df['priority_label'] = priority_labels
        labeled_df['action_label'] = action_labels
        labeled_df['action_reason'] = action_reasons
        
        # Calculate label distributions
        self._log_label_distributions(labeled_df)
        
        return labeled_df
    
    def _log_label_distributions(self, df: pd.DataFrame):
        """Log distribution of generated labels"""
        if 'priority_label' in df.columns:
            priority_counts = df['priority_label'].value_counts().sort_index()
            logger.info("Priority Label Distribution:")
            for label_value, count in priority_counts.items():
                label_name = PriorityLabel(label_value).name
                percentage = (count / len(df)) * 100
                logger.info(f"  {label_name}: {count} ({percentage:.1f}%)")
        
        if 'action_label' in df.columns:
            action_counts = df['action_label'].value_counts().sort_index()
            logger.info("Action Label Distribution:")
            for label_value, count in action_counts.items():
                label_name = ActionLabel(label_value).name
                percentage = (count / len(df)) * 100
                logger.info(f"  {label_name}: {count} ({percentage:.1f}%)")
    
    def get_label_descriptions(self) -> Dict[str, str]:
        """Return descriptions of generated labels"""
        return {
            'priority_score': 'Calculated priority score (0-1, higher=higher priority)',
            'priority_label': f'Priority classification: {[f"{l.name}={l.value}" for l in PriorityLabel]}',
            'action_label': f'Recommended action: {[f"{l.name}={l.value}" for l in ActionLabel]}',
            'action_reason': 'Explanation for the recommended action',
        }
    
    def validate_labels(self, labeled_df: pd.DataFrame) -> Dict[str, Any]:
        """
        Validate generated labels for consistency and quality.
        Returns validation results dictionary.
        """
        validation = {
            'total_cves': len(labeled_df),
            'has_priority_labels': 'priority_label' in labeled_df.columns,
            'has_action_labels': 'action_label' in labeled_df.columns,
            'issues': [],
            'warnings': [],
        }
        
        if labeled_df.empty:
            validation['issues'].append("Empty labeled dataset")
            return validation
        
        # Check for missing labels
        if 'priority_label' not in labeled_df.columns:
            validation['issues'].append("Missing priority_label column")
        
        if 'action_label' not in labeled_df.columns:
            validation['issues'].append("Missing action_label column")
        
        # Check label ranges
        if 'priority_label' in labeled_df.columns:
            valid_priorities = set([l.value for l in PriorityLabel])
            invalid_priorities = set(labeled_df['priority_label']) - valid_priorities
            if invalid_priorities:
                validation['issues'].append(f"Invalid priority labels: {invalid_priorities}")
        
        if 'action_label' in labeled_df.columns:
            valid_actions = set([l.value for l in ActionLabel])
            invalid_actions = set(labeled_df['action_label']) - valid_actions
            if invalid_actions:
                validation['issues'].append(f"Invalid action labels: {invalid_actions}")
        
        # Check for logical inconsistencies
        if all(col in labeled_df.columns for col in ['priority_label', 'action_label']):
            # HIGH priority should not have IGNORE action
            high_ignore = labeled_df[
                (labeled_df['priority_label'] == PriorityLabel.HIGH.value) & 
                (labeled_df['action_label'] == ActionLabel.IGNORE.value)
            ]
            
            if len(high_ignore) > 0:
                validation['warnings'].append(
                    f"{len(high_ignore)} CVEs with HIGH priority but IGNORE action"
                )
            
            # LOW priority with PATCH_NOW action should be reviewed
            low_patch_now = labeled_df[
                (labeled_df['priority_label'] == PriorityLabel.LOW.value) & 
                (labeled_df['action_label'] == ActionLabel.PATCH_NOW.value)
            ]
            
            if len(low_patch_now) > 0:
                validation['warnings'].append(
                    f"{len(low_patch_now)} CVEs with LOW priority but PATCH_NOW action"
                )
        
        # Check for missing CVE IDs (if present)
        if 'cve_id' in labeled_df.columns:
            missing_cve_ids = labeled_df['cve_id'].isna().sum()
            if missing_cve_ids > 0:
                validation['warnings'].append(f"{missing_cve_ids} CVEs missing CVE ID")
        
        return validation


# Convenience function
def generate_labels(features_df: pd.DataFrame, config: Optional[Dict] = None) -> pd.DataFrame:
    """
    High-level function to generate labels from features.
    
    Args:
        features_df: DataFrame from FeatureExtractor
        config: Optional configuration dictionary
        
    Returns:
        DataFrame with added labels
    """
    generator = LabelGenerator(config)
    return generator.generate_labels(features_df)


if __name__ == "__main__":
    # Test the label generator with sample data
    import numpy as np
    
    print("Testing LabelGenerator with sample data...")
    
    # Create sample features
    sample_data = {
        'cve_id': ['CVE-2023-1234', 'CVE-2023-5678', 'CVE-2023-9012', 'CVE-2023-3456'],
        'cvss_score': [0.95, 0.75, 0.35, 0.25],
        'epss_probability': [0.8, 0.3, 0.1, 0.05],
        'exploited_in_wild': [1.0, 0.0, 0.0, 0.0],
        'ransomware_associated': [1.0, 0.0, 0.0, 0.0],
        'proof_of_concept': [1.0, 1.0, 0.0, 0.0],
        'patch_available': [1.0, 1.0, 1.0, 0.0],
        'patch_missing': [1.0, 1.0, 1.0, 1.0],
        'detection_confidence': [0.9, 0.9, 0.9, 0.5],
        'mitigation_available': [1.0, 1.0, 1.0, 0.0],
        'mitigation_confidence': [0.8, 0.8, 0.8, 0.0],
        'os_age_score': [0.2, 0.5, 0.8, 0.9],
        'system_role_score': [0.8, 0.3, 0.2, 0.1],
        'is_domain_member': [1.0, 1.0, 0.0, 0.0],
        'is_server': [1.0, 0.0, 0.0, 0.0],
        'threat_score': [0.85, 0.45, 0.15, 0.08],
    }
    
    sample_df = pd.DataFrame(sample_data)
    
    # Generate labels
    generator = LabelGenerator()
    labeled_df = generator.generate_labels(sample_df)
    
    print("\nGenerated Labels:")
    print(labeled_df[['cve_id', 'priority_label', 'action_label', 'action_reason']])
    
    # Validate labels
    validation = generator.validate_labels(labeled_df)
    print("\nValidation Results:")
    print(f"Total CVEs: {validation['total_cves']}")
    if validation['issues']:
        print("Issues:")
        for issue in validation['issues']:
            print(f"  - {issue}")
    if validation['warnings']:
        print("Warnings:")
        for warning in validation['warnings']:
            print(f"  - {warning}")