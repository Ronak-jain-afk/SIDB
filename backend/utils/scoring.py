"""
Security Scoring Utilities for Shadow IT Discovery Bot.
Calculates overall organizational security posture.
"""

from typing import List
from models import Asset, PostureScore, PostureRating, RiskLevel, ExposureLevel


class ScoringCalculator:
    """
    Calculates organizational security posture score.
    
    The posture score represents the overall security health
    of an organization based on all discovered assets.
    
    Formula: Security Score = 100 - weighted_average_risk
    
    Assets are weighted by exposure level (public assets matter more)
    and severity (critical issues weighted higher).
    """
    
    # Weight multipliers for exposure levels
    EXPOSURE_WEIGHTS = {
        ExposureLevel.PUBLIC: 1.5,      # Public assets are more critical
        ExposureLevel.RESTRICTED: 1.0,  # Normal weight
        ExposureLevel.INTERNAL: 0.5,    # Less impactful
    }
    
    # Weight multipliers for risk levels (used in severity distribution emphasis)
    RISK_WEIGHTS = {
        RiskLevel.CRITICAL: 2.0,
        RiskLevel.HIGH: 1.5,
        RiskLevel.MEDIUM: 1.0,
        RiskLevel.LOW: 0.5,
    }
    
    def calculate_posture_score(self, assets: List[Asset]) -> PostureScore:
        """
        Calculate the overall security posture score.
        
        The score considers:
        1. Individual asset risk scores
        2. Exposure level (public vs internal)
        3. Distribution of risk levels
        
        Args:
            assets: List of analyzed assets
            
        Returns:
            PostureScore with overall security assessment
        """
        if not assets:
            return PostureScore(
                score=100,
                rating=PostureRating.SECURE,
                summary="No assets discovered. No known exposure.",
                risk_distribution={
                    "Critical": 0,
                    "High": 0,
                    "Medium": 0,
                    "Low": 0
                }
            )
        
        # Calculate risk distribution
        risk_distribution = self._calculate_distribution(assets)
        
        # Calculate weighted average risk
        weighted_risk = self._calculate_weighted_risk(assets)
        
        # Security score is inverse of risk
        score = max(0, min(100, 100 - int(weighted_risk)))
        
        # Classify the rating
        rating = self._classify_rating(score)
        
        # Generate human-readable summary
        summary = self._generate_summary(score, rating, risk_distribution)
        
        return PostureScore(
            score=score,
            rating=rating,
            summary=summary,
            risk_distribution=risk_distribution
        )
    
    def _calculate_distribution(self, assets: List[Asset]) -> dict:
        """
        Calculate the count of assets by risk level.
        
        Used for dashboard visualization (pie charts, severity breakdown).
        """
        distribution = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0
        }
        
        for asset in assets:
            level = asset.risk_level.value if hasattr(asset.risk_level, 'value') else str(asset.risk_level)
            if level in distribution:
                distribution[level] += 1
        
        return distribution
    
    def _calculate_weighted_risk(self, assets: List[Asset]) -> float:
        """
        Calculate weighted average risk across all assets.
        
        Weighting:
        - Public assets weighted 1.5x (more critical)
        - Critical risks weighted 2x (more impactful)
        - Combines exposure and severity weights
        """
        if not assets:
            return 0.0
        
        total_weighted_score = 0.0
        total_weight = 0.0
        
        for asset in assets:
            # Get exposure weight
            exposure_weight = self.EXPOSURE_WEIGHTS.get(asset.exposure, 1.0)
            
            # Get risk level weight
            risk_weight = self.RISK_WEIGHTS.get(asset.risk_level, 1.0)
            
            # Combined weight
            combined_weight = exposure_weight * risk_weight
            
            # Add to totals
            total_weighted_score += asset.risk_score * combined_weight
            total_weight += combined_weight
        
        if total_weight == 0:
            return 0.0
        
        return total_weighted_score / total_weight
    
    def _classify_rating(self, score: int) -> PostureRating:
        """
        Classify score into posture rating.
        
        Thresholds:
        - 80-100: Secure
        - 60-79: Moderate Risk
        - 40-59: High Risk
        - 0-39: Critical Exposure
        """
        if score >= 80:
            return PostureRating.SECURE
        elif score >= 60:
            return PostureRating.MODERATE_RISK
        elif score >= 40:
            return PostureRating.HIGH_RISK
        else:
            return PostureRating.CRITICAL_EXPOSURE
    
    def _generate_summary(
        self, 
        score: int, 
        rating: PostureRating, 
        distribution: dict
    ) -> str:
        """
        Generate a human-readable summary of security posture.
        
        The summary helps non-technical stakeholders understand
        the security state of their organization.
        """
        critical_count = distribution.get("Critical", 0)
        high_count = distribution.get("High", 0)
        total = sum(distribution.values())
        
        if rating == PostureRating.SECURE:
            return (
                f"Organization has a strong security posture with a score of {score}/100. "
                f"Out of {total} discovered assets, most are properly configured. "
                "Continue monitoring and maintain current security practices."
            )
        
        elif rating == PostureRating.MODERATE_RISK:
            return (
                f"Organization has moderate security exposure (score: {score}/100). "
                f"Found {high_count} high-risk and {critical_count} critical issues "
                "that should be addressed in the near term. Review recommendations."
            )
        
        elif rating == PostureRating.HIGH_RISK:
            return (
                f"Organization has significant security exposure (score: {score}/100). "
                f"Detected {critical_count} critical and {high_count} high-risk assets. "
                "Immediate attention recommended to reduce attack surface."
            )
        
        else:  # CRITICAL_EXPOSURE
            return (
                f"ALERT: Organization has critical security exposure (score: {score}/100). "
                f"{critical_count} critical vulnerabilities require immediate action. "
                "Prioritize remediation of highest-risk assets to prevent potential breach."
            )


# Singleton instance (eager initialization)
_calculator_instance: ScoringCalculator = ScoringCalculator()


def get_scoring_calculator() -> ScoringCalculator:
    """Get the scoring calculator singleton."""
    return _calculator_instance


def calculate_posture_score(assets: List[Asset]) -> PostureScore:
    """Convenience function to calculate posture score."""
    return get_scoring_calculator().calculate_posture_score(assets)
