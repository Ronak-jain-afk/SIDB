"""
Rate Limiter for Shadow IT Discovery Bot.
Implements token bucket algorithm for API rate limiting.
"""

import asyncio
import time
from typing import Dict, Optional


class RateLimiter:
    """
    Token bucket rate limiter for API calls.
    
    Shodan API limits:
    - Free tier: 1 request/second
    - Paid tiers: Higher limits
    
    This implementation is async-safe and supports multiple named buckets.
    """
    
    def __init__(
        self,
        requests_per_second: float = 1.0,
        burst_size: int = 1
    ):
        """
        Initialize rate limiter.
        
        Args:
            requests_per_second: Maximum sustained request rate
            burst_size: Maximum burst capacity (tokens)
        """
        self.rate = requests_per_second
        self.burst_size = burst_size
        self.tokens = burst_size
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()
    
    async def acquire(self, tokens: int = 1) -> float:
        """
        Acquire tokens, waiting if necessary.
        
        Args:
            tokens: Number of tokens to acquire
            
        Returns:
            Time waited in seconds
        """
        async with self._lock:
            wait_time = 0.0
            
            # Replenish tokens based on elapsed time
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(
                self.burst_size,
                self.tokens + elapsed * self.rate
            )
            self.last_update = now
            
            # Check if we need to wait
            if self.tokens < tokens:
                # Calculate wait time
                deficit = tokens - self.tokens
                wait_time = deficit / self.rate
                
                # Wait for tokens to replenish
                await asyncio.sleep(wait_time)
                
                # Update after waiting
                self.tokens = min(
                    self.burst_size,
                    self.tokens + wait_time * self.rate
                )
            
            # Consume tokens
            self.tokens -= tokens
            
            return wait_time
    
    def try_acquire(self, tokens: int = 1) -> bool:
        """
        Try to acquire tokens without waiting.
        
        Args:
            tokens: Number of tokens to acquire
            
        Returns:
            True if tokens were acquired, False otherwise
        """
        # Replenish tokens
        now = time.monotonic()
        elapsed = now - self.last_update
        self.tokens = min(
            self.burst_size,
            self.tokens + elapsed * self.rate
        )
        self.last_update = now
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False


class MultiRateLimiter:
    """
    Manages multiple rate limiters for different APIs/endpoints.
    """
    
    def __init__(self):
        self._limiters: Dict[str, RateLimiter] = {}
    
    def get_limiter(
        self,
        name: str,
        requests_per_second: float = 1.0,
        burst_size: int = 1
    ) -> RateLimiter:
        """
        Get or create a named rate limiter.
        
        Args:
            name: Unique identifier for the limiter
            requests_per_second: Rate limit
            burst_size: Burst capacity
            
        Returns:
            RateLimiter instance
        """
        if name not in self._limiters:
            self._limiters[name] = RateLimiter(
                requests_per_second=requests_per_second,
                burst_size=burst_size
            )
        return self._limiters[name]
    
    async def acquire(self, name: str, tokens: int = 1) -> float:
        """Acquire tokens from a named limiter."""
        limiter = self._limiters.get(name)
        if limiter:
            return await limiter.acquire(tokens)
        return 0.0


# Global rate limiter instance
_rate_limiter: Optional[MultiRateLimiter] = None


def get_rate_limiter() -> MultiRateLimiter:
    """Get the global rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = MultiRateLimiter()
    return _rate_limiter
