from __future__ import annotations
from typing import TypeVar, Callable, Any, Optional, Type, Tuple
import time
import logging
from functools import wraps

from .exceptions import ProbeError, ConnectionError, TimeoutError

T = TypeVar('T')

def retry(
    max_retries: int = 3,
    initial_delay: float = 1.0,
    backoff_factor: float = 2.0,
    exceptions: Tuple[Type[Exception], ...] = (ConnectionError, TimeoutError)
) -> Callable:
    """Retry decorator with exponential backoff.
    
    Args:
        max_retries: Maximum number of retries
        initial_delay: Initial delay between retries in seconds
        backoff_factor: Factor to increase delay between retries
        exceptions: Tuple of exceptions to catch
        
    Returns:
        Decorated function
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            delay = initial_delay
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt == max_retries:
                        break
                        
                    # Calculate next delay with jitter
                    jitter = (0.5 + time.time() % 1.0) * 0.1
                    next_delay = delay * (1 + jitter)
                    
                    logging.warning(
                        f"Attempt {attempt + 1}/{max_retries + 1} failed: {str(e)}. "
                        f"Retrying in {next_delay:.2f} seconds..."
                    )
                    
                    time.sleep(delay)
                    delay *= backoff_factor
                    
            # If we get here, all retries failed
            if isinstance(last_exception, ProbeError):
                raise last_exception
            else:
                raise ProbeError(f"All retries failed: {str(last_exception)}")
                
        return wrapper
    return decorator

def validate_domain(domain: str) -> bool:
    """Validate domain name.
    
    Args:
        domain: Domain name to validate
        
    Returns:
        True if domain is valid, False otherwise
    """
    if not domain or len(domain) > 255:
        return False
        
    # Split domain into parts
    parts = domain.split(".")
    if len(parts) < 2:
        return False
        
    # Check each part
    for part in parts:
        if not part or len(part) > 63:
            return False
        if not all(c.isalnum() or c == "-" for c in part):
            return False
        if part.startswith("-") or part.endswith("-"):
            return False
            
    return True

def format_score(score: float) -> str:
    """Format score as percentage.
    
    Args:
        score: Score between 0 and 1
        
    Returns:
        Formatted score string
    """
    return f"{score * 100:.1f}%" 