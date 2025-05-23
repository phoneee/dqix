from __future__ import annotations
from typing import List, Optional
from bs4 import BeautifulSoup, Tag

def get_title(soup: BeautifulSoup) -> Optional[str]:
    """Get page title.
    
    Args:
        soup: BeautifulSoup object
        
    Returns:
        Title text if found, None otherwise
    """
    title_tag = soup.find("title")
    return title_tag.text.strip() if title_tag else None

def get_images(soup: BeautifulSoup) -> List[Tag]:
    """Get all image tags.
    
    Args:
        soup: BeautifulSoup object
        
    Returns:
        List of img tags
    """
    return soup.find_all("img")

def get_inputs(soup: BeautifulSoup) -> List[Tag]:
    """Get all input tags.
    
    Args:
        soup: BeautifulSoup object
        
    Returns:
        List of input tags
    """
    return soup.find_all("input")

def get_links(soup: BeautifulSoup) -> List[Tag]:
    """Get all link tags.
    
    Args:
        soup: BeautifulSoup object
        
    Returns:
        List of a tags
    """
    return soup.find_all("a")

def get_meta_tags(soup: BeautifulSoup) -> List[Tag]:
    """Get all meta tags.
    
    Args:
        soup: BeautifulSoup object
        
    Returns:
        List of meta tags
    """
    return soup.find_all("meta")

def get_scripts(soup: BeautifulSoup) -> List[Tag]:
    """Get all script tags.
    
    Args:
        soup: BeautifulSoup object
        
    Returns:
        List of script tags
    """
    return soup.find_all("script")

def get_styles(soup: BeautifulSoup) -> List[Tag]:
    """Get all style tags.
    
    Args:
        soup: BeautifulSoup object
        
    Returns:
        List of style tags
    """
    return soup.find_all("style")

def get_links_with_rel(soup: BeautifulSoup, rel: str) -> List[Tag]:
    """Get link tags with specific rel attribute.
    
    Args:
        soup: BeautifulSoup object
        rel: rel attribute value to match
        
    Returns:
        List of matching link tags
    """
    return soup.find_all("link", rel=rel) 