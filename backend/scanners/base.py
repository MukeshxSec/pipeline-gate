"""Base scanner contract."""
from abc import ABC, abstractmethod


class BaseScanner(ABC):
    """Every scanner must inherit from this and implement scan()."""
    name: str = ""
    category: str = ""

    @abstractmethod
    def scan(self, target: str, options: dict = None) -> list[dict]:
        """Return raw findings from the underlying tool."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the tool binary is installed."""
        pass