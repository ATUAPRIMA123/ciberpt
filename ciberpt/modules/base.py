from abc import ABC, abstractmethod
from typing import List
from ciberpt.core.models import Finding


class BaseScanner(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Identificador unico do modulo."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Descricao sucinta do escopo da analise."""
        pass

    @abstractmethod
    def scan(self, target: str, **kwargs) -> List[Finding]:
        """Executa a analise defensiva e retorna a lista de achados identificados."""
        pass
