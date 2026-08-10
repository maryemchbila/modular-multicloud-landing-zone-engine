"""Interface extensible des regles du scanner de securite."""

from __future__ import annotations

from abc import ABC, abstractmethod

from security_models import SecurityFinding, SecurityResource, SecurityRuleMetadata


class SecurityRule(ABC):
    """Contrat d'une regle independante de Terraform et des SDK Cloud."""

    def __init__(self, metadata: SecurityRuleMetadata) -> None:
        if not isinstance(metadata, SecurityRuleMetadata):
            raise TypeError("metadata doit etre un SecurityRuleMetadata")
        self._metadata = metadata

    @property
    def metadata(self) -> SecurityRuleMetadata:
        return self._metadata

    @abstractmethod
    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        """Evalue une ressource applicable et retourne un finding unique."""

