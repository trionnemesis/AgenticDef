class InvestigationError(Exception):
    """A typed, auditable investigation failure."""


class ContractError(InvestigationError): pass
class PolicyError(InvestigationError): pass
class BudgetError(InvestigationError): pass
class ToolNotAllowedError(PolicyError): pass
class ScopeError(PolicyError): pass
class ToolExecutionError(InvestigationError): pass
class ModelError(InvestigationError): pass
class GroundingError(InvestigationError): pass
class PersistenceError(InvestigationError): pass
