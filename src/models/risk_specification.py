from typing import Any, List, Optional
from pydantic import BaseModel

class RiskSpecification(BaseModel):
    cpe: Optional[str] = None
    risk_score: Optional[float] = None
    privacy_score: Optional[float] = None
    anomalies: Optional[List[Any]] = None
