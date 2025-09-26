from pydantic import BaseModel, Field
from typing import List, Optional

from models.service_spec import ServiceSpec, ServiceSpecCharacteristic

class ServiceInventory(BaseModel):
    name: str
    uuid: str
    id: Optional[str] = None
    description: Optional[str] = None
    start_date: Optional[str] = Field(alias="startDate", default=None)
    end_date: Optional[str] = Field(alias="endDate", default=None)
    state: Optional[str] = None
    service_order_id: Optional[str] = Field(alias="serviceOrderId", default=None)
    service_spec: Optional[ServiceSpec] = Field(alias="serviceSpecification", default=None)
    service_spec_characteristic: Optional[List[ServiceSpecCharacteristic]] = \
        Field(alias="serviceCharacteristic", default=[])
    service_type: Optional[str] = Field(alias="serviceType", default=None)
    supporting_service: Optional[List["ServiceInventory"]] = Field(alias="supportingService", default=[])

    def __json__(self) -> dict:
        json = {}
        if self.name is not None:
            json["name"] = self.name
        if self.uuid is not None:
            json["uuid"] = self.uuid
        if self.id is not None:
            json["id"] = self.id
        if self.description is not None:
            json["description"] = self.description
        if self.start_date is not None:
            json["startDate"] = self.start_date
        if self.end_date is not None:
            json["endDate"] = self.end_date
        if self.state is not None:
            json["state"] = self.state
        if self.service_order_id is not None:
            json["serviceOrderId"] = self.service_order_id
        if self.service_spec is not None:
            json["serviceSpecification"] = self.service_spec.__json__()
        if self.service_spec_characteristic is not None:
            json["serviceCharacteristic"] = [service_char.__json__() for service_char in self.service_spec_characteristic]
        if self.service_type is not None:
            json["serviceType"] = self.service_type
        return json
