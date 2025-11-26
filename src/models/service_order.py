from datetime import datetime, timezone
from pydantic import BaseModel, Field
from typing import List, Optional

from models.service_inventory import ServiceInventory
from models.service_spec import ServiceSpec, ServiceSpecCharacteristic

class OrderItemService(BaseModel):
    service_spec: Optional[ServiceSpec] = Field(alias="serviceSpecification", default=None)
    service_chars: Optional[List[ServiceSpecCharacteristic]] = Field(alias="serviceCharacteristic", default=None)
    supporting_services: Optional[List[ServiceInventory]] = Field(alias="supportingService", default=None)
    state: Optional[str] = None

    def __json__(self) -> dict:
        json = {}
        if self.service_spec is not None:
            json["serviceSpecification"] = self.service_spec.__json__()
        if self.service_chars is not None:
            json["serviceCharacteristic"] = [service_char.__json__() for service_char in self.service_chars]
        if self.state is not None:
            json["state"] = self.state
        return json
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, OrderItemService):
            return False
        return self.service_spec == other.service_spec and \
            len(self.service_chars) == len(other.service_chars) and \
            len(self.supporting_services) == len(other.supporting_services) and \
            self.state == other.state

class OrderItem(BaseModel):
    service: Optional[OrderItemService] = None
    action: Optional[str] = "add"
    id: Optional[str] = None
    uuid: Optional[str] = None
    href: Optional[str] = None
    state: Optional[str] = None
    base_type: Optional[str] = Field(alias="@baseType", default=None)
    type: Optional[str] = Field(alias="@type", default=None)
    schema_location: Optional[str] = Field(alias="@schemaLocation", default=None)

    def __json__(self) -> dict:
        json = {
            "service": self.service.__json__(),
            "action": self.action
        }
        if self.id is not None:
            json["id"] = self.id
        if self.uuid is not None:
            json["uuid"] = self.uuid
        if self.href is not None:
            json["href"] = self.href
        if self.state is not None:
            json["state"] = self.state
        if self.base_type is not None:
            json["@baseType"] = self.base_type
        if self.type is not None:
            json["@type"] = self.type
        if self.schema_location is not None:
            json["@schemaLocation"] = self.schema_location
        return json
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, OrderItem):
            return False
        return self.service == other.service and self.action == other.action and self.id == other.id

class ServiceOrder(BaseModel):
    id: Optional[str] = None
    state: Optional[str] = None
    expected_completion_date: Optional[str] = Field(alias="expectedCompletionDate", default=None)
    requested_completion_date: Optional[str] = Field(alias="requestedCompletionDate", default=None)
    requested_start_date: Optional[str] = Field(alias="requestedStartDate", default=None)
    order_items: Optional[List[OrderItem]] = Field(alias="orderItem", default=None)

    def is_active(self) -> bool:
        completion_time = datetime.fromisoformat(self.expected_completion_date.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        return now < completion_time
    
    def uses_service_spec(self, service_spec: ServiceSpec) -> bool:
        if not self.order_items:
            return False
        return any(order_item.service.service_spec.name == service_spec.name or \
                   order_item.service.service_spec.id == service_spec.id \
                   for order_item in self.order_items)
    
    def __json__(self) -> dict:
        json = {}
        if self.id is not None:
            json["id"] = self.id
        if self.expected_completion_date is not None:
            json["expectedCompletionDate"] = self.expected_completion_date
        if self.requested_completion_date is not None:
            json["requestedCompletionDate"] = self.requested_completion_date
        if self.requested_start_date is not None:
            json["requestedStartDate"] = self.requested_start_date
        if self.state is not None:
            json["state"] = self.state
        if self.order_items is not None:
            json["orderItem"] = [order_item.__json__() for order_item in self.order_items]
        return json
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, ServiceOrder):
            return False
        for self_order_item in self.order_items:
            if self_order_item not in other.order_items:
                return False
        for other_order_item in other.order_items:
            if other_order_item not in self.order_items:
                return False
        return self.state == other.state
