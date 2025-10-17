from fastapi import HTTPException, status
from typing import List, Optional

from apis.auth import Auth as AuthApi
from apis.tmf import Tmf as TmfApi
from models.service_inventory import ServiceInventory
from models.service_order import ServiceOrder
from models.service_spec import ServiceSpec, ServiceSpecCharacteristic, ServiceSpecCharacteristicValue, ServiceSpecCharacteristicValueAndAlias

class TmfApiConnector:
    _api: TmfApi

    def __init__(self, url: str):
        token = AuthApi(url).get_token()
        if not token:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Could not get authorization token from OpenSlice"
            )
        self._api = TmfApi(url, token)
        
    def get_service_spec(self, id: str) -> Optional[ServiceSpec]:
        try:
            return self._api.get_service_spec(id)
        except HTTPException:
            return None

    def get_service_order(self, id: str) -> Optional[ServiceOrder]:
        try:
            return self._api.get_service_order(id)
        except HTTPException:
            return None

    def get_service_inventory(self, id: str) -> Optional[ServiceInventory]:
        try:
            return self._api.get_service_inventory(id)
        except HTTPException:
            return None
    
    def list_service_orders(self) -> List[ServiceOrder]:
        try:
            return self._api.list_service_orders()
        except HTTPException:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Could not get Service Orders from OpenSlice"
            )

    def list_active_service_orders(self) -> List[ServiceOrder]:
        try:
            return [service_order for service_order in self._api.list_service_orders() if service_order.is_active()]
        except HTTPException:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Could not get Service Orders from OpenSlice"
            )
        
    def list_service_specs(self) -> List[ServiceSpec]:
        try:
            return [service_spec for service_spec in self._api.list_service_specs() if \
                    service_spec.type == "CustomerFacingServiceSpecification"]
        except HTTPException:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Could not get Service Specifications from OpenSlice"
            )
          
    def get_ids_of_service_orders_using_service_spec(self, service_spec: ServiceSpec) -> List[str]:
        try:
            ids_of_service_orders_using_service_spec = []
            service_order_ids = [service_order.id for service_order in self.list_active_service_orders()]
            for service_order_id in service_order_ids:
                service_order = self.get_service_order(service_order_id)
                if service_order.uses_service_spec(service_spec):
                    ids_of_service_orders_using_service_spec.append(service_order_id)
            return ids_of_service_orders_using_service_spec
        except HTTPException:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Could not get Service Inventory from OpenSlice"
            )
        
    def update_service_orders_and_inventories_from_service_spec(self, service_spec: ServiceSpec) -> List[ServiceOrder]:
        service_orders = []
        service_order_ids = self.get_ids_of_service_orders_using_service_spec(service_spec)
        for service_order_id in service_order_ids:
            service_order = self.update_service_order_and_inventories(service_order_id, service_spec)
            if service_order:
                service_orders.append(service_order)
        return service_orders
        
    def update_service_order_and_inventories(self, service_order_id: str, service_spec: ServiceSpec) -> Optional[ServiceOrder]:
        service_order = self.get_service_order(service_order_id)
        updated_service_order = self._update_service_order_from_service_spec(service_order, service_spec)
        service_inventory_ids = {
            supporting_service.id
            for order_item in service_order.order_items
            for supporting_service in order_item.service.supporting_services
        }
        for service_inventory_id in service_inventory_ids:
            self._update_service_inventory(service_inventory_id, service_spec)
        return updated_service_order
    
    def _update_service_order_from_service_spec(self, service_order: ServiceOrder, service_spec: ServiceSpec) -> Optional[ServiceOrder]:
        if not service_order:
            return None
        updated_service_order = \
            self._get_service_order_with_updated_characteristics(service_order, service_spec)
        if not updated_service_order:
            return None
        self._api.update_service_order(service_order.id, updated_service_order.__json__())
        return updated_service_order
    
    def _get_service_order_with_updated_characteristics(
        self, 
        service_order: ServiceOrder, 
        service_spec: ServiceSpec
    ) -> Optional[ServiceOrder]:
        for order_item in service_order.order_items:
            for service_spec_characteristic in service_spec.service_spec_characteristic:
                if "mutation::all" == service_spec_characteristic.name.lower():
                    for service_order_characteristic in order_item.service.service_chars:
                        if service_order_characteristic.name.lower().startswith("mutation::"):
                            INTERVAL_ALIAS = "interval"
                            service_spec.service_spec_characteristic.append(ServiceSpecCharacteristic(
                                name=service_order_characteristic.name, 
                                serviceSpecCharacteristicValue=[
                                    ServiceSpecCharacteristicValue(value=ServiceSpecCharacteristicValueAndAlias(
                                        value=service_spec_characteristic.find_value_from_alias(INTERVAL_ALIAS), 
                                        alias=INTERVAL_ALIAS
                                    ))
                                ]
                            ))
            service_spec_chars_names = [service_spec_characteristic.name for service_spec_characteristic in \
                                    service_spec.service_spec_characteristic]
            matching_service_order_chars = [service_order_characteristic for service_order_characteristic in \
                                            order_item.service.service_chars if \
                                            service_order_characteristic.name in service_spec_chars_names]
            updated_service_order_characteristics = \
                self._get_updated_service_spec_characteristics(service_spec, matching_service_order_chars)
            if updated_service_order_characteristics:
                order_item.service.service_chars = updated_service_order_characteristics
                order_item.action = "modify"
        order_items = [order_item for order_item in service_order.order_items if order_item.action == "modify"]
        if not order_items:
            return None
        service_order.order_items = order_items
        return service_order
    
    def _update_service_inventory(self, service_inventory_id: str, service_spec: ServiceSpec) -> Optional[ServiceInventory]:
        service_inventory = self.get_service_inventory(service_inventory_id)
        if not service_inventory:
            return None
        updated_service_inventory = \
            self._get_service_inventory_with_updated_characteristics(service_inventory, service_spec)
        if updated_service_inventory:
            self._api.update_service_inventory(service_inventory_id, updated_service_inventory.__json__())
        return updated_service_inventory
    
    def _get_service_inventory_with_updated_characteristics(
        self, 
        service_inventory: ServiceInventory, 
        service_spec: ServiceSpec
    ) -> Optional[ServiceOrder]:
        INTERVAL_ALIAS = "interval"
        for service_spec_characteristic in service_spec.service_spec_characteristic:
            if "mutation::all" == service_spec_characteristic.name.lower():
                for service_inventory_characteristic in service_inventory.service_spec_characteristic:
                    if service_inventory_characteristic.name.lower().startswith("mutation::"):
                        service_spec.service_spec_characteristic.append(ServiceSpecCharacteristic(
                            name=service_inventory_characteristic.name, 
                            serviceSpecCharacteristicValue=[
                                ServiceSpecCharacteristicValue(value=ServiceSpecCharacteristicValueAndAlias(
                                    value=service_spec_characteristic.find_value_from_alias(INTERVAL_ALIAS), 
                                    alias=INTERVAL_ALIAS
                                ))
                            ]
                        ))
        service_spec_chars_names = [service_spec_characteristic.name for service_spec_characteristic in \
                                service_spec.service_spec_characteristic]
        matching_service_inventory_chars = [service_inventory_characteristic for service_inventory_characteristic in \
                                        service_inventory.service_spec_characteristic if \
                                        service_inventory_characteristic.name in service_spec_chars_names]
        updated_service_inventory_characteristics = \
            self._get_updated_service_spec_characteristics(service_spec, matching_service_inventory_chars)
        if updated_service_inventory_characteristics:
            service_inventory.service_spec_characteristic = updated_service_inventory_characteristics
        return service_inventory
    
    def _get_updated_service_spec_characteristics(
        self, 
        service_spec: ServiceSpec, 
        relevant_service_spec_characteristics: List[ServiceSpecCharacteristic]
    ) -> List[ServiceSpecCharacteristic]:
        updated_service_spec_characteristics = []
        for relevant_service_spec_characteristic in relevant_service_spec_characteristics:
            updated = False
            for relevant_service_spec_characteristic_value in \
            self._get_mutable_service_spec_char_values(relevant_service_spec_characteristic):
                for service_spec_characteristic in service_spec.service_spec_characteristic:
                    if service_spec_characteristic.name.lower() not in \
                    relevant_service_spec_characteristic.name.lower():
                        continue
                    for service_spec_characteristic_value in \
                    self._get_mutable_service_spec_char_values(service_spec_characteristic):
                        if relevant_service_spec_characteristic_value.value != \
                        service_spec_characteristic_value.value:
                            if (service_spec_characteristic_value.alias == "interval" and \
                            relevant_service_spec_characteristic_value.alias == "interval") \
                            or (service_spec_characteristic_value.alias != "interval" and \
                            relevant_service_spec_characteristic_value.alias != "interval"):
                                relevant_service_spec_characteristic_value.value = \
                                    service_spec_characteristic_value.value
                                updated = True
            if updated:
                updated_service_spec_characteristics.append(relevant_service_spec_characteristic)
        return updated_service_spec_characteristics
    
    def _get_mutable_service_spec_char_values(self, service_spec_characteristic: ServiceSpecCharacteristic) \
    -> List[ServiceSpecCharacteristicValueAndAlias]:
        IMMUTABLE_ALIASES = {"member_vnf_index", "kdu_name", "valueFrom", "valueTo"}
        return [service_spec_char_value.value for service_spec_char_value in \
                service_spec_characteristic.service_spec_characteristic_value if \
                service_spec_char_value.value.alias not in IMMUTABLE_ALIASES]
