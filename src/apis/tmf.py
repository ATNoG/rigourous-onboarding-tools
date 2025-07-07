import copy
import requests

from typing import Any, List, Optional

from apis.bearer_auth import BearerAuth
from apis.openslice import OpenSlice
from models.service_inventory import ServiceInventory
from models.service_order import ServiceOrder
from models.service_spec import ServiceSpec

class Tmf(OpenSlice):
    TMF_URL = "/tmf-api"
    API_VERSION = "v4"

    def __init__(self, url: str, token: str):
        super().__init__(url)
        self._auth = BearerAuth(token)
        self._url += self.TMF_URL
        self._headers = {"accept": "application/json"}

    def get_service_order(self, id: str) -> Optional[ServiceOrder]:
        response = requests.get(f"{self._url}/serviceOrdering/{self.API_VERSION}/serviceOrder/{id}",
                                headers=self._headers,
                                auth=self._auth)
        if response.status_code != requests.codes.ok:
            super().handle_response_not_ok(response)
        try:
            return ServiceOrder(**response.json())
        except:
            return None

    def list_service_orders(self) -> List[ServiceOrder]:
        response = requests.get(f"{self._url}/serviceOrdering/{self.API_VERSION}/serviceOrder",
                                headers=self._headers,
                                auth=self._auth)
        if response.status_code != requests.codes.ok:
            super().handle_response_not_ok(response)
        try:
            return [ServiceOrder(**service_order) for service_order in response.json()]
        except:
            return []

    def create_service_order(self, json: Any) -> Optional[ServiceOrder]:
        headers = copy.deepcopy(self._headers)
        headers["Content-Type"] = "application/json;charset=utf-8"
        response = requests.post(f"{self._url}/serviceOrdering/{self.API_VERSION}/serviceOrder",
                                headers=self._headers,
                                json=json,
                                auth=self._auth)
        if response.status_code != requests.codes.ok:
            super().handle_response_not_ok(response)
        try:
            return ServiceOrder(**response.json())
        except:
            return None

    def update_service_order(self, id: str, json: Any) -> Optional[ServiceOrder]:
        headers = copy.deepcopy(self._headers)
        headers["Content-Type"] = "application/json;charset=utf-8"
        response = requests.patch(f"{self._url}/serviceOrdering/{self.API_VERSION}/serviceOrder/{id}",
                                  headers=headers,
                                  json=json,
                                  auth=self._auth)
        if response.status_code != requests.codes.ok:
            super().handle_response_not_ok(response)
        try:
            return ServiceOrder(**response.json())
        except:
            return None

    def get_service_spec(self, id: str) -> Optional[ServiceSpec]:
        response = requests.get(f"{self._url}/serviceCatalogManagement/{self.API_VERSION}/serviceSpecification/{id}",
                                headers=self._headers,
                                auth=self._auth)
        if response.status_code != requests.codes.ok:
            super().handle_response_not_ok(response)
        try:
            return ServiceSpec(**response.json())
        except:
            return None

    def list_service_specs(self) -> List[ServiceSpec]:
        response = requests.get(f"{self._url}/serviceCatalogManagement/{self.API_VERSION}/serviceSpecification",
                                headers=self._headers,
                                auth=self._auth)
        if response.status_code != requests.codes.ok:
            super().handle_response_not_ok(response)
        try:
            return [ServiceSpec(**service_spec) for service_spec in response.json()]
        except:
            return []
        
    def update_service_spec(self, id: str, json: Any) -> Optional[ServiceSpec]:
        headers = copy.deepcopy(self._headers)
        headers["Content-Type"] = "application/json;charset=utf-8"
        response = requests.patch(f"{self._url}/serviceCatalogManagement/{self.API_VERSION}/serviceSpecification/{id}",
                                  headers=headers,
                                  json=json,
                                  auth=self._auth)
        if response.status_code != requests.codes.ok:
            super().handle_response_not_ok(response)
        try:
            return ServiceSpec(**response.json())
        except:
            return None

    def get_service_inventory(self, id: str) -> Optional[ServiceInventory]:
        response = requests.get(f"{self._url}/serviceInventory/{self.API_VERSION}/service/{id}",
                                headers=self._headers,
                                auth=self._auth)
        if response.status_code != requests.codes.ok:
            super().handle_response_not_ok(response)
        try:
            return ServiceInventory(**response.json())
        except:
            return None
