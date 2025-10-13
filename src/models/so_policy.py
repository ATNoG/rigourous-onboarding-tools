import xmltodict

from abc import ABC, abstractmethod
from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional

from models.service_spec import ServiceSpecCharacteristic, ServiceSpecCharacteristicValue, ServiceSpecCharacteristicValueAndAlias, ServiceSpecWithAction

class PolicyType(str, Enum):
    CHANNEL_PROTECTION = "Channel_Protection"
    FIREWALL = "Firewall"
    TELEMETRY = "Telemetry"
    SIEM = "Network_traffic_analysis"

    @classmethod
    def from_mspl(cls, mspl: str) -> Optional["PolicyType"]:
        doc = xmltodict.parse(mspl)
        try:
            name = doc["ITResourceOrchestration"]["ITResource"]["configuration"]["capability"]["Name"]
            return PolicyType(name)
        except:
            return None

class Policy(BaseModel, ABC):
    def to_service_spec(self, service_name: str) -> ServiceSpecWithAction:
        return ServiceSpecWithAction(
            name=service_name,
            service_spec_characteristic=[
                ServiceSpecCharacteristic(
                    name="CONFIG",
                    serviceSpecCharacteristicValue=[
                        ServiceSpecCharacteristicValue(
                            value=ServiceSpecCharacteristicValueAndAlias.from_string(str(self.__json__()))
                        )
                    ]
                )
            ]
        )
    
    @abstractmethod
    def get_type(self) -> PolicyType:
        pass
    
    @abstractmethod
    def __json__(self) -> dict:
        pass

class ChannelProtectionPolicy(Policy):
    local_address: Optional[str] = None
    remote_address: Optional[str] = None
    encryption_key_1: Optional[str] = Field(alias="enc_key_1", default=None)
    encryption_key_2: Optional[str] = Field(alias="enc_key_2", default=None)
    integrity_key_1: Optional[str] = Field(alias="int_key_1", default=None)
    integrity_key_2: Optional[str] = Field(alias="int_key_2", default=None)

    def to_service_spec(self, service_name: str="RIGOUROUS Channel Protection") -> ServiceSpecWithAction:
        return super().to_service_spec(service_name)
    
    def get_type(self) -> PolicyType:
        return PolicyType.CHANNEL_PROTECTION
    
    def __json__(self) -> dict:
        res = {}
        if self.local_address:
            res.update({"local_address": self.local_address})
        if self.remote_address:
            res.update({"remote_address": self.remote_address})
        if self.encryption_key_1:
            res.update({"enc_key_1": self.encryption_key_1})
        if self.encryption_key_2:
            res.update({"enc_key_2": self.encryption_key_2})
        if self.integrity_key_1:
            res.update({"int_key_1": self.integrity_key_1})
        if self.integrity_key_2:
            res.update({"int_key_2": self.integrity_key_2})
        return res
    
class FirewallPolicy(Policy):
    name: Optional[str] = None
    source_address: Optional[str] = Field(alias="srcAddr", default=None)
    destination_address: Optional[str] = Field(alias="dstAddr", default=None)
    action: Optional[str] = None

    def to_service_spec(self, service_name: str="RIGOUROUS Firewall") -> ServiceSpecWithAction:
        return super().to_service_spec(service_name)
    
    def get_type(self) -> PolicyType:
        return PolicyType.FIREWALL
    
    def __json__(self) -> dict:
        res = {}
        if self.name:
            res.update({"name": self.name})
        if self.source_address:
            res.update({"srcAddr": self.source_address})
        if self.destination_address:
            res.update({"dstAddr": self.destination_address})
        if self.action:
            res.update({"action": self.action})
        return res

class SiemPolicy(Policy):
    def to_service_spec(self, service_name: str="RIGOUROUS SIEM") -> ServiceSpecWithAction:
        return super().to_service_spec(service_name)
    
    def get_type(self) -> PolicyType:
        return PolicyType.SIEM
    
    def __json__(self) -> dict:
        return {}

class TelemetryConfiguration(BaseModel):
    domain_id: Optional[str] = Field(alias="domainID", default=None)
    flavor_id: Optional[str] = Field(alias="flavorID", default=None)
    exporter_endpoint: Optional[str] = Field(alias="exporterEndpoint", default=None)

    def __json__(self) -> dict:
        res = {}
        if self.domain_id:
            res.update({"domainID": self.domain_id})
        if self.flavor_id:
            res.update({"flavorID": self.flavor_id})
        if self.exporter_endpoint:
            res.update({"exporterEndpoint": self.exporter_endpoint})
        return res

class TelemetryPolicy(Policy):
    deploy: Optional[str] = None
    configuration: Optional[TelemetryConfiguration] = None

    def to_service_spec(self, service_name: str="RIGOUROUS Telemetry") -> ServiceSpecWithAction:
        return super().to_service_spec(service_name)
    
    def get_type(self) -> PolicyType:
        return PolicyType.TELEMETRY
    
    def __json__(self) -> dict:
        res = {}
        if self.deploy:
            res.update({"deploy": self.deploy})
        if self.configuration:
            res.update({"configuration": self.configuration.__json__()})
        return res
