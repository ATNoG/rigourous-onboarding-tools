import asyncio
import logging
import time

from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, List, Optional

from apis.security_orchestrator import SecurityOrchestrator
from connectors.tmf_api_connector import TmfApiConnector
from models.mtd_action import MtdAction
from models.risk_specification import RiskSpecification
from models.service_order import ServiceOrder
from models.service_spec import ServiceSpec, ServiceSpecType, ServiceSpecWithAction
from models.so_policy import ChannelProtectionPolicy, FirewallPolicy, Policy, PolicyType, SiemPolicy, TelemetryPolicy
from settings import settings

description = """
The Onboarding Tools is capable of performing Moving Target Defense operations on KNF-based network services; receive and enforce policies from the Security Orchestrator; and receive and update the risk score of services based on a Risk Specification provided by the Threat Risk Assessor and Privacy Quantifier from the RIGOUROUS project.
"""

metadata_tags = [
    {
        "name": "Services",
        "description": "Service Specification updates in OpenSlice."
    },
    {
        "name": "Service Orders",
        "description": "Lists all active Service Orders in OpenSlice."
    },
    {
        "name": "Service Specifications",
        "description": "Lists all Service Specifications in OpenSlice."
    },
    {
        "name": "Security Orchestrator Policies",
        "description": "Handles policies from Security Orchestrator."
    },
    {
        "name": "Risk Specification",
        "description": "Handles TRA risk score and PQ privacy score."
    }
]

logging_level = {
    "ERROR": logging.ERROR,
    "WARN": logging.WARN,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG
}
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging_level.get(settings.log_level.upper()), format='%(asctime)s %(levelname)s: %(message)s')

async def handle_mtd_actions(openslice_host: str):
    mtd_actions: Dict[str, List[MtdAction]] = {}
    tmf_api_connector = TmfApiConnector(f"http://{openslice_host}")
    while True:
        start_time = time.monotonic()
        _update_mtd_actions_from_service_orders(mtd_actions, tmf_api_connector)
        _update_service_orders(mtd_actions, tmf_api_connector)
        elapsed_time = time.monotonic() - start_time
        logging.debug(f"Elapsed time: {elapsed_time}")
        await asyncio.sleep(max(60.0 - elapsed_time, 1.0))

def _update_mtd_actions_from_service_orders(mtd_actions: Dict[str, List[MtdAction]], tmf_api_connector: TmfApiConnector):
    active_service_order_ids = [service_order.id for service_order in tmf_api_connector.list_active_service_orders() if service_order.id]
    for service_order_id in active_service_order_ids:
        service_order = tmf_api_connector.get_service_order(service_order_id)
        if service_order:
            list_of_mtd_actions = MtdAction.from_service_order(service_order, mtd_actions.get(service_order_id, []))
            if list_of_mtd_actions:
                mtd_actions[service_order_id] = list_of_mtd_actions
    logging.debug(f"Scheduled MTD actions: {mtd_actions}")

def _update_service_orders(mtd_actions: Dict[str, List[MtdAction]], tmf_api_connector: TmfApiConnector):
    for service_order_id, value in mtd_actions.items():
        service_order_characteristics = []
        for mtd_action in value:
            service_characteristic = mtd_action.decrement_time_and_get_service_spec_characteristic_if_zero()
            if service_characteristic:
                service_order_characteristics.append(service_characteristic)
        if service_order_characteristics:
            tmf_api_connector.update_service_order_and_inventories(service_order_id, ServiceSpec(serviceSpecCharacteristic=service_order_characteristics))
            logging.debug(f"Updating Service Order {service_order_id} with characteristics {service_order_characteristics}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(handle_mtd_actions(settings.openslice_host))
    yield
    task.cancel()
    asyncio.gather(task, return_exceptions=True)

app = FastAPI(
    lifespan=lifespan,
    title="Onboarding Tools",
    description=description,
    summary="Onboard and configure KNF-based network services.",
    version=f"{settings.version}.{settings.sub_version}",
    openapi_tags=metadata_tags
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

service_orders_waiting_policies = {
    PolicyType.CHANNEL_PROTECTION: asyncio.Queue(),
    PolicyType.FIREWALL: asyncio.Queue(),
    PolicyType.SIEM: asyncio.Queue(),
    PolicyType.TELEMETRY: asyncio.Queue()
}

@app.get(f"/v{settings.version}/serviceOrders", tags=["Service Orders"], responses={
    status.HTTP_503_SERVICE_UNAVAILABLE: {"description": "Could not get Service Orders from OpenSlice"}
})
def list_service_orders() -> List[str]:
    return [service_order.id for service_order in TmfApiConnector(f"http://{settings.openslice_host}").list_active_service_orders() if service_order.id]

@app.get(f"/v{settings.version}/serviceSpecs", tags=["Service Specifications"], responses={
    status.HTTP_503_SERVICE_UNAVAILABLE: {"description": "Could not get Service Specifications from OpenSlice"}
})
def list_service_specs() -> List[str]:
    return [service_spec.name for service_spec in TmfApiConnector(f"http://{settings.openslice_host}").list_service_specs() if service_spec.name]

@app.post(f"/v{settings.version}" + "/osl/{service_order_id}", tags=["Services"], responses={
})
async def handle_openslice_service_order(service_order_id: str, mspl: Request) -> str:
    mspl_body = await mspl.body()
    policy_type = PolicyType.from_mspl(mspl_body.decode("utf-8"))
    if policy_type:
        security_orchestrator = SecurityOrchestrator(f"http://{settings.so_host}")
        if security_orchestrator.send_mspl(mspl_body):
            await service_orders_waiting_policies[policy_type].put(service_order_id)
            return service_order_id
    return ""

@app.post(f"/v{settings.version}/risk", tags=["Risk Specification"], responses={
    status.HTTP_400_BAD_REQUEST: {"description": "Missing attribute 'cpe' in Risk Specification"},
    status.HTTP_503_SERVICE_UNAVAILABLE: {"description": "Could not reach OpenSlice"}
})
async def handle_risk_specification(risk_specification: RiskSpecification) -> List[ServiceOrder]:
    if not risk_specification.cpe:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing attribute 'cpe' in Risk Specification"
        )
    try:
        service_orders = []
        tmf_api_connector = TmfApiConnector(f"http://{settings.openslice_host}")
        service_spec_ids = [service_spec.id for service_spec in tmf_api_connector.list_service_specs() if service_spec.type == ServiceSpecType.CFSS]
        logging.debug(f"Service Specs: {service_spec_ids}")
        for service_spec_id in service_spec_ids:
            service_spec = tmf_api_connector.get_service_spec(service_spec_id)
            if service_spec:
                if service_spec.update_risk(risk_specification):
                    service_orders.extend(tmf_api_connector.update_service_orders_and_inventories_from_service_spec(service_spec))
        return service_orders
    except HTTPException:
        return []

@app.post(f"/v{settings.version}/so", tags=["Security Orchestrator Policies"], responses={
    status.HTTP_400_BAD_REQUEST: {"description": "Missing service 'name' or 'id' from provided Service Specification"},
    status.HTTP_503_SERVICE_UNAVAILABLE: {"description": "Could not reach OpenSlice"}
})
async def handle_nmtd_policy(service_spec: ServiceSpecWithAction) -> List[ServiceOrder]:
    if not service_spec.name and not service_spec.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing service 'name' or 'id' from provided Service Specification"
        )
    try:
        tmf_api_connector = TmfApiConnector(f"http://{settings.openslice_host}")
        return tmf_api_connector.update_service_orders_and_inventories_from_service_spec(service_spec)
    except HTTPException:
        return []

@app.post(f"/v{settings.version}/telemetry", tags=["Security Orchestrator Policies"], responses={
    status.HTTP_400_BAD_REQUEST: {"description": "Missing service 'name' or 'id' from provided Service Specification"},
    status.HTTP_503_SERVICE_UNAVAILABLE: {"description": "Could not reach OpenSlice"}
})
async def handle_telemetry_policy(telemetry_configuration: TelemetryPolicy) -> Optional[ServiceOrder]:
    return await _handle_so_policy(telemetry_configuration)

@app.post(f"/v{settings.version}/firewall", tags=["Security Orchestrator Policies"], responses={
    status.HTTP_400_BAD_REQUEST: {"description": "Missing service 'name' or 'id' from provided Service Specification"},
    status.HTTP_503_SERVICE_UNAVAILABLE: {"description": "Could not reach OpenSlice"}
})
async def handle_firewall_policy(firewall_configuration: FirewallPolicy) -> Optional[ServiceOrder]:
    return await _handle_so_policy(firewall_configuration)

@app.post(f"/v{settings.version}/siem", tags=["Security Orchestrator Policies"], responses={
    status.HTTP_400_BAD_REQUEST: {"description": "Missing service 'name' or 'id' from provided Service Specification"},
    status.HTTP_503_SERVICE_UNAVAILABLE: {"description": "Could not reach OpenSlice"}
})
async def handle_siem_policy(siem_configuration: SiemPolicy) -> Optional[ServiceOrder]:
    return await _handle_so_policy(siem_configuration)

@app.post(f"/v{settings.version}/channelProtection", tags=["Security Orchestrator Policies"], responses={
    status.HTTP_400_BAD_REQUEST: {"description": "Missing service 'name' or 'id' from provided Service Specification"},
    status.HTTP_503_SERVICE_UNAVAILABLE: {"description": "Could not reach OpenSlice"}
})
async def handle_channel_protection_policy(channel_protection_configuration: ChannelProtectionPolicy) -> Optional[ServiceOrder]:
    return await _handle_so_policy(channel_protection_configuration)

async def _handle_so_policy(policy: Policy) -> Optional[ServiceOrder]:
    service_spec = policy.to_service_spec()
    if not service_orders_waiting_policies[policy.get_type()].empty():
        service_order_id = await service_orders_waiting_policies[policy.get_type()].get()
        tmf_api_connector = TmfApiConnector(f"http://{settings.openslice_host}")
        return tmf_api_connector.update_service_order_and_inventories(service_order_id, service_spec)
    return None

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app)
