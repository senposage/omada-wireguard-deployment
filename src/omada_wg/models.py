from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class WireGuardPeer:
    id: str
    name: str
    interface_ip: str
    public_key: str
    private_key: str
    pre_shared_key: str = ""
    allowed_addresses: tuple[str, ...] = ()

    @classmethod
    def from_api(cls, value: dict[str, Any]) -> "WireGuardPeer":
        return cls(
            id=str(value.get("id", "")),
            name=str(value.get("name", "")),
            interface_ip=str(value.get("interfaceIp", "")),
            public_key=str(value.get("publicKey", "")),
            private_key=str(value.get("privateKey", "")),
            pre_shared_key=str(value.get("preSharedKey", "")),
            allowed_addresses=tuple(value.get("allowedAddress") or ()),
        )


@dataclass(frozen=True)
class WireGuardServer:
    id: str
    name: str
    public_key: str
    service_port: int
    keep_alive: int
    clients: tuple[WireGuardPeer, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_api(cls, value: dict[str, Any]) -> "WireGuardServer":
        return cls(
            id=str(value.get("id", "")),
            name=str(value.get("name", "")),
            public_key=str(value.get("publicKey", "")),
            service_port=int(value.get("servicePort", 51820)),
            keep_alive=int(value.get("keepAlive", 25)),
            clients=tuple(WireGuardPeer.from_api(x) for x in value.get("clients") or ()),
            raw=value,
        )

