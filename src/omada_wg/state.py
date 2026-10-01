from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class EnrollmentState:
    server_id: str
    client_id: str
    client_name: str
    tunnel_name: str


class StateStore:
    def __init__(self, path: Path):
        self.path = path

    def load(self) -> EnrollmentState | None:
        if not self.path.exists():
            return None
        return EnrollmentState(**json.loads(self.path.read_text(encoding="utf-8")))

    def save(self, state: EnrollmentState) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_text(json.dumps(asdict(state), indent=2) + "\n", encoding="utf-8")
        os.chmod(temp, 0o600)
        temp.replace(self.path)

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
