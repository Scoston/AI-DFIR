"""
Importable containment guard for an inference/tool worker.

The guard verifies the signed control each time its cached file state changes.
Integration points:
  guard.allow_inference()
  guard.authorize_tool(name, mutating=True)
  guard.routing_target(default_backend)

Fail-closed behavior is configurable for invalid controls.
"""
from __future__ import annotations
import json, os, threading
from pathlib import Path
from fleet_crypto import verify_envelope


class ContainmentDenied(RuntimeError):
    pass


class ContainmentGuard:
    def __init__(self, control_file, public_key, fail_closed=True):
        self.control_file=Path(control_file)
        self.public_key=Path(public_key)
        self.fail_closed=fail_closed
        self._lock=threading.Lock()
        self._signature=None
        self._payload={"mode":"released","read_only_tools":[]}

    def _refresh(self):
        try:
            st=self.control_file.stat()
            sig=(st.st_ino,st.st_size,st.st_mtime_ns)
        except FileNotFoundError:
            self._payload={"mode":"released","read_only_tools":[]}
            self._signature=None
            return
        if sig==self._signature:
            return
        with self._lock:
            if sig==self._signature:return
            try:
                env=json.loads(self.control_file.read_text(encoding="utf-8"))
                payload=verify_envelope(self.public_key,env)
                if payload.get("schema")!="ai-dfir/containment-control/v0.6":
                    raise ValueError("wrong containment-control schema")
                self._payload=payload
                self._signature=sig
            except Exception:
                if self.fail_closed:
                    self._payload={"mode":"quarantine","read_only_tools":[],
                                   "reason":"containment control failed signature validation"}
                    self._signature=sig
                else:
                    raise

    @property
    def state(self):
        self._refresh()
        return dict(self._payload)

    def allow_inference(self):
        self._refresh()
        mode=self._payload.get("mode","released")
        if mode in ("quarantine","failover"):
            raise ContainmentDenied(
                f"local inference denied by containment mode={mode}; incident={self._payload.get('incident_id')}"
            )
        return True

    def authorize_tool(self, tool_name, mutating=True):
        self._refresh()
        mode=self._payload.get("mode","released")
        if mode in ("quarantine","failover","freeze-tools"):
            raise ContainmentDenied(f"tool denied: containment mode={mode}")
        if mode=="read-only":
            allowed=set(self._payload.get("read_only_tools") or [])
            if mutating or tool_name not in allowed:
                raise ContainmentDenied(f"tool denied by read-only containment: {tool_name}")
        return True

    def routing_target(self, default_backend):
        self._refresh()
        if self._payload.get("mode")=="failover":
            target=self._payload.get("approved_backend")
            if not target:
                raise ContainmentDenied("failover mode lacks approved backend")
            return target
        return default_backend
