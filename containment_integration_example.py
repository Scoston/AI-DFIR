"""
Production integration example.

Attach this at BOTH model request dispatch and tool execution. A tool gate alone
is insufficient if there are other mutating paths.
"""
from containment_guard import ContainmentGuard

guard = ContainmentGuard(
    control_file="/run/ai-dfir/containment.json",
    public_key="/etc/ai-dfir/containment_ed25519.pub.pem",
    fail_closed=True,
)

# Before local model inference:
guard.allow_inference()

# Before any tool call:
# mutating must come from an approved static tool classification, not from the model.
guard.authorize_tool("lookup_ticket", mutating=False)

# For routing:
backend = guard.routing_target(default_backend="http://suspect-worker:8000")
