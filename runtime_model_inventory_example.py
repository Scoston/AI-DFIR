"""
Add this to the already-running inference worker after the model is loaded.
It inventories the live Python object, including registered hooks and PEFT state.
"""
import json
from pathlib import Path
from runtime_inventory import capture_model_runtime

inventory = capture_model_runtime(
    model,
    model_ref="Qwen/Qwen3.8-27B",
    revision="<deployed revision>",
)
Path("/var/log/ai-dfir/model_runtime_inventory.json").write_text(
    json.dumps(inventory, indent=2, sort_keys=True, default=str)
)
