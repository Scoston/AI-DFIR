"""
Architecture registry for model-agnostic AI-DFIR support.

Qwen3.8 is the first specialized adapter. Generic models fall back to a
ModuleList-based layer-stack detector. The adapter reports block labels for
forensic visualization; it does not alter model execution.
"""
import torch


class GenericAdapter:
    name="generic"
    def find_layers(self,model,expected=None):
        candidates=[]
        for name,m in model.named_modules():
            if isinstance(m,torch.nn.ModuleList) and (expected is None or len(m)==expected):
                candidates.append((name,m))
        if not candidates: raise RuntimeError("No candidate layer stack")
        candidates.sort(key=lambda x:("layers" in x[0].lower(),len(x[1])),reverse=True)
        return candidates[0]
    def block_label(self,index,module):
        return module.__class__.__name__


class Qwen38Adapter(GenericAdapter):
    name="qwen3.8"
    def block_label(self,index,module):
        # Official Qwen3.8 language stack: three Gated DeltaNet layers followed
        # by one full-attention layer, repeated. Report pattern without relying
        # on private implementation class names.
        return "full_attention" if index % 4 == 3 else "gated_deltanet"


REGISTRY={"qwen3.8":Qwen38Adapter(),"generic":GenericAdapter()}


def choose_adapter(model_ref=None):
    s=(model_ref or "").lower()
    if "qwen3.8" in s or "qwen3_8" in s:return REGISTRY["qwen3.8"]
    return REGISTRY["generic"]
