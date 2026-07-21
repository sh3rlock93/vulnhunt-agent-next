"""Independent PoC reproduction and deterministic oracle evaluation."""

from .oracles import evaluate_oracle
from .service import ReproductionOutcome, ReproductionStatus, ReproducerService
from .variants import (
    LLMVariantCompiler,
    ReproductionVariantExecutor,
    VariantCompiler,
    VariantExecutionPatch,
    VariantExecutionResult,
    compile_variant_spec,
)

__all__ = [
    "ReproductionOutcome",
    "ReproductionStatus",
    "ReproducerService",
    "LLMVariantCompiler",
    "ReproductionVariantExecutor",
    "VariantCompiler",
    "VariantExecutionPatch",
    "VariantExecutionResult",
    "compile_variant_spec",
    "evaluate_oracle",
]
