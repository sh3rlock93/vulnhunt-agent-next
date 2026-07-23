"""Independent PoC reproduction and deterministic oracle evaluation."""

from .oracles import evaluate_oracle
from .service import ReproductionOutcome, ReproductionStatus, ReproducerService
from .planning import (
    CapabilityAwareExperimentPlanner,
    ExperimentPlan,
    ExperimentPlanner,
    ExperimentPlanStatus,
    ExperimentStrategy,
    validate_compiled_experiment,
)
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
    "CapabilityAwareExperimentPlanner",
    "ExperimentPlan",
    "ExperimentPlanner",
    "ExperimentPlanStatus",
    "ExperimentStrategy",
    "LLMVariantCompiler",
    "ReproductionVariantExecutor",
    "VariantCompiler",
    "VariantExecutionPatch",
    "VariantExecutionResult",
    "compile_variant_spec",
    "validate_compiled_experiment",
    "evaluate_oracle",
]
