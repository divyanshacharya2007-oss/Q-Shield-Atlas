"""QAOA cross-check for small weekly asset-selection subproblems.

The result is an empirical measured cross-check only. It makes no claim of
quantum advantage and never interprets simulator output as such.
"""

from __future__ import annotations

import importlib.util
import os
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np
from scipy.optimize import minimize

MAX_BINARY_VARIABLES = 16
LABEL = "Measured cross-check only, no claim of quantum advantage."


@dataclass(frozen=True)
class WeeklyQUBO:
    """Binary QUBO plus source selection and feasibility metadata."""

    asset_ids: tuple[str, ...]
    variable_names: tuple[str, ...]
    coefficients: Mapping[tuple[int, int], float]
    capacity: int
    dependencies: Mapping[str, tuple[str, ...]]
    risk_weights: tuple[float, ...]
    penalty: float
    offset: float

    @property
    def n_variables(self) -> int:
        return len(self.variable_names)

    def energy(self, bitstring: str) -> float:
        bits = decode_bitstring(bitstring, self.n_variables)
        return float(self.offset +
            sum(coefficient * bits[left] * bits[right]
                for (left, right), coefficient in self.coefficients.items())
        )

    def decode(self, bitstring: str) -> dict[str, Any]:
        bits = decode_bitstring(bitstring, self.n_variables)
        selected = tuple(
            asset_id for index, asset_id in enumerate(self.asset_ids) if bits[index]
        )
        return {
            "bitstring": bitstring,
            "selected_asset_ids": selected,
            "objective": self.objective(selected),
            "feasible": self.is_feasible(selected),
            "bits": bits,
        }

    def is_feasible(self, selected_asset_ids: Sequence[str]) -> bool:
        selected = set(selected_asset_ids)
        if not selected.issubset(self.asset_ids) or len(selected) > self.capacity:
            return False
        return all(
            dependency in selected
            for asset_id in selected
            for dependency in self.dependencies.get(asset_id, ())
        )

    def objective(self, selected_asset_ids: Sequence[str]) -> float:
        weight_by_id = dict(zip(self.asset_ids, self.risk_weights, strict=True))
        return float(sum(weight_by_id[asset_id] for asset_id in set(selected_asset_ids)))

    def exact_optimum(self) -> tuple[float, tuple[str, ...], tuple[str, ...]]:
        best_score = float("-inf")
        optimal_selections: list[tuple[str, ...]] = []
        for mask in range(1 << len(self.asset_ids)):
            selected = tuple(
                asset_id for index, asset_id in enumerate(self.asset_ids)
                if mask & (1 << index)
            )
            if not self.is_feasible(selected):
                continue
            score = self.objective(selected)
            if score > best_score:
                best_score = score
                optimal_selections = [selected]
            elif score == best_score:
                optimal_selections.append(selected)

        optimal_strings = tuple(
            _canonical_full_bitstring(self, selection) for selection in optimal_selections
        )
        return best_score, optimal_selections[0], optimal_strings


@dataclass(frozen=True)
class QAOAResult:
    label: str
    backend: str
    backend_status: str
    selected_asset_ids: tuple[str, ...]
    selected_bitstring: str
    selected_objective: float
    exact_optimum: float
    exact_optimal_asset_ids: tuple[str, ...]
    approximation_ratio: float
    optimal_bitstring_probability: float
    feasible_counts: Mapping[str, int]
    discarded_infeasible_counts: int
    job_ids: tuple[str, ...]
    depth_results: tuple[Mapping[str, Any], ...]


def decode_bitstring(bitstring: str, n_variables: int) -> tuple[int, ...]:
    """Decode SDK measurement strings; qubit 0 is represented by the rightmost bit."""
    if len(bitstring) != n_variables or any(bit not in "01" for bit in bitstring):
        raise ValueError(f"bitstring must contain exactly {n_variables} binary digits")
    return tuple(int(bitstring[-1 - index]) for index in range(n_variables))


def formulate_weekly_qubo(
    assets: Sequence[Mapping[str, Any]],
    *,
    capacity: int,
    penalty: float | None = None,
) -> WeeklyQUBO:
    """Build a risk-maximizing QUBO with capacity and dependency penalties."""
    if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 0:
        raise ValueError("capacity must be a non-negative integer")
    asset_ids = tuple(str(asset.get("asset_id", "")).strip() for asset in assets)
    if not asset_ids or any(not asset_id for asset_id in asset_ids):
        raise ValueError("assets must have non-empty asset_id values")
    if len(set(asset_ids)) != len(asset_ids):
        raise ValueError("asset_id values must be unique")

    risk_weights = []
    dependencies: dict[str, tuple[str, ...]] = {}
    asset_id_set = set(asset_ids)
    for asset_id, asset in zip(asset_ids, assets, strict=True):
        try:
            risk_weight = float(asset["risk_weight"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f"asset {asset_id} needs a numeric risk_weight") from error
        if not np.isfinite(risk_weight) or risk_weight < 0:
            raise ValueError(f"risk_weight for {asset_id} must be finite and non-negative")
        raw_dependencies = asset.get("dependencies", ()) or ()
        dependency_ids = tuple(str(dependency) for dependency in raw_dependencies)
        if len(set(dependency_ids)) != len(dependency_ids):
            raise ValueError(f"asset {asset_id} has duplicate dependencies")
        unknown = set(dependency_ids) - asset_id_set
        if unknown:
            raise ValueError(f"asset {asset_id} has unknown dependencies: {sorted(unknown)}")
        dependencies[asset_id] = dependency_ids
        risk_weights.append(risk_weight)

    if penalty is None:
        penalty = sum(risk_weights) + 1.0
    if not np.isfinite(penalty) or penalty <= sum(risk_weights):
        raise ValueError("penalty must be finite and greater than total risk weight")

    slack_width = 0
    if capacity < len(asset_ids):
        slack_width = max(1, int(np.ceil(np.log2(capacity + 1))))
    variable_names = [*asset_ids]
    variable_names.extend(f"capacity_slack_{index}" for index in range(slack_width))
    if len(variable_names) > MAX_BINARY_VARIABLES:
        raise ValueError(
            f"weekly QUBO has {len(variable_names)} binary variables including capacity slack; "
            f"limit is {MAX_BINARY_VARIABLES}"
        )

    coefficients: dict[tuple[int, int], float] = {}
    offset = 0.0

    def add(left: int, right: int, value: float) -> None:
        key = (left, right) if left <= right else (right, left)
        coefficients[key] = coefficients.get(key, 0.0) + float(value)

    for index, weight in enumerate(risk_weights):
        add(index, index, -weight)

    if slack_width:
        offset += penalty * capacity * capacity
        capacity_terms = [(index, 1) for index in range(len(asset_ids))]
        capacity_terms.extend(
            (len(asset_ids) + index, 1 << index) for index in range(slack_width)
        )
        for index, weight in capacity_terms:
            add(index, index, penalty * (weight * weight - 2 * capacity * weight))
        for term_index, (left, left_weight) in enumerate(capacity_terms):
            for right, right_weight in capacity_terms[term_index + 1 :]:
                add(left, right, 2 * penalty * left_weight * right_weight)

    asset_index_by_id = {asset_id: index for index, asset_id in enumerate(asset_ids)}
    for asset_id, required_ids in dependencies.items():
        child_index = asset_index_by_id[asset_id]
        for dependency_id in required_ids:
            parent_index = asset_index_by_id[dependency_id]
            add(child_index, child_index, penalty)
            add(child_index, parent_index, -penalty)

    return WeeklyQUBO(
        asset_ids=asset_ids,
        variable_names=tuple(variable_names),
        coefficients={key: value for key, value in coefficients.items() if value != 0},
        capacity=capacity,
        dependencies=dependencies,
        risk_weights=tuple(risk_weights),
        penalty=float(penalty),
        offset=offset,
    )


def _canonical_full_bitstring(problem: WeeklyQUBO, selected: Sequence[str]) -> str:
    selected_set = set(selected)
    bits = [int(asset_id in selected_set) for asset_id in problem.asset_ids]
    slack = problem.capacity - len(selected_set)
    for index in range(problem.n_variables - len(problem.asset_ids)):
        bits.append((slack >> index) & 1)
    return "".join(str(bit) for bit in reversed(bits))


def _local_statevector_counts(
    problem: WeeklyQUBO,
    *,
    layers: int,
    shots: int,
    seed: int,
    max_iterations: int,
) -> tuple[dict[str, int], Mapping[str, Any]]:
    n_qubits = problem.n_variables
    dimension = 1 << n_qubits
    basis_indices = np.arange(dimension, dtype=np.uint32)
    energies = np.fromiter(
        (problem.energy(format(index, f"0{n_qubits}b")) for index in basis_indices),
        dtype=np.float64,
        count=dimension,
    )

    def state_for(parameters: np.ndarray) -> np.ndarray:
        state = np.full(dimension, 1 / np.sqrt(dimension), dtype=np.complex128)
        for layer in range(layers):
            gamma = parameters[2 * layer]
            beta = parameters[2 * layer + 1]
            state *= np.exp(-1j * gamma * energies)
            cosine, sine = np.cos(beta), -1j * np.sin(beta)
            for qubit in range(n_qubits):
                zero_indices = basis_indices[(basis_indices & (1 << qubit)) == 0]
                one_indices = zero_indices | (1 << qubit)
                zero_values = state[zero_indices].copy()
                one_values = state[one_indices].copy()
                state[zero_indices] = cosine * zero_values + sine * one_values
                state[one_indices] = cosine * one_values + sine * zero_values
        return state

    def expected_energy(parameters: np.ndarray) -> float:
        probabilities = np.abs(state_for(parameters)) ** 2
        return float(np.dot(probabilities, energies))

    rng = np.random.default_rng(seed + layers)
    initial_parameters = rng.uniform(0.0, np.pi, size=2 * layers)
    optimization = minimize(
        expected_energy,
        initial_parameters,
        method="COBYLA",
        options={
            "maxiter": max(max_iterations, len(initial_parameters) + 2),
            "rhobeg": 0.5,
            "tol": 1e-3,
        },
    )
    probabilities = np.abs(state_for(optimization.x)) ** 2
    sampled = rng.multinomial(shots, probabilities / probabilities.sum())
    counts = {
        format(index, f"0{n_qubits}b"): int(count)
        for index, count in enumerate(sampled)
        if count
    }
    return counts, {
        "optimizer": "COBYLA",
        "optimizer_success": bool(optimization.success),
        "optimizer_message": str(optimization.message),
        "expected_energy": float(optimization.fun),
    }


def _qcloud_counts(
    problem: WeeklyQUBO,
    *,
    layers: int,
    shots: int,
    max_iterations: int,
    device_name: str,
) -> tuple[dict[str, int], str | None]:
    if not os.environ.get("API_KEY") or importlib.util.find_spec("qpiai_quantum") is None:
        raise RuntimeError("QCloud credentials or qpiai_quantum SDK are unavailable")

    class _Problem:
        n_qubits = problem.n_variables

        def get_hamiltonian_terms(self) -> list[tuple[list[tuple[int, str]], float]]:
            terms: list[tuple[list[tuple[int, str]], float]] = [([], problem.offset)]
            for (left, right), coefficient in problem.coefficients.items():
                if left == right:
                    terms.extend([([], coefficient / 2), ([(left, "Z")], -coefficient / 2)])
                else:
                    terms.extend(
                        [
                            ([], coefficient / 4),
                            ([(left, "Z")], -coefficient / 4),
                            ([(right, "Z")], -coefficient / 4),
                            ([(left, "Z"), (right, "Z")], coefficient / 4),
                        ]
                    )
            return terms

        def decode_solution(self, bitstring: str) -> dict[str, int]:
            return {name: bit for name, bit in zip(problem.variable_names, decode_bitstring(bitstring, problem.n_variables), strict=True)}

        def validate_solution(self, solution: dict[str, int]) -> tuple[bool, str]:
            selected = [asset_id for asset_id in problem.asset_ids if solution.get(asset_id)]
            feasible = problem.is_feasible(selected)
            return feasible, "feasible" if feasible else "capacity or dependency violation"

        def compute_solution_quality(self, solution: dict[str, int]) -> dict[str, float]:
            selected = [asset_id for asset_id in problem.asset_ids if solution.get(asset_id)]
            return {"risk_weight": problem.objective(selected)}

    from qpiai_quantum.algorithms.opt.solvers.qaoa import QAOASolver

    result = QAOASolver(
        problem=_Problem(),
        layers=layers,
        optimizer="COBYLA",
        max_iterations=max_iterations,
        verbose=False,
    ).run(
        shots=shots,
        need_statevector=False,
        device_name=device_name,
        experiment_name="Q-Shield Atlas weekly cross-check",
    )
    job_id = result.metadata.get("job_id") if isinstance(result.metadata, Mapping) else None
    return dict(result.counts or {}), str(job_id) if job_id else None


def cross_check_weekly_wave(
    assets: Sequence[Mapping[str, Any]],
    *,
    capacity: int,
    shots: int = 1024,
    seed: int = 7,
    max_iterations: int = 60,
    penalty: float | None = None,
    prefer_qcloud: bool = True,
    device_name: str = "QpiAI-QSV-Simulator",
    sampler: Callable[..., tuple[Mapping[str, int], str | None]] | None = None,
) -> QAOAResult:
    """Run p=1,2,3 QAOA; retain feasible samples and compare to exact optimum."""
    if isinstance(shots, bool) or not isinstance(shots, int) or shots < 1:
        raise ValueError("shots must be a positive integer")
    if isinstance(max_iterations, bool) or not isinstance(max_iterations, int) or max_iterations < 1:
        raise ValueError("max_iterations must be a positive integer")

    problem = formulate_weekly_qubo(assets, capacity=capacity, penalty=penalty)
    exact_score, exact_assets, optimal_bitstrings = problem.exact_optimum()
    aggregate_counts: Counter[str] = Counter()
    depth_results = []
    job_ids = []
    actual_backends: set[str] = set()
    backend = "local-statevector" if not prefer_qcloud else "qcloud-simulator"
    backend_status = "MEASURED"
    used_qcloud = False

    for layers in (1, 2, 3):
        metadata = None
        if sampler is not None:
            counts, job_id = sampler(
                problem=problem,
                layers=layers,
                shots=shots,
                seed=seed,
                max_iterations=max_iterations,
            )
            run_backend = "injected-sampler"
        elif prefer_qcloud:
            try:
                counts, job_id = _qcloud_counts(
                    problem,
                    layers=layers,
                    shots=shots,
                    max_iterations=max_iterations,
                    device_name=device_name,
                )
                run_backend = "qcloud-simulator"
                used_qcloud = True
            except Exception:
                counts, metadata = _local_statevector_counts(
                    problem,
                    layers=layers,
                    shots=shots,
                    seed=seed,
                    max_iterations=max_iterations,
                )
                job_id = None
                run_backend = "local-statevector-fallback"
                backend_status = "FALLBACK_OFFLINE_OR_UNAVAILABLE"
        else:
            counts, metadata = _local_statevector_counts(
                problem,
                layers=layers,
                shots=shots,
                seed=seed,
                max_iterations=max_iterations,
            )
            job_id = None
            run_backend = "local-statevector"

        clean_counts = {}
        feasible_total = 0
        for bitstring, count in counts.items():
            if isinstance(count, bool) or int(count) < 0:
                raise ValueError("sample counts must be non-negative integers")
            count = int(count)
            decoded = problem.decode(bitstring)
            if decoded["feasible"] and count:
                clean_counts[bitstring] = clean_counts.get(bitstring, 0) + count
                feasible_total += count
            aggregate_counts[bitstring] += count
        depth_results.append(
            {
                "layers": layers,
                "backend": run_backend,
                "feasible_shots": feasible_total,
                "discarded_infeasible_shots": sum(map(int, counts.values())) - feasible_total,
                "feasible_counts": clean_counts,
                "optimizer": metadata,
            }
        )
        actual_backends.add(run_backend)
        if job_id:
            job_ids.append(job_id)

    feasible_counts: Counter[str] = Counter()
    total_samples = 0
    discarded_samples = 0
    for bitstring, count in aggregate_counts.items():
        decoded = problem.decode(bitstring)
        total_samples += count
        if decoded["feasible"]:
            feasible_counts[bitstring] += count
        else:
            discarded_samples += count
    if not feasible_counts:
        raise RuntimeError("QAOA produced no feasible samples at p=1, 2, or 3")

    best_bitstring = min(
        feasible_counts,
        key=lambda bitstring: (-problem.objective(problem.decode(bitstring)["selected_asset_ids"]), bitstring),
    )
    best_decoded = problem.decode(best_bitstring)
    selected_score = float(best_decoded["objective"])
    approximation_ratio = 1.0 if exact_score == 0 else selected_score / exact_score
    optimal_count = sum(feasible_counts[bitstring] for bitstring in optimal_bitstrings)
    probability = optimal_count / total_samples if total_samples else 0.0
    if used_qcloud:
        backend_status = "MEASURED_QCLOUD"
    elif sampler is not None:
        backend_status = "MEASURED_INJECTED_SAMPLER"
    elif prefer_qcloud:
        backend = "local-statevector-fallback"
    if len(actual_backends) > 1:
        backend = "mixed-backends"

    return QAOAResult(
        label=LABEL,
        backend=backend,
        backend_status=backend_status,
        selected_asset_ids=tuple(best_decoded["selected_asset_ids"]),
        selected_bitstring=best_bitstring,
        selected_objective=selected_score,
        exact_optimum=exact_score,
        exact_optimal_asset_ids=tuple(exact_assets),
        approximation_ratio=approximation_ratio,
        optimal_bitstring_probability=probability,
        feasible_counts=dict(feasible_counts),
        discarded_infeasible_counts=discarded_samples,
        job_ids=tuple(job_ids),
        depth_results=tuple(depth_results),
    )