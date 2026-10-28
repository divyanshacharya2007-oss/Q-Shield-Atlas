"""MILP-based scheduling of post-quantum migration work."""

from __future__ import annotations

import math
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from qpiai_opt.opt_modeller import Binary, Model, quicksum
from qpiai_opt.opt_solvers import solve as solve_milp

DEFAULT_Z_SCENARIOS = (2030, 2032, 2035)
WEEKS_PER_YEAR = 52


@dataclass(frozen=True)
class ScheduleEntry:
    """One asset's migration window and scenario exposure."""

    asset_id: str
    start_week: int
    completion_week: int
    completion_year: float
    scenario_exposure_years: Mapping[int, float]
    weighted_exposure_years: float


@dataclass(frozen=True)
class SchedulePlan:
    """A schedule and its risk-weighted objective value."""

    schedule: tuple[ScheduleEntry, ...]
    objective: float


@dataclass(frozen=True)
class SchedulerResult:
    """Optimized schedule and its comparisons with both baselines."""

    optimized: SchedulePlan
    fcfs: SchedulePlan
    greedy: SchedulePlan
    exposure_years_avoided_vs_fcfs: float
    exposure_years_avoided_vs_greedy: float


@dataclass(frozen=True)
class _Asset:
    asset_id: str
    risk_weight: float
    shelf_life_years: float
    effort_weeks: int


def _normalize_assets(assets: Iterable[Mapping[str, Any]]) -> tuple[_Asset, ...]:
    normalized = []
    seen_ids = set()
    for index, asset in enumerate(assets):
        asset_id = str(asset.get("asset_id", f"asset-{index:03d}")).strip()
        if not asset_id:
            raise ValueError("asset_id must be a non-empty string")
        if asset_id in seen_ids:
            raise ValueError(f"duplicate asset_id: {asset_id}")
        seen_ids.add(asset_id)

        try:
            risk_weight = float(asset["risk_weight"])
            shelf_life_years = float(asset["shelf_life_years"])
            raw_effort = float(asset["effort_weeks"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(
                "each asset needs numeric risk_weight, shelf_life_years, and effort_weeks"
            ) from error

        if not math.isfinite(risk_weight) or risk_weight < 0:
            raise ValueError(f"risk_weight for {asset_id} must be finite and non-negative")
        if not math.isfinite(shelf_life_years) or shelf_life_years <= 0:
            raise ValueError(f"shelf_life_years for {asset_id} must be finite and positive")
        if not math.isfinite(raw_effort) or raw_effort <= 0:
            raise ValueError(f"effort_weeks for {asset_id} must be finite and positive")

        normalized.append(
            _Asset(
                asset_id=asset_id,
                risk_weight=risk_weight,
                shelf_life_years=shelf_life_years,
                effort_weeks=math.ceil(raw_effort),
            )
        )
    return tuple(normalized)


def _scenario_exposure(
    asset: _Asset,
    completion_week: int,
    planning_start_year: int,
    scenarios: tuple[int, ...],
) -> dict[int, float]:
    completion_years = completion_week / WEEKS_PER_YEAR
    return {
        scenario: min(
            asset.shelf_life_years,
            scenario - planning_start_year,
            completion_years,
        )
        for scenario in scenarios
    }


def _make_entry(
    asset: _Asset,
    start_week: int,
    planning_start_year: int,
    scenarios: tuple[int, ...],
) -> ScheduleEntry:
    completion_week = start_week + asset.effort_weeks
    scenario_exposure = _scenario_exposure(
        asset, completion_week, planning_start_year, scenarios
    )
    return ScheduleEntry(
        asset_id=asset.asset_id,
        start_week=start_week,
        completion_week=completion_week,
        completion_year=planning_start_year + completion_week / WEEKS_PER_YEAR,
        scenario_exposure_years=scenario_exposure,
        weighted_exposure_years=asset.risk_weight * sum(scenario_exposure.values()),
    )


def _make_plan(
    assets: tuple[_Asset, ...],
    start_weeks: Mapping[str, int],
    planning_start_year: int,
    scenarios: tuple[int, ...],
) -> SchedulePlan:
    schedule = tuple(sorted((
        _make_entry(asset, start_weeks[asset.asset_id], planning_start_year, scenarios)
        for asset in assets
    ), key=lambda entry: (entry.start_week, entry.asset_id)))
    return SchedulePlan(
        schedule=schedule,
        objective=sum(entry.weighted_exposure_years for entry in schedule),
    )


class _BaselineScheduler:
    def __init__(
        self,
        *,
        planning_start_year: int = 2026,
        z_scenarios: Iterable[int] = DEFAULT_Z_SCENARIOS,
        capacity: int = 1,
    ) -> None:
        self.planning_start_year, self.z_scenarios, self.capacity = _validate_options(
            planning_start_year, z_scenarios, capacity
        )

    def _order(self, assets: tuple[_Asset, ...]) -> tuple[_Asset, ...]:
        raise NotImplementedError

    def solve(self, assets: Iterable[Mapping[str, Any]]) -> SchedulePlan:
        normalized = _normalize_assets(assets)
        if not normalized:
            return SchedulePlan(schedule=(), objective=0.0)

        total_effort = sum(asset.effort_weeks for asset in normalized)
        occupancy = [0] * total_effort
        start_weeks: dict[str, int] = {}
        for asset in self._order(normalized):
            for start_week in range(total_effort - asset.effort_weeks + 1):
                work_weeks = range(start_week, start_week + asset.effort_weeks)
                if all(occupancy[week] < self.capacity for week in work_weeks):
                    start_weeks[asset.asset_id] = start_week
                    for week in work_weeks:
                        occupancy[week] += 1
                    break
            else:
                raise RuntimeError(f"could not place migration work for {asset.asset_id}")

        return _make_plan(
            normalized, start_weeks, self.planning_start_year, self.z_scenarios
        )


class FCFScheduler(_BaselineScheduler):
    """Baseline that schedules assets in the order received."""

    def _order(self, assets: tuple[_Asset, ...]) -> tuple[_Asset, ...]:
        return assets


class GreedyScheduler(_BaselineScheduler):
    """Baseline that schedules the highest-risk assets first."""

    def _order(self, assets: tuple[_Asset, ...]) -> tuple[_Asset, ...]:
        return tuple(sorted(assets, key=lambda asset: -asset.risk_weight))


class AtlasScheduler(_BaselineScheduler):
    """Minimize risk-weighted exposure using a QpiAI Opt MILP model."""

    def __init__(
        self,
        *,
        planning_start_year: int = 2026,
        z_scenarios: Iterable[int] = DEFAULT_Z_SCENARIOS,
        capacity: int = 1,
        solver: Callable[..., Any] | None = None,
    ) -> None:
        super().__init__(
            planning_start_year=planning_start_year,
            z_scenarios=z_scenarios,
            capacity=capacity,
        )
        self._solver = solver or solve_milp

    def _order(self, assets: tuple[_Asset, ...]) -> tuple[_Asset, ...]:
        return assets

    def solve(self, assets: Iterable[Mapping[str, Any]]) -> SchedulerResult:
        assets = tuple(assets)
        normalized = _normalize_assets(assets)
        if not normalized:
            empty_plan = SchedulePlan(schedule=(), objective=0.0)
            return SchedulerResult(empty_plan, empty_plan, empty_plan, 0.0, 0.0)

        total_effort = sum(asset.effort_weeks for asset in normalized)
        model = Model("q_shield_atlas_schedule")
        start_variables: dict[tuple[int, int], Binary] = {}
        start_options: dict[int, tuple[int, ...]] = {}
        for asset_index, asset in enumerate(normalized):
            latest_start = total_effort - asset.effort_weeks
            feasible_starts = tuple(range(latest_start + 1))
            start_options[asset_index] = feasible_starts
            for start_week in feasible_starts:
                start_variables[asset_index, start_week] = Binary(
                    f"start_{asset_index}_{start_week}"
                )

            model.add_constraint(
                quicksum(start_variables[asset_index, week] for week in feasible_starts)
                == 1,
                label=f"schedule_asset_{asset_index}",
            )

        for week in range(total_effort):
            active_starts = [
                variable
                for (asset_index, start_week), variable in start_variables.items()
                if start_week <= week < start_week + normalized[asset_index].effort_weeks
            ]
            model.add_constraint(
                quicksum(active_starts) <= self.capacity,
                label=f"capacity_week_{week}",
            )

        objective_terms = []
        for (asset_index, start_week), variable in start_variables.items():
            asset = normalized[asset_index]
            completion_week = start_week + asset.effort_weeks
            exposure = _scenario_exposure(
                asset,
                completion_week,
                self.planning_start_year,
                self.z_scenarios,
            )
            objective_terms.append(
                asset.risk_weight * sum(exposure.values()) * variable
            )
        model.minimize(quicksum(objective_terms))
        model.validate("MILP")

        result = self._solver(model, mode="local")
        start_weeks = {}
        for asset_index, asset in enumerate(normalized):
            selected = [
                week
                for week in start_options[asset_index]
                if float(result.solution.get(f"start_{asset_index}_{week}", 0.0)) > 0.5
            ]
            if len(selected) != 1:
                raise ValueError(
                    f"MILP returned {len(selected)} start times for {asset.asset_id}"
                )
            start_weeks[asset.asset_id] = selected[0]

        optimized = _make_plan(
            normalized, start_weeks, self.planning_start_year, self.z_scenarios
        )
        fcfs = FCFScheduler(
            planning_start_year=self.planning_start_year,
            z_scenarios=self.z_scenarios,
            capacity=self.capacity,
        ).solve(assets)
        greedy = GreedyScheduler(
            planning_start_year=self.planning_start_year,
            z_scenarios=self.z_scenarios,
            capacity=self.capacity,
        ).solve(assets)
        return SchedulerResult(
            optimized=optimized,
            fcfs=fcfs,
            greedy=greedy,
            exposure_years_avoided_vs_fcfs=fcfs.objective - optimized.objective,
            exposure_years_avoided_vs_greedy=greedy.objective - optimized.objective,
        )


def _validate_options(
    planning_start_year: int,
    z_scenarios: Iterable[int],
    capacity: int,
) -> tuple[int, tuple[int, ...], int]:
    if isinstance(planning_start_year, bool) or not isinstance(planning_start_year, int):
        raise ValueError("planning_start_year must be an integer")
    if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
        raise ValueError("capacity must be a positive integer")
    scenarios = tuple(sorted(set(z_scenarios)))
    if not scenarios or any(
        isinstance(year, bool) or not isinstance(year, int) or year <= planning_start_year
        for year in scenarios
    ):
        raise ValueError("z_scenarios must contain integer years after planning_start_year")
    return planning_start_year, scenarios, capacity