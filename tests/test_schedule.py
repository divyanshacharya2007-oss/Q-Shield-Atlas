from types import SimpleNamespace

import pytest

from schedule.solver import AtlasScheduler, FCFScheduler, GreedyScheduler


ASSETS = [
    {
        "asset_id": "low-risk",
        "risk_weight": 1,
        "shelf_life_years": 10,
        "effort_weeks": 1,
    },
    {
        "asset_id": "high-risk",
        "risk_weight": 10,
        "shelf_life_years": 10,
        "effort_weeks": 1,
    },
]


def test_baselines_follow_expected_orders():
    fcfs = FCFScheduler().solve(ASSETS)
    greedy = GreedyScheduler().solve(ASSETS)

    assert [entry.asset_id for entry in fcfs.schedule] == ["low-risk", "high-risk"]
    assert [entry.asset_id for entry in greedy.schedule] == ["high-risk", "low-risk"]
    assert greedy.objective < fcfs.objective


def test_atlas_builds_milp_and_reports_avoided_exposure():
    captured = {}

    def fake_solver(model, *, mode):
        captured["model"] = model
        captured["mode"] = mode
        return SimpleNamespace(
            solution={
                "start_0_1": 1,
                "start_1_0": 1,
            }
        )

    result = AtlasScheduler(solver=fake_solver).solve(ASSETS)

    assert captured["mode"] == "local"
    assert captured["model"].validate("MILP") == "MILP"
    assert [entry.start_week for entry in result.optimized.schedule] == [0, 1]
    assert result.optimized.objective == pytest.approx(result.greedy.objective)
    assert result.exposure_years_avoided_vs_fcfs == pytest.approx(
        result.fcfs.objective - result.optimized.objective
    )
    assert result.exposure_years_avoided_vs_greedy == pytest.approx(0)
    assert result.optimized.schedule[0].scenario_exposure_years == {
        2030: pytest.approx(1 / 52),
        2032: pytest.approx(1 / 52),
        2035: pytest.approx(1 / 52),
    }


def test_shelf_life_caps_each_scenario_exposure():
    plan = FCFScheduler().solve(
        [
            {
                "asset_id": "short-lived",
                "risk_weight": 2,
                "shelf_life_years": 0.01,
                "effort_weeks": 4,
            }
        ]
    )

    assert list(plan.schedule[0].scenario_exposure_years.values()) == [0.01] * 3
    assert plan.objective == pytest.approx(0.06)


def test_duplicate_asset_ids_are_rejected():
    with pytest.raises(ValueError, match="duplicate asset_id"):
        FCFScheduler().solve([ASSETS[0], ASSETS[0]])


def test_atlas_accepts_one_shot_asset_iterables():
    def fake_solver(model, *, mode):
        return SimpleNamespace(solution={"start_0_0": 1})

    result = AtlasScheduler(solver=fake_solver).solve(iter([ASSETS[0]]))

    assert len(result.fcfs.schedule) == 1
    assert len(result.greedy.schedule) == 1