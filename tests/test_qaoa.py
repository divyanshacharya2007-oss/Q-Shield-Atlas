import pytest

from qaoa.cross_check import (
    LABEL,
    cross_check_weekly_wave,
    decode_bitstring,
    formulate_weekly_qubo,
)


def test_weekly_qubo_encodes_capacity_and_dependency_penalties():
    assets = [
        {"asset_id": "base", "risk_weight": 2.0, "dependencies": []},
        {"asset_id": "dependent", "risk_weight": 5.0, "dependencies": ["base"]},
    ]
    problem = formulate_weekly_qubo(assets, capacity=1, penalty=20.0)

    assert problem.n_variables == 3
    assert problem.energy("001") == pytest.approx(-2.0)
    assert problem.energy("011") == pytest.approx(-7.0 + 20.0)
    assert problem.energy("010") == pytest.approx(-5.0 + 20.0)
    assert problem.decode("001")["selected_asset_ids"] == ("base",)
    assert problem.decode("001")["feasible"] is True
    assert problem.decode("011")["feasible"] is False
    assert problem.decode("010")["feasible"] is False
    assert decode_bitstring("001", 3) == (1, 0, 0)


def test_cross_check_decodes_samples_discards_infeasible_and_reports_metrics():
    assets = [
        {"asset_id": "base", "risk_weight": 2.0, "dependencies": []},
        {"asset_id": "dependent", "risk_weight": 5.0, "dependencies": ["base"]},
    ]

    def fake_sampler(*, problem, layers, shots, seed, max_iterations):
        assert problem.n_variables == 3
        assert layers in (1, 2, 3)
        assert shots == 10
        return {"001": 4, "100": 2, "011": 3, "010": 1}, f"job-{layers}"

    result = cross_check_weekly_wave(
        assets,
        capacity=1,
        shots=10,
        sampler=fake_sampler,
    )

    assert result.label == LABEL
    assert result.label == "Measured cross-check only, no claim of quantum advantage."
    assert result.backend_status == "MEASURED_INJECTED_SAMPLER"
    assert result.selected_asset_ids == ("base",)
    assert result.selected_objective == pytest.approx(2.0)
    assert result.exact_optimum == pytest.approx(2.0)
    assert result.approximation_ratio == pytest.approx(1.0)
    assert result.optimal_bitstring_probability == pytest.approx(12 / 30)
    assert result.discarded_infeasible_counts == 12
    assert result.job_ids == ("job-1", "job-2", "job-3")
    assert len(result.depth_results) == 3
    assert result.feasible_counts == {"001": 12, "100": 6}


def test_local_qaoa_fallback_executes_all_depths():
    result = cross_check_weekly_wave(
        [
            {"asset_id": "one", "risk_weight": 3.0},
            {"asset_id": "two", "risk_weight": 1.0},
        ],
        capacity=1,
        shots=64,
        seed=11,
        max_iterations=3,
        prefer_qcloud=False,
    )

    assert result.backend == "local-statevector"
    assert result.backend_status == "MEASURED"
    assert [run["layers"] for run in result.depth_results] == [1, 2, 3]
    assert result.selected_asset_ids == ("one",)
    assert result.approximation_ratio == pytest.approx(1.0)
    assert result.job_ids == ()


def test_weekly_qubo_enforces_sixteen_variable_limit():
    assets = [{"asset_id": f"asset-{index}", "risk_weight": 1} for index in range(16)]

    with pytest.raises(ValueError, match="limit is 16"):
        formulate_weekly_qubo(assets, capacity=8)