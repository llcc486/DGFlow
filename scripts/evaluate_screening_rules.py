"""Compare the screening rule against its named candidates on the same inputs.

This produces a *candidate evaluation*, not a calibration. It runs the default rule
and the two declared alternatives over synthetic score sets whose shape is
controlled, so the regions where they disagree are visible and the eventual
calibration experiment can target them.

It deliberately does not adopt a candidate: item 4 of the staged plan asks for the
comparison, item 5 asks for thresholds fixed on an independent calibration run
against real training data with a calibration/validation seed split. This script is
neither, and its output must not be presented as a defence result.

Usage:
    python scripts/evaluate_screening_rules.py [--json PATH] [--seeds N]
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT/'src'))

from dgfl.validation import policy

#: Shapes to evaluate. Each row is an honest-or-attacked scenario in the terms the
#: rule sees: how far apart the two groups sit, how far below the bound the low
#: group's centre is, how many clients are in each, and how tight each group is.
SCENARIOS = (
    ('attacked_minority_clear', 0.9, 0.05, 2, 4, 0.01, 0.02),
    ('attacked_minority_marginal', 0.9, 0.20, 3, 3, 0.01, 0.02),
    ('honest_non_iid_minority', 0.9, 0.30, 3, 3, 0.01, 0.02),
    ('honest_non_iid_majority', 0.9, 0.10, 4, 2, 0.02, 0.01),
    ('honest_tight_low_minority', 0.9, 0.15, 2, 4, 0.005, 0.05),
    ('attacked_loose_minority', 0.9, 0.10, 2, 4, 0.09, 0.01),
    ('barely_separated', 0.5, 0.05, 2, 4, 0.01, 0.02),
    ('equal_groups', 0.9, 0.05, 3, 3, 0.01, 0.02),
)


def build(scenario, seed):
    _name, high, low, low_size, high_size, low_spread, high_spread = scenario
    rng = random.Random(seed)
    scores = {}
    for index in range(low_size):
        scores[f'low{index}'] = low + rng.uniform(-low_spread, low_spread)
    for index in range(high_size):
        scores[f'high{index}'] = high + rng.uniform(-high_spread, high_spread)
    return {cid: min(1.0, max(-1.0, value)) for cid, value in scores.items()}


def evaluate(seeds):
    rules = (policy.SCREENING_RULE_LEGACY_V1, *policy.CANDIDATE_RULES)
    results = {}
    for scenario in SCENARIOS:
        name = scenario[0]
        record = {'shape': {'high_center': scenario[1], 'low_center': scenario[2],
                            'low_size': scenario[3], 'high_size': scenario[4],
                            'low_spread': scenario[5], 'high_spread': scenario[6]},
                  'rules': {}}
        for rule in rules:
            rejections = 0
            separations = []
            for seed in range(seeds):
                scores = build(scenario, seed)
                clustering = policy.screen_decided(
                    scores, dict.fromkeys(scores, 100), {})['clustering']
                rejected, _reason = policy.rule_rejects(rule, clustering)
                rejections += 1 if rejected else 0
                if clustering['separation'] is not None:
                    separations.append(clustering['separation'])
            record['rules'][rule] = {
                'rejection_rate': rejections/seeds,
                'mean_separation': (sum(separations)/len(separations)) if separations else None,
            }
        # The disagreement is the point: where the candidates differ from the
        # default is where a calibration run has to look.
        baseline = record['rules'][policy.SCREENING_RULE_LEGACY_V1]['rejection_rate']
        record['disagreement'] = {rule: record['rules'][rule]['rejection_rate']-baseline
                                  for rule in policy.CANDIDATE_RULES}
        results[name] = record
    return {'kind': 'screening-rule-candidate-evaluation',
            'not_a_calibration': True,
            'scope': ('Synthetic score sets only. No training data, no attack model and '
                      'no calibration/validation seed split. Not defence evidence.'),
            'seeds_per_scenario': seeds,
            'rules': list(rules),
            'scenarios': results}


def render(report):
    lines = [f"筛选候选规则对比（合成输入，{report['seeds_per_scenario']} 个种子/场景）",
             '这不是标定实验，不能作为防御结论。', '']
    header = f"{'场景':<28}{'分离度':>8}"
    for rule in report['rules']:
        header += f"{rule:>20}"
    lines.append(header)
    for name, record in report['scenarios'].items():
        separations = [item['mean_separation'] for item in record['rules'].values()
                       if item['mean_separation'] is not None]
        row = f"{name:<28}{(sum(separations)/len(separations) if separations else 0):>8.3f}"
        for rule in report['rules']:
            row += f"{record['rules'][rule]['rejection_rate']*100:>19.1f}%"
        lines.append(row)
    lines.append('')
    lines.append('与默认规则 legacy_v1 的差异（正数表示更激进）：')
    for name, record in record_disagreements(report):
        parts = '、'.join(f'{rule} {value*100:+.1f}pp' for rule, value in record.items())
        lines.append(f'  {name}: {parts}')
    return '\n'.join(lines)


def record_disagreements(report):
    for name, record in report['scenarios'].items():
        yield name, record['disagreement']


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', type=Path, help='Write the evaluation as JSON')
    parser.add_argument('--seeds', type=int, default=32,
                        help='Seeds per scenario (default 32)')
    arguments = parser.parse_args(argv)
    if arguments.seeds < 1:
        parser.error('--seeds must be at least 1')
    report = evaluate(arguments.seeds)
    if arguments.json:
        arguments.json.parent.mkdir(parents=True, exist_ok=True)
        arguments.json.write_text(json.dumps(report, ensure_ascii=False, indent=2,
                                             sort_keys=True) + '\n', encoding='utf8')
    print(render(report))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
