"""PRD v2 section 4.3 estimators, stdlib only.

Every function here is pure and takes integers/floats, so a table cell can be recomputed
byte-identically on any interpreter. Floats are quantized by the caller (bench.common.
quantize) before hashing; that is what makes cross-machine figure diffs meaningful.

Reference for each estimator is named in the docstring rather than in a comment above the
code, because the names are the audit trail a reviewer follows.
"""
import math
from bisect import bisect_left

from bench.common import quantize


def _beta_ppf(p, a, b, low=0.0, high=1.0, iterations=200):
    """Inverse CDF of Beta(a,b) by bisection on the regularized incomplete beta."""
    for _ in range(iterations):
        mid = (low + high) / 2.0
        if mid <= low or mid >= high:
            break
        if incomplete_beta(mid, a, b) < p:
            low = mid
        else:
            high = mid
    return (low + high) / 2.0


def incomplete_beta(x, a, b):
    """Regularized incomplete beta I_x(a,b) via the continued fraction (Lentz)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    ln_boundary = (math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
                   + a * math.log(x) + b * math.log(1.0 - x))
    boundary = math.exp(ln_boundary)
    if x < (a + 1.0) / (a + b + 2.0):
        return boundary * beta_cf(x, a, b) / a
    return 1.0 - boundary * beta_cf(1.0 - x, b, a) / b


def beta_cf(x, a, b):
    tiny, maximum, cap = 1e-300, 1e300, 300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c, d = 1.0, 1.0 - qab * x / qap
    if abs(d) < tiny:
        d = tiny
    d = 1.0 / d
    total = d
    for m in range(1, cap + 1):
        even = 2 * m
        numerator = m * (b - m) * x / ((qam + even) * (a + even))
        d = 1.0 + numerator * d
        c = 1.0 + numerator / c
        if abs(d) < tiny:
            d = tiny
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        total *= d * c
        odd = even + 1
        numerator = -(a + m) * (qab + m) * x / ((a + odd) * (qam + odd))
        d = 1.0 + numerator * d
        c = 1.0 + numerator / c
        if abs(d) < tiny:
            d = tiny
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        total *= delta
        if abs(delta - 1.0) < 1e-12:
            break
    return total


def wilson(successes, count, confidence=0.95):
    """Wilson score interval for a binomial proportion (PRD 4.3, BH/BC reference)."""
    if count <= 0:
        return {"successes": successes, "count": count, "point": None, "low": None, "high": None,
                "method": "wilson", "confidence": confidence}
    z = Z_TABLE.get(round(confidence, 4), 1.959963984540054)
    phat = successes / count
    denominator = 1.0 + z * z / count
    centre = (phat + z * z / (2 * count)) / denominator
    spread = (z / denominator) * math.sqrt(phat * (1 - phat) / count + z * z / (4 * count * count))
    return {"successes": successes, "count": count, "point": quantize(phat),
            "low": quantize(max(0.0, centre - spread)), "high": quantize(min(1.0, centre + spread)),
            "method": "wilson", "confidence": confidence}


Z_TABLE = {0.80: 1.2815515655446004, 0.90: 1.6448536269514722, 0.95: 1.959963984540054,
           0.98: 2.3263478740408408, 0.99: 2.5758293035489004}


def clopper_pearson(successes, count, confidence=0.95):
    """Exact Clopper-Pearson interval; the conservative companion to Wilson."""
    alpha = 1.0 - confidence
    low = 0.0 if successes == 0 else _beta_ppf(alpha / 2.0, successes, count - successes + 1)
    high = 1.0 if successes == count else _beta_ppf(1.0 - alpha / 2.0, successes + 1, count - successes)
    return {"successes": successes, "count": count,
            "point": quantize(successes / count) if count else None,
            "low": quantize(low), "high": quantize(high), "method": "clopper-pearson",
            "confidence": confidence}


def nearest_rank(values, percentile):
    """Percentile by nearest rank, matching scripts/benchmark.py so old and new tables agree."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile / 100.0 * len(ordered)))
    return ordered[rank - 1]


def distribution(values):
    """Count/min/p50/p90/p95/p99/max, quantized for stable hashing."""
    if not values:
        return {"count": 0}
    ordered = sorted(values)
    return {"count": len(ordered), "min": quantize(ordered[0]), "max": quantize(ordered[-1]),
            "mean": quantize(sum(ordered) / len(ordered)),
            "p50": quantize(nearest_rank(ordered, 50)), "p90": quantize(nearest_rank(ordered, 90)),
            "p95": quantize(nearest_rank(ordered, 95)), "p99": quantize(nearest_rank(ordered, 99))}


def geometric_mean(values):
    """Cross-workload aggregation (PRD 4.3). Zero or negative input makes the mean undefined."""
    positive = [value for value in values if value is not None]
    if not positive or any(value <= 0 for value in positive):
        return None
    return quantize(math.exp(sum(math.log(value) for value in positive) / len(positive)))


def arithmetic_mean(values):
    values = [value for value in values if value is not None]
    return quantize(sum(values) / len(values)) if values else None


def bootstrap_percentile(values, percentile, samples=2000, seed=20261031, bca=False):
    """Bootstrap interval for a percentile; bca=True adds the bias-corrected acceleration."""
    if len(values) < 3:
        return {"percentile": percentile, "count": len(values), "point": None, "low": None, "high": None,
                "method": "bca" if bca else "percentile", "insufficient_data": True}
    point = nearest_rank(values, percentile)
    replicates = sorted(resample_stat(values, percentile, samples, seed))
    low, high = replicates[int(0.025 * len(replicates))], replicates[min(len(replicates) - 1, int(0.975 * len(replicates)))]
    result = {"percentile": percentile, "count": len(values), "point": quantize(point),
              "low": quantize(low), "high": quantize(high), "method": "bca" if bca else "percentile",
              "replicates": len(replicates)}
    if bca:
        result.update(bootstrap_bca(values, point, low, high, replicates))
    return result


def resample_stat(values, percentile, samples, seed):
    import random
    rng = random.Random(seed)
    out = []
    n = len(values)
    for _ in range(samples):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        out.append(nearest_rank(sample, percentile))
    return out


def bootstrap_bca(values, point, low, high, replicates):
    """Bias correction z0 and acceleration a from jackknife (Efron)."""
    n = len(values)
    sorted_reps = sorted(replicates)
    counts_below = bisect_left(sorted_reps, point)
    z0 = normal_quantile(max(1e-9, min(1 - 1e-9, counts_below / len(sorted_reps))))
    mean = sum(values) / n
    theta = [sum(value for index, value in enumerate(values) if index != drop) / (n - 1) for drop in range(n)]
    diffs = [mean - item for item in theta]
    accel = sum(item ** 3 for item in diffs) / (6.0 * (sum(item ** 2 for item in diffs) ** 1.5)) if any(diffs) else 0.0
    def adjusted(alpha):
        denominator = 1.0 - (z0 + normal_quantile(alpha)) * accel
        if not denominator:
            return 0.025 if alpha < 0.5 else 0.975
        return normal_cdf(z0 + normal_quantile(alpha) / denominator)
    return {"bias_correction": quantize(z0), "acceleration": quantize(accel),
            "adjusted_low": quantize(adjusted(0.025)), "adjusted_high": quantize(adjusted(0.975)),
            "note": "BCa adjustment reported alongside the plain percentile interval"}


def normal_quantile(p):
    """Acklam's inverse normal CDF approximation, accurate to ~1e-9."""
    a = [-3.969683028665376e+01, 2.209460984245205e+02, -2.759285104469687e+02,
         1.383577518672690e+02, -3.066479806614716e+01, 2.506628277459239e+00]
    b = [-5.447609879822406e+01, 1.615858368580409e+02, -1.556989798598866e+02,
         6.680131188771972e+01, -1.328068155288572e+01]
    c = [-7.021038566629227e-03, -1.182033053624463e-03, 3.018401392016103e-02, 1.281627890158791e-01,
         -5.217854258572583e-02, -8.366940402212113e-03, 9.253356875023822e-03, 7.630249774097220e-02,
         -2.044996115344659e-01, -8.119858785323399e-02, -9.337984242823638e-02, -8.228291696877034e-02, -3.063145076656262e-02]
    d = [7.184933555456408e-02, 7.497828316168218e-01, 2.375417159025399e-01, 4.650237810383840e-02]
    plow, phigh = 0.02425, 1 - 0.02425
    if p <= 0:
        return -math.inf
    if p >= 1:
        return math.inf
    if p < plow:
        q = math.sqrt(-2 * math.log(p))
        return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / \
               ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1)
    if p <= phigh:
        q = p - 0.5
        r = q * q
        return (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q / \
               (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1)
    q = math.sqrt(-2 * math.log(1 - p))
    return -(((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / \
           ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1)


def normal_cdf(z):
    return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))


def mcnemar_exact(pairs):
    """McNemar's exact test on discordant pairs (two-sided binomial, mid-p free)."""
    b = sum(1 for first, second in pairs if first and not second)
    c = sum(1 for first, second in pairs if second and not first)
    n = b + c
    result = {"discordant_b": b, "discordant_c": c, "n": n, "method": "mcnemar-exact"}
    if n == 0:
        result.update({"p_value": 1.0, "note": "no discordant pairs; the two tools never disagreed"})
        return result
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / (2.0 ** n)
    result.update({"p_value": quantize(min(1.0, tail * 2)),
                   "continuity_corrected_chi2": quantize((abs(b - c) - 1) ** 2 / n) if n else None})
    return result


def mcnemar_normal(pairs):
    """Large-sample McNemar chi-square, reported next to the exact test for transparency."""
    b = sum(1 for first, second in pairs if first and not second)
    c = sum(1 for first, second in pairs if second and not first)
    if b + c == 0:
        return {"chi2": 0.0, "p_value": 1.0, "method": "mcnemar-chi2"}
    chi2 = (b - c) ** 2 / (b + c)
    return {"chi2": quantize(chi2), "p_value": quantize(math.erfc(math.sqrt(chi2 / 2.0))),
            "method": "mcnemar-chi2"}


def mann_whitney_u(sample_a, sample_b):
    """Two-sided Mann-Whitney U with tie-corrected normal approximation (PRD 4.3)."""
    a, b = list(sample_a), list(sample_b)
    if not a or not b:
        return {"u": None, "p_value": None, "n_a": len(a), "n_b": len(b), "insufficient_data": True}
    combined = sorted(a + b)
    ranks = average_ranks(combined)
    position = {}
    for index, value in enumerate(combined):
        position.setdefault(value, []).append(index)
    def rank_of(value):
        return ranks[position[value][0]]
    sum_a = sum(rank_of(value) for value in a)
    n1, n2 = len(a), len(b)
    u1 = sum_a - n1 * (n1 + 1) / 2.0
    u2 = n1 * n2 - u1
    mean = n1 * n2 / 2.0
    total = n1 + n2
    tie_groups = {}
    for value in combined:
        tie_groups[value] = tie_groups.get(value, 0) + 1
    tie_term = sum(count ** 3 - count for count in tie_groups.values()) / float(total * (total - 1)) if total > 1 else 0.0
    variance = n1 * n2 / 12.0 * (total + 1 - tie_term)
    z = 0.0 if variance <= 0 else ((abs(u1 - mean) - 0.5) / math.sqrt(variance))
    return {"u": quantize(min(u1, u2)), "u_a": quantize(u1), "u_b": quantize(u2), "z": quantize(z),
            "p_value": quantize(math.erfc(z / math.sqrt(2.0))), "n_a": n1, "n_b": n2,
            "mean_rank_difference": quantize((sum_a / n1) - (sum(rank_of(value) for value in b) / n2)),
            "method": "mann-whitney-normal-tie-corrected-continuity"}


def average_ranks(sorted_values):
    out, index = [], 0
    while index < len(sorted_values):
        last = index
        while last + 1 < len(sorted_values) and sorted_values[last + 1] == sorted_values[index]:
            last += 1
        value = (index + last + 2) / 2.0
        out.extend([value] * (last - index + 1))
        index = last + 1
    return out


def cliffs_delta(sample_a, sample_b):
    """Cliff's delta effect size with the Romano magnitude labels."""
    a, b = list(sample_a), list(sample_b)
    if not a or not b:
        return {"delta": None}
    greater = sum(1 for x in a for y in b if x > y)
    less = sum(1 for x in a for y in b if x < y)
    delta = (greater - less) / float(len(a) * len(b))
    magnitude = abs(delta)
    label = ("negligible" if magnitude < 0.147 else "small" if magnitude < 0.33
             else "medium" if magnitude < 0.474 else "large")
    return {"delta": quantize(delta), "magnitude": label, "greater": greater, "less": less,
            "equal": len(a) * len(b) - greater - less}


def holm(p_values, alpha=0.05):
    """Holm-Bonferroni step-down adjustment; input order is preserved in the output."""
    indexed = sorted(enumerate(p_values), key=lambda item: item[1])
    adjusted, running = [None] * len(p_values), 0.0
    m = len(p_values)
    for step, (position, raw) in enumerate(indexed):
        candidate = min(1.0, (m - step) * raw)
        running = max(running, candidate)
        adjusted[position] = quantize(running)
    return {"alpha": alpha, "raw": [quantize(value) for value in p_values],
            "adjusted": adjusted, "reject": [value <= alpha for value in adjusted]}


def cohens_kappa(pairs):
    """Cohen's kappa for two raters over nominal classes, with the agreement rate."""
    classes = sorted({first for first, _ in pairs} | {second for _, second in pairs})
    if not pairs:
        return {"kappa": None, "classes": classes}
    n = len(pairs)
    observed = sum(1 for first, second in pairs if first == second) / n
    expected = 0.0
    for label in classes:
        first_share = sum(1 for item, _ in pairs if item == label) / n
        second_share = sum(1 for _, item in pairs if item == label) / n
        expected += first_share * second_share
    kappa = (observed - expected) / (1.0 - expected) if expected != 1.0 else 1.0
    return {"kappa": quantize(kappa), "observed_agreement": quantize(observed),
            "expected_agreement": quantize(expected), "n": n, "classes": classes,
            "interpretation": landis_kappa(kappa)}


def landis_kappa(kappa):
    if kappa is None:
        return "undefined"
    return ("pure chance" if kappa <= 0 else "slight" if kappa < 0.21 else "fair" if kappa < 0.41
            else "moderate" if kappa < 0.61 else "substantial" if kappa < 0.81
            else "almost perfect")


def fleiss_kappa(matrix):
    """Fleiss' kappa; rows are subjects, matrix[row][category] is a rater count."""
    if not matrix:
        return {"kappa": None}
    subjects = len(matrix)
    categories = len(matrix[0])
    n = sum(matrix[0])
    if subjects == 0 or n <= 1:
        return {"kappa": None, "subjects": subjects}
    total = sum(sum(row) for row in matrix)
    proportions = [sum(row[c] for row in matrix) / total for c in range(categories)]
    pe = sum(share ** 2 for share in proportions)
    p_j = [sum(count * (count - 1) for count in row) / (n * (n - 1)) for row in matrix]
    p_bar = sum(p_j) / subjects
    denominator = (1.0 - pe)
    kappa = (p_bar - pe) / denominator if denominator else 1.0
    return {"kappa": quantize(kappa), "p_bar": quantize(p_bar), "p_e": quantize(pe),
            "subjects": subjects, "raters_per_subject": n, "interpretation": landis_kappa(kappa)}


def cluster_bootstrap_by_case(case_groups, samples=2000, seed=20261031, statistic=None):
    """Case-level resampling: correlated runs inside a case must not buy fake precision."""
    groups = list(case_groups)
    if not groups:
        return {"point": None, "low": None, "high": None}
    statistic = statistic or ratio_statistic
    point = quantize(statistic([item for group in groups for item in group]))
    import random
    rng = random.Random(seed)
    replicates = []
    for _ in range(samples):
        drawn = [groups[rng.randrange(len(groups))] for _ in groups]
        flat = [item for group in drawn for item in group]
        replicates.append(statistic(flat) if flat else 0.0)
    replicates.sort()
    return {"point": point, "low": quantize(replicates[int(0.025 * len(replicates))]),
            "high": quantize(replicates[min(len(replicates) - 1, int(0.975 * len(replicates)))]),
            "clusters": len(groups), "method": "cluster-bootstrap-case", "samples": samples}


def ratio_statistic(flags):
    return sum(1 for flag in flags if flag) / len(flags) if flags else 0.0


def change_point(series, threshold_ratio=0.20, required_confirmations=2):
    """Regression detection needing two consecutive confirmations at a practical threshold.

    One spike is noise; the PRD requires the degradation to repeat before it is called a
    regression, so this returns the flagged indexes and the reason each was kept or dropped.
    """
    values = [value for value in series if value is not None]
    if len(values) < 3:
        return {"flagged": [], "baseline": None, "insufficient_data": True,
                "practical_threshold": threshold_ratio, "required_confirmations": required_confirmations}
    warmup = min(len(values), max(3, len(values) // 4))
    baseline = sum(values[:warmup]) / warmup
    candidates, evidence = [], []
    for index, value in enumerate(values):
        ratio = value / baseline if baseline else 1.0
        over = index >= warmup and ratio > 1.0 + threshold_ratio
        evidence.append({"index": index, "value": quantize(value), "ratio": quantize(ratio),
                         "in_baseline_window": index < warmup, "exceeds": over})
        if over:
            candidates.append(index)
    confirmed, streak = [], []
    for item in evidence:
        if item["exceeds"]:
            streak.append(item["index"])
            if len(streak) >= required_confirmations:
                confirmed.extend(streak)
                streak = []
        else:
            streak = []
    return {"flagged": sorted(set(confirmed)), "dropped_single_spikes": sorted(set(candidates) - set(confirmed)),
            "baseline": quantize(baseline), "warmup_points": warmup, "practical_threshold": threshold_ratio,
            "required_confirmations": required_confirmations, "evidence": evidence}


def dkw_bound(successes, count, confidence=0.95):
    """Dvoretzky-Kiefer-Wolfowitz style additive bound, kept for comparability with the old script."""
    if count <= 0:
        return None
    epsilon = math.sqrt(math.log(2.0 / (1.0 - confidence)) / (2.0 * count))
    return {"epsilon": quantize(epsilon), "low": quantize(max(0.0, successes / count - epsilon)),
            "high": quantize(min(1.0, successes / count + epsilon)), "method": "dkw"}


def sample_size_note(positives, achieved=None, target=0.13):
    """PRD 4.4: a small positive set cannot support a tight recall claim."""
    if not positives or achieved is None:
        return {"positives": positives, "achieved": achieved, "half_width": None,
                "target_half_width": target,
                "warning": "no positives recorded; recall is unmeasurable" if not positives
                           else "recall numerator missing; cannot size the interval"}
    interval = wilson(achieved, positives)
    half = quantize((interval["high"] - interval["low"]) / 2.0)
    return {"positives": positives, "achieved": achieved, "half_width": half,
            "target_half_width": target, "interval": interval,
            "warning": "recall interval is wider than the PRD 4.4 target" if half > target else None}
