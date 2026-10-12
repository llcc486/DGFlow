"""Exact bounded-DLP cache for public intervals.

Only fixed-base public baby steps and public endpoint shifts are cached.
No ciphertext, target, recovered exponent, witness or secret is memoized.
Cache residency is bounded; concurrently active callers can retain evicted
tables, so this is not a whole-process memory ceiling.
"""
from __future__ import annotations

import math
import threading
from collections import OrderedDict
from types import MappingProxyType

MAX_STEP = 100_000


def table_step(width):
    if type(width) is not int or width < 1:
        raise ValueError("positive integer DLP width required")
    minimum = math.isqrt(width) + 1
    if minimum > MAX_STEP:
        raise ValueError("discrete logarithm range exceeds configured memory budget")
    # Exact for small tables. Larger public intervals share fine-grained
    # buckets: at most ~3.125% extra baby steps; same exact authorized range.
    quantum = 1 << max(0, minimum.bit_length() - 6)
    return min(MAX_STEP, ((minimum + quantum - 1) // quantum) * quantum)


class BoundedLogCache:
    def __init__(self, group, base, power, shift, *, max_entries=200_000):
        if type(max_entries) is not int or not MAX_STEP <= max_entries <= 800_000:
            raise ValueError("retained public baby-step budget must be 100000 to 800000")
        self._group, self._base = group, base
        self._power, self._shift = power, shift
        self.max_entries = max_entries
        self._tables = OrderedDict()
        self._lock = threading.RLock()
        self._retained = self._builds = self._hits = 0

    def _table(self, step):
        with self._lock:
            if step in self._tables:
                self._hits += 1
                self._tables.move_to_end(step)
                return self._tables[step]
            # Evict before allocation. Each completed retained table counts
            # all its group elements, unlike a simple number-of-tables limit.
            while self._retained + step > self.max_entries:
                count, _ = self._tables.popitem(last=False)
                self._retained -= count
            baby, value = {}, self._group.one()
            for exponent in range(step):
                baby[value] = exponent
                value = value * self._base
            result = (MappingProxyType(baby), self._power(self._base, -step))
            self._tables[step] = result
            self._retained += step
            self._builds += 1
            return result

    def decode(self, value, lower, upper):
        if type(lower) is not int or type(upper) is not int or lower > upper:
            raise ValueError("integer ordered discrete logarithm interval required")
        width = upper - lower + 1
        step = table_step(width)
        baby_steps, inverse_step = self._table(step)
        current = value * self._shift(lower)
        for giant in range((upper - lower) // step + 1):
            baby = baby_steps.get(current)
            if baby is not None:
                result = lower + giant * step + baby
                if result <= upper:
                    return result
            current = current * inverse_step
        raise ValueError("discrete logarithm outside authorized range")

    def cache_info(self):
        with self._lock:
            return {"table_steps": list(self._tables), "retained_entries": self._retained,
                    "budget_entries": self.max_entries, "builds": self._builds, "hits": self._hits}
