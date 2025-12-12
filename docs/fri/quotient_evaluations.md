## FRI quotient evaluations

`FriQuotientEvaluations(...)` computes the FRI quotient evaluations used for batching constraints across:

- multiple trees,
- multiple columns per log size,
- and possibly two sample points per log size.

### What it returns

A 2D array:

- outer index: per log size in `circuitData.ColumnBounds`
- inner index: per query position in that log size

Each entry is a `QM31` quotient evaluation.

### How it works (main ideas)

1. Determine `maxNColumns` across all trees/log-sizes and precompute powers of `randomCoeff`.
2. Merge `sampledValues` and `sampledPoints` into ordered `SampleData` buckets:
   - grouped by log size,
   - then grouped by sample point,
   - preserving order (not a map).
3. For each query position:
   - bit-reverse index into the circle domain (`reverseBitIndex`)
   - load and flatten queried M31 column values across all trees
   - evaluate the quotient by:
     - computing a rational term per sample point:
       - numerator batches all lines through the same sample point
       - denominator is derived from the circle geometry
     - combining per-sample-point terms with `randomCoeff` powers.

The key routine is:

- `quotientEvaluation(samples, valuesAtQueryPosition, domainPoint, randomCoeffPowers)`
