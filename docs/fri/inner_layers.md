## Inner layers

### Goal

Iteratively verify each inner FRI layer:

1. incorporate first-layer columns into the current folded polynomial accumulator,
2. verify Merkle openings of `g_i(x)` values at required positions,
3. fold `(P, -P)` evaluations into the next layer using the current layer’s `alpha`,
4. update `alpha` and continue.

### Folding formula

For a pair of evaluations at `P` and `-P`:

- `evenPart = h(P) + h(-P)`
- `oddPart  = (h(P) - h(-P)) / coord(P)`

Then folded value is:

- `folded = evenPart + alpha * oddPart`

Where `coord(P)` depends on the domain:

- On circle domains (first layer): divide by `Py`
- On line domains (inner layers): divide by `Px`

This is why you see:

- first-layer folding uses `inversePy`
- inner-layer folding uses `inversePx`

### Building the running accumulator `currentLayerEvals`

At each inner step, when column answers must be folded in:

- fold `h` answers with the _previous alpha_ (from the previous commitment)
- then update the accumulator with:
  - `current = current * (previousAlpha^2) + foldedColumnEval`

This matches the standard “combine two sources with a challenge” pattern: the accumulator binds both the previous folded polynomial and newly folded answers.

### Merkle verification for `g_i(x_j)`

For each inner layer and log size:

1. Encode the current `QM31` evaluations into a lookup table:
   - `EncodeNative(eval)` inserted into `logderivlookup.Table`

2. Rebuild paired `(g_i(P), g_i(-P))` using:
   - `computeDecommitmentPositionsAndRebuildEvals(...)`
   - with that layer’s `FriWitness`

3. Construct decommitmentPositions for the Merkle verifier:
   - level `logSize+1`: uses paired positions
   - level `logSize`: folded query list (pair-folded)
   - above that: regular queries

4. Verify Merkle proof against `InnerLayerProof.Commitment`.

### Folding to next inner layer

After Merkle verification, we fold the sparse evaluations:

- `folded = (g(P)+g(-P)) + alpha_i * (g(P)-g(-P))/Px`

Store these in `currentLayerEvals` and proceed to the next log size.

Alpha is updated each step:

- `previousAlpha = alpha_i`
