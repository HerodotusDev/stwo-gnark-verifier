## First layer

### Goal

1. Compute the **decommitment positions** needed for Merkle verification:
   - includes queried positions and any necessary siblings (deduped / paired)
2. Rebuild **paired evaluations** `(h(P), h(-P))`:
   - using provided evaluations where available,
   - otherwise using a **hinted witness stream**
3. Verify the **Merkle decommitment** against the first layer commitment root.

### Key routine: `computeDecommitmentPositionsAndRebuildEvals(...)`

Given a list of queries for a layer and a table of evaluations at those queries:

- For each pair index `i` (up to `layerQueriesShape`):
  - read two consecutive query handles:
    - `leftQuery  = layerQueries[i]`
    - `rightQuery = layerQueries[i+1]`
  - derive the **pair index** (“initial”):
    - `queryInitial = (leftQuery >> 1)`
  - rebuild the canonical pair positions:
    - `leftCandidate  = 2*queryInitial`
    - `rightCandidate = 2*queryInitial + 1`
  - insert these two candidates into `layerDecommitmentPositions`

So **even if the original query list only contained one side**, the decommitment position list is always the _full pair_ `(2k, 2k+1)`.

### Selecting which evaluations to use (provided vs witness)

We detect which side was actually queried:

- `isLeftQueried  = (leftQuery  == leftCandidate)`
- `isRightQueried = (rightQuery == rightCandidate)`

We then obtain a missing evaluation from a **hint**:

- Inputs to the hint:
  - `(isLeftQueried, isRightQueried, witnessIndex)`
  - plus the entire witness stream `witnessEvals` flattened into limbs
- Outputs from the hint:
  - `witness` (a `QM31` value = 4 limbs)
  - updated `witnessIndex`

Then we select:

- `leftEval  = select(isLeftQueried,  eval0, witness)`
- `rightEval = select(isLeftQueried,  select(isRightQueried, eval1, witness), eval0)`

This yields correct `(leftEval, rightEval)` under all cases below.

### Interpretation by case (first layer pairing)

| Case                                     | Meaning in the query pair | leftEval  | rightEval | Offset advance |
| ---------------------------------------- | ------------------------- | --------- | --------- | -------------- |
| `isLeftQueried=1` and `isRightQueried=1` | both sides provided       | `eval0`   | `eval1`   | `offset += 1`  |
| `isLeftQueried=1` and `isRightQueried=0` | only left side provided   | `eval0`   | `witness` | `offset += 0`  |
| `isLeftQueried=0` and `isRightQueried=1` | only right side provided  | `witness` | `eval0`   | `offset += 1`  |
| otherwise                                | neither side provided     | `witness` | `witness` | `offset += 0`  |

> Note: `offset` is the mechanism used here to “skip” consumption of the second query entry when appropriate, because we’re iterating over a flattened query list that may contain placeholders depending on dedup/pairing.

### Producing values for Merkle verification

Merkle nodes in this system hash **flattened M31 columns**.

A single `QM31` value corresponds to 4 `M31` limbs:

- `AReal, AImag, BReal, BImag`

So each `(leftEval, rightEval)` becomes **8 M31 elements** appended into `pairedEvalsFlattened`,
which becomes the `queriedValues` stream consumed by `MerkleVerifier`.

### Folding queries across layers

In `verifyFirstLayer`, when we do not have direct FRI answers at a layer, we compute that layer’s queries by folding the layer below:

- extract previous decommitment positions,
- call:
  - `utils.FoldQueries(api, previousLayerQueries, shape)`
- store as the next layer’s `decommitmentPositions[logSize]`.

This constructs a consistent set of decommitment positions all the way to the root.

### Merkle decommitment

Finally, we instantiate the Merkle verifier with:

- `root = FirstLayerProof.Commitment`
- `columnLogSizes`: derived from each commitment domain (flattened by 4)
- `nColumnsPerLogSize[logSize] = 4` for each bound we open

and call:

- `merkleVerifier.Verify(decommitmentPositions, sparseEvaluationsFlattened, decommitment, queriesShape)`

This proves the reconstructed evaluations are bound to the committed root.

---
