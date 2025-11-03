package cairo_components

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

const (
	PREPROCESSED_IDX = 0
	MAIN_IDX         = 1
	INTERACTION_IDX  = 2
	CP_IDX           = 3
)

// Traces encapsulates the sampled values for preprocessed, main trace
// and interaction domains while keeping track of consumption as
// components advance through evaluation.
type Traces struct {
	preprocessed PreprocessedSampledValues
	main         [][]m31.QM31
	interaction  [][]m31.QM31
}

// NewTraces builds a Traces helper from the sampled values.
func NewTraces(preprocessed PreprocessedSampledValues, main [][]m31.QM31, interaction [][]m31.QM31) *Traces {
	return &Traces{
		preprocessed: preprocessed,
		main:         main,
		interaction:  interaction,
	}
}

// RemainingMain returns the number of trace columns left to consume.
func (t *Traces) RemainingMain() int {
	return len(t.main)
}

// RemainingInteraction returns the number of interaction columns left.

func (t *Traces) RemainingInteraction() int {
	return len(t.interaction)
}

// Take returns the next main and interaction columns and advances the
// internal cursors. It panics if insufficient data is available.
func (t *Traces) Take(mainCols, interactionCols int) ([][]m31.QM31, [][]m31.QM31) {
	if mainCols < 0 || interactionCols < 0 {
		panic("trace consumption counts must be non-negative")
	}
	if len(t.main) < mainCols {
		panic("insufficient trace columns for component evaluation")
	}
	if len(t.interaction) < interactionCols {
		panic("insufficient interaction columns for component evaluation")
	}

	main := t.main[:mainCols]
	interaction := t.interaction[:interactionCols]

	t.main = t.main[mainCols:]
	t.interaction = t.interaction[interactionCols:]

	return main, interaction
}

// Get returns the sampled value for the provided preprocessed column.
func (t *Traces) Get(column PreprocessedColumn) m31.QM31 {
	return t.preprocessed.Get(column)
}

// Preprocessed exposes the underlying preprocessed sampled values.
func (t *Traces) Preprocessed() PreprocessedSampledValues {
	return t.preprocessed
}
