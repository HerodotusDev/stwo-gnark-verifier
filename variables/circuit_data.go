package variables

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
)

// ╔══════════════════════════════════╗
// ║         Structure Types          ║
// ╚══════════════════════════════════╝

// CircuitData contains additional data used to compile the circuit.
// Fields are constants and specific to a given proof.
type CircuitData struct {
	// NColumnsPerLogSize contains the number of columns per log size for each tree (preprocessed, main, interaction and cp).
	// log sizes of NColumnsPerLogSize are not blew up by the [fri.FriConfig.LogBlowupFactor].
	NColumnsPerLogSize [][]int
	// ColumnLogSizes contains the ordered log sizes of the columns for each tree.
	// log sizes of ColumnLogSizes are not blew up.
	ColumnLogSizes [][]int
	// ColumnBounds is a deduped slice of blew up log sizes of the columns accross all trees.
	// Ordered in descending order.
	ColumnBounds []int
	// DedupedQueriesShape contains the deduplicated number of queries per log size.
	// Meaning there is DedupedQueriesShape[i] queries for log size i.
	DedupedQueriesShape []int
	// ComponentConfig holds as many booleans as there are components in the circuit.
	// True if the component is used in the circuit, false otherwise.
	ComponentConfig ComponentConfig
	// PreprocessedConfig holds as many booleans as there are preprocessed columns in the circuit.
	// True if the preprocessed column is used in the circuit, false otherwise.
	PreprocessedConfig PreprocessedConfig
	// BoundsLength is len(ColumnBounds)
	BoundsLength int
	// MaxLogSize is max(ColumnBounds)
	MaxLogSize uint8
}

// ComponentConfig is the configuration of the components used in the circuit
// The booleans are specifically ordered to match cairo's ordering.
type ComponentConfig [61]bool

// PreprocessedConfig is the configuration of the preprocessed columns used in the circuit
// The booleans are specifically ordered to match cairo's ordering.
type PreprocessedConfig [cairo_components.NPreprocessedColumns]bool

// ╔══════════════════════════════════╗
// ║             Reading              ║
// ╚══════════════════════════════════╝

// ReadCircuitShape loads a circuit shape file from disk.
func ReadCircuitShape(path string) (*CircuitShapeRaw, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()
	return readCircuitShapeFromReader(file)
}

// readCircuitShapeFromReader decodes a circuit shape from the supplied reader.
func readCircuitShapeFromReader(r io.Reader) (*CircuitShapeRaw, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var shape CircuitShapeRaw
	if err := json.Unmarshal(data, &shape); err != nil {
		return nil, err
	}

	return &shape, nil
}

// ╔══════════════════════════════════╗
// ║             Building             ║
// ╚══════════════════════════════════╝

// BuildCircuitData builds CircuitData from the raw JSON shape description.
func BuildCircuitData(shapeRaw *CircuitShapeRaw) CircuitData {
	if shapeRaw == nil {
		return CircuitData{}
	}
	return buildCircuitDataFromShape(*shapeRaw)
}

// buildCircuitDataFromShape builds the fields of CircuitData from the raw shape.
// See [CircuitData] for more details.
func buildCircuitDataFromShape(shape CircuitShapeRaw) CircuitData {
	if len(shape.ColumnLogSizes) != cairo_components.N_TREES {
		panic(fmt.Sprintf("expected %d column trees, got %d", cairo_components.N_TREES, len(shape.ColumnLogSizes)))
	}

	// extract the column log sizes for each tree
	columnLogSizes := make([][]int, len(shape.ColumnLogSizes))
	for i, tree := range shape.ColumnLogSizes {
		columnLogSizes[i] = append([]int(nil), tree...)
	}

	// extract the component config
	var componentConfig ComponentConfig
	if len(shape.ComponentConfig) != len(componentConfig) {
		panic(fmt.Sprintf("expected %d component config entries, got %d", len(componentConfig), len(shape.ComponentConfig)))
	}
	copy(componentConfig[:], shape.ComponentConfig)

	// extract the preprocessed config
	var preprocessedConfig PreprocessedConfig
	if len(shape.PreprocessedConfig) != len(preprocessedConfig) {
		panic(fmt.Sprintf("expected %d preprocessed config entries, got %d", len(preprocessedConfig), len(shape.PreprocessedConfig)))
	}
	copy(preprocessedConfig[:], shape.PreprocessedConfig)

	// extract the deduped queries shape
	dedupedQueriesShape := append([]int(nil), shape.DedupedQueriesShape...)

	// compute the maximum blew up log size
	maxObservedLogSize := 0
	for _, tree := range columnLogSizes {
		for _, logSize := range tree {
			if logSize > maxObservedLogSize {
				maxObservedLogSize = logSize
			}
		}
	}

	bucketLen := len(dedupedQueriesShape)
	if bucketLen == 0 || bucketLen <= maxObservedLogSize {
		bucketLen = maxObservedLogSize + 1
	}

	// compute the number of columns per log size for each tree
	nColumnsPerLogSize := make([][]int, cairo_components.N_TREES)
	for treeIdx := range nColumnsPerLogSize {
		nColumnsPerLogSize[treeIdx] = make([]int, bucketLen)
		for _, logSize := range columnLogSizes[treeIdx] {
			if logSize < 0 {
				panic("log size cannot be negative")
			}
			if logSize >= len(nColumnsPerLogSize[treeIdx]) {
				extended := make([]int, logSize+1)
				copy(extended, nColumnsPerLogSize[treeIdx])
				nColumnsPerLogSize[treeIdx] = extended
			}
			nColumnsPerLogSize[treeIdx][logSize]++
		}
	}

	// compute the unique log sizes
	uniqueLogSizes := make(map[int]struct{})
	for _, tree := range columnLogSizes {
		for _, logSize := range tree {
			uniqueLogSizes[logSize] = struct{}{}
		}
	}

	// blow up the log sizes
	columnBounds := make([]int, 0, len(uniqueLogSizes))
	for logSize := range uniqueLogSizes {
		columnBounds = append(columnBounds, logSize+1)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(columnBounds)))

	return CircuitData{
		ComponentConfig:     componentConfig,
		PreprocessedConfig:  preprocessedConfig,
		ColumnLogSizes:      columnLogSizes,
		ColumnBounds:        columnBounds,
		NColumnsPerLogSize:  nColumnsPerLogSize,
		BoundsLength:        len(uniqueLogSizes),
		DedupedQueriesShape: dedupedQueriesShape,
		MaxLogSize:          uint8(maxObservedLogSize + 1),
	}
}
