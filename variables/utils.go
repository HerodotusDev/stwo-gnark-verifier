package variables

import (
	"math/big"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	// BitsPerM31 is the number of bits in a M31
	BitsPerM31 = 9
	// NM31InFelt252 is the number of M31s in a Felt252
	NM31InFelt252 = 28
)

// ╔══════════════════════════════════╗
// ║              Fixtures            ║
// ╚══════════════════════════════════╝

const (
	// HdpProofFixture : hdp proof
	HdpProofFixture = "hdp_proof.json"
	// AllComponentsProofFixture : uses all the components (good for exhaustive testing)
	AllComponentsProofFixture = "all_components_proof.json"
	// AllComponents1QueryProofFixture : uses all the components with 1 query (good for quick testing)
	AllComponents1QueryProofFixture = "all_components_one_query.json"
)

// ProofFixturePath returns the path to the proof fixture with the given name.
func ProofFixturePath(name string) string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "test_data", name)
}

// ShapeFixturePath returns the path to the circuit shape fixture derived from the proof fixture.
func ShapeFixturePath(name string) string {
	proofPath := ProofFixturePath(name)
	dir := filepath.Dir(proofPath)
	base := filepath.Base(proofPath)
	ext := filepath.Ext(base)
	shapeName := strings.TrimSuffix(base, ext) + "_shape.json"
	return filepath.Join(dir, shapeName)
}

// ╔══════════════════════════════════╗
// ║         Zeroing Variables        ║
// ╚══════════════════════════════════╝

var (
	frontendVariableType = reflect.TypeOf((*frontend.Variable)(nil)).Elem()
	frontendZeroValue    = reflect.ValueOf(frontend.Variable(0))
	m31QM31Type          = reflect.TypeOf(m31.QM31{})
)

func zeroFrontendVariables(value reflect.Value, skipPublicData bool) {
	if !value.IsValid() {
		return
	}
	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() {
			return
		}
		zeroFrontendVariables(value.Elem(), skipPublicData)
	case reflect.Struct:
		valueType := value.Type()
		for i := 0; i < value.NumField(); i++ {
			if skipPublicData && valueType.Field(i).Name == "PublicData" {
				continue
			}
			zeroFrontendVariables(value.Field(i), false)
		}
	case reflect.Interface:
		if value.Type() == frontendVariableType && value.CanSet() {
			value.Set(frontendZeroValue)
		}
	}
}

func zeroInteractionValues(value reflect.Value) {
	if !value.IsValid() {
		return
	}
	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() {
			return
		}
		zeroInteractionValues(value.Elem())
	case reflect.Struct:
		if value.Type() == m31QM31Type && value.CanSet() {
			value.Set(reflect.ValueOf(m31.NewQM31Unchecked(0, 0, 0, 0)))
			return
		}
		for i := 0; i < value.NumField(); i++ {
			zeroInteractionValues(value.Field(i))
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < value.Len(); i++ {
			zeroInteractionValues(value.Index(i))
		}
	}
}

// ╔══════════════════════════════════╗
// ║           Miscellaneous          ║
// ╚══════════════════════════════════╝

var feltChunkMasks = [BitsPerM31 + 1]uints.U32{
	uints.NewU32(0),
	uints.NewU32(1),
	uints.NewU32(3),
	uints.NewU32(7),
	uints.NewU32(15),
	uints.NewU32(31),
	uints.NewU32(63),
	uints.NewU32(127),
	uints.NewU32(255),
	uints.NewU32(511),
}

// SplitFeltWords converts eight 32-bit limbs into NM31InFelt252 M31 limbs with N_BITS_PER_FELT bits each.
func SplitFeltWords(words [8]uint32) Felt252Value {
	// Build the big integer from the limbs
	acc := big.NewInt(0)
	tmp := new(big.Int)
	for i := len(words) - 1; i >= 0; i-- {
		acc.Lsh(acc, 32)
		tmp.SetUint64(uint64(words[i]))
		acc.Or(acc, tmp)
	}

	mask := new(big.Int).Lsh(big.NewInt(1), BitsPerM31)
	mask.Sub(mask, big.NewInt(1))

	// Split the big integer into NM31InFelt252 M31 limbs
	var result Felt252Value
	for i := 0; i < NM31InFelt252; i++ {
		tmp.And(acc, mask)
		result[i] = m31.NewM31Unchecked(tmp.Uint64())
		acc.Rsh(acc, BitsPerM31)
	}

	return result
}

func convertUintSliceToM31(values []uint64) []m31.M31 {
	if len(values) == 0 {
		return nil
	}

	result := make([]m31.M31, len(values))
	for i, v := range values {
		result[i] = m31.NewM31Unchecked(v)
	}
	return result
}

func feltValueToU32Words(value Felt252Value, uapi32 *uints.BinaryField[uints.U32]) [8]uints.U32 {
	const bitsPerWord = 32

	var words [8]uints.U32
	current := uints.NewU32(0)
	bitsFilled := 0
	wordIdx := 0
	limbMask := feltChunkMasks[BitsPerM31]

	for i := 0; i < NM31InFelt252 && wordIdx < len(words); i++ {
		limb := uapi32.And(uapi32.ValueOf(value[i].Limb), limbMask)
		bitsLeft := BitsPerM31
		offset := 0

		for bitsLeft > 0 && wordIdx < len(words) {
			room := bitsPerWord - bitsFilled
			take := bitsLeft
			if take > room {
				take = room
			}

			chunk := limb
			if offset != 0 {
				chunk = uapi32.Rshift(limb, offset)
			}
			chunk = uapi32.And(chunk, feltChunkMasks[take])
			if bitsFilled != 0 {
				chunk = uapi32.Lrot(chunk, bitsFilled)
			}

			current = uapi32.Add(current, chunk)

			bitsLeft -= take
			offset += take
			bitsFilled += take

			if bitsFilled == bitsPerWord {
				words[wordIdx] = current
				wordIdx++
				current = uints.NewU32(0)
				bitsFilled = 0
			}
		}
	}

	if bitsFilled > 0 && wordIdx < len(words) {
		words[wordIdx] = current
	}

	return words
}
