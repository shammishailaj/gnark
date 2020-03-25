/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by gnark/internal/generators DO NOT EDIT

package groth16

import (
	curve "github.com/consensys/gurvy/bls381"
	"github.com/consensys/gurvy/bls381/fr"

	"github.com/consensys/gnark/backend/static/bls381"

	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	constants "github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/internal/utils/encoding/gob"

	"reflect"

	"github.com/stretchr/testify/require"
)

func TestCircuits(t *testing.T) {
	assert := NewAssert(t)

	matches, err := filepath.Glob("../../../../backend/groth16/testdata/" + strings.ToLower(curve.ID.String()) + "/*.r1cs")

	if err != nil {
		t.Fatal(err)
	}

	if len(matches) == 0 {
		t.Fatal("couldn't find test circuits for", curve.ID.String())
	}
	for _, name := range matches {
		name = name[:len(name)-5]
		t.Log(curve.ID.String(), " -- ", filepath.Base(name))

		good := backend.NewAssignment()
		if err := good.ReadFile(name + ".good"); err != nil {
			t.Fatal(err)
		}
		bad := backend.NewAssignment()
		if err := bad.ReadFile(name + ".bad"); err != nil {
			t.Fatal(err)
		}
		var r1cs backend.R1CS

		if err := gob.Read(name+".r1cs", &r1cs, curve.ID); err != nil {
			t.Fatal(err)
		}
		assert.NotSolved(&r1cs, bad)
		assert.Solved(&r1cs, good, nil)
	}
}

func TestParsePublicInput(t *testing.T) {

	expectedNames := [2]string{"data", "ONE_WIRE"}

	inputOneWire := backend.NewAssignment()
	inputOneWire.Assign(constants.Public, "ONE_WIRE", 3)
	if _, err := parsePublicInput(expectedNames[:], inputOneWire); err == nil {
		t.Fatal("expected ErrMissingAssigment error")
	}

	inputPrivate := backend.NewAssignment()
	inputPrivate.Assign(constants.Secret, "data", 3)
	if _, err := parsePublicInput(expectedNames[:], inputPrivate); err == nil {
		t.Fatal("expected ErrMissingAssigment error")
	}

	missingInput := backend.NewAssignment()
	if _, err := parsePublicInput(expectedNames[:], missingInput); err == nil {
		t.Fatal("expected ErrMissingAssigment")
	}

	correctInput := backend.NewAssignment()
	correctInput.Assign(constants.Public, "data", 3)
	got, err := parsePublicInput(expectedNames[:], correctInput)
	if err != nil {
		t.Fatal(err)
	}

	expected := make([]fr.Element, 2)
	expected[0].SetUint64(3).FromMont()
	expected[1].SetUint64(1).FromMont()
	if len(got) != len(expected) {
		t.Fatal("Unexpected length for assignment")
	}
	for i := 0; i < len(got); i++ {
		if !got[i].Equal(&expected[i]) {
			t.Fatal("error public assignment")
		}
	}

}

//--------------------//
//     benches		  //
//--------------------//

func referenceCircuit() (backend.R1CS, backend.Assignments, backend.Assignments) {

	name := "../../../../backend/groth16/testdata/" + strings.ToLower(curve.ID.String()) + "/reference_large"

	good := backend.NewAssignment()
	if err := good.ReadFile(name + ".good"); err != nil {
		panic(err)
	}
	bad := backend.NewAssignment()
	if err := bad.ReadFile(name + ".bad"); err != nil {
		panic(err)
	}
	var r1cs backend.R1CS

	if err := gob.Read(name+".r1cs", &r1cs, curve.ID); err != nil {
		panic(err)
	}

	return r1cs, good, bad
}

// BenchmarkSetup is a helper to benchmark Setup on a given circuit
func BenchmarkSetup(b *testing.B) {
	r1cs, _, _ := referenceCircuit()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	var pk ProvingKey
	var vk VerifyingKey
	b.ResetTimer()

	b.Run("setup", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Setup(&r1cs, &pk, &vk)
		}
	})
}

// BenchmarkProver is a helper to benchmark Prove on a given circuit
// it will run the Setup, reset the benchmark timer and benchmark the prover
func BenchmarkProver(b *testing.B) {
	r1cs, solution, _ := referenceCircuit()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	var pk ProvingKey
	var vk VerifyingKey
	Setup(&r1cs, &pk, &vk)

	b.ResetTimer()
	b.Run("prover", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = Prove(&r1cs, &pk, solution)
		}
	})
}

// BenchmarkVerifier is a helper to benchmark Verify on a given circuit
// it will run the Setup, the Prover and reset the benchmark timer and benchmark the verifier
// the provided solution will be filtered to keep only public inputs
func BenchmarkVerifier(b *testing.B) {
	r1cs, solution, _ := referenceCircuit()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	var pk ProvingKey
	var vk VerifyingKey
	Setup(&r1cs, &pk, &vk)
	proof, err := Prove(&r1cs, &pk, solution)
	if err != nil {
		panic(err)
	}

	solution = solution.DiscardSecrets()
	b.ResetTimer()
	b.Run("verifier", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = Verify(proof, &vk, solution)
		}
	})
}

// assert helpers

// Assert is a helper to test circuits
// it embeds a frontend.Assert object (see gnark/cs/assert)
type Assert struct {
	*require.Assertions
}

// NewAssert returns an Assert helper
func NewAssert(t *testing.T) *Assert {
	return &Assert{require.New(t)}
}

// NotSolved check that a solution does NOT solve a circuit
// error may be missing inputs or unsatisfied constraints
// it runs frontend.Assert.NotSolved and ensure running groth16.Prove and groth16.Verify doesn't return true
func (assert *Assert) NotSolved(r1cs *backend.R1CS, solution backend.Assignments) {
	// setup

	var pk ProvingKey
	var vk VerifyingKey
	Setup(r1cs, &pk, &vk)

	// prover
	_, err := Prove(r1cs, &pk, solution)
	assert.Error(err, "proving with bad solution should output an error")
}

// Solved check that a solution solves a circuit
// for each expectedValues, this helper compares the output from backend.Inspect() after Solving.
// this helper also ensure the result vectors a*b=c
// it runs frontend.Assert.Solved and ensure running groth16.Prove and groth16.Verify returns true
func (assert *Assert) Solved(r1cs *backend.R1CS, solution backend.Assignments, expectedValues map[string]interface{}) {
	// setup

	var pk ProvingKey
	var vk VerifyingKey
	Setup(r1cs, &pk, &vk)

	// ensure random sampling; calliung setup twice should produce != pk and vk
	{
		var pk2 ProvingKey
		var vk2 VerifyingKey
		Setup(r1cs, &pk2, &vk2)

		assert.False(pk.G1.Alpha.Equal(&pk2.G1.Alpha), "groth16 setup with same input should produce different outputs (alpha)")
		assert.False(pk.G1.Beta.Equal(&pk2.G1.Beta), "groth16 setup with same input should produce different outputs (beta)")
		assert.False(pk.G1.Delta.Equal(&pk2.G1.Delta), "groth16 setup with same input should produce different outputs (delta)")

		for i := 0; i < len(pk.G1.K); i++ {
			if !pk.G1.K[i].IsInfinity() {
				assert.False(pk.G1.K[i].Equal(&pk2.G1.K[i]), "groth16 setup with same input should produce different outputs (pk.K)")
			}
		}

		for i := 0; i < len(vk.G1.K); i++ {
			if !vk.G1.K[i].IsInfinity() {
				assert.False(vk.G1.K[i].Equal(&vk2.G1.K[i]), "groth16 setup with same input should produce different outputs (vk.K)")
			}
		}
	}

	// prover
	proof, err := Prove(r1cs, &pk, solution)
	assert.Nil(err, "proving with good solution should not output an error")

	// ensure random sampling; calling prove twice with same input should produce different proof
	{
		proof2, err := Prove(r1cs, &pk, solution)
		assert.Nil(err, "proving with good solution should not output an error")
		assert.False(reflect.DeepEqual(proof, proof2), "calling prove twice with same input should produce different proof")
	}

	// verifier
	{
		isValid, err := Verify(proof, &vk, solution.DiscardSecrets())
		assert.Nil(err, "verifying proof with good solution should not output an error")
		assert.True(isValid, "unexpected Verify(proof) result")
	}
}
