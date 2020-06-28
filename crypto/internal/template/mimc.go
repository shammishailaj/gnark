package template

const Encrypt = `

{{ define "encrypt" }}

{{ if eq .Curve "BN256" }}
	// plain execution of a mimc run
	// m: message
	// k: encryption key
	func (d *digest) encrypt(m fr.Element) {

		for _, cons := range d.Params {
			// m = (m+k+c)^7
			var tmp fr.Element
			tmp.Add(&m, &d.h).Add(&tmp, &cons)
			m.Square(&tmp).
				Mul(&m, &tmp).
				Square(&m).
				Mul(&m, &tmp)
		}
		m.Add(&m, &d.h)
		d.h = m
	}
{{ else if eq .Curve "BLS381" }}
	// plain execution of a mimc run
	// m: message
	// k: encryption key
	func (d *digest) encrypt(m fr.Element) {

		for _, cons := range d.Params {
			// m = (m+k+c)^7
			var tmp fr.Element
			tmp.Add(&m, &d.h).Add(&tmp, &cons)
			m.Square(&tmp).
				Square(&m).
				Mul(&m, &tmp)
		}
		m.Add(&m, &d.h)
		d.h = m
	}
{{ else if eq .Curve "BLS377" }}
	// plain execution of a mimc run
	// m: message
	// k: encryption key
	func (d *digest) encrypt(m fr.Element) {

		for _, cons := range d.Params {
			// m = (m+k+c)^7
			m.Add(&m, &d.h).Add(&m, &cons).Inverse(&m)
		}
		m.Add(&m, &d.h)
		d.h = m
	}
{{end}}

{{end}}

`

const MimcPerCurve = `

{{ define "mimc_custom" }}

{{ if eq .Curve "BN256" }}
	import (
		"encoding/binary"
		"hash"
		"math/big"

		"github.com/consensys/gurvy/bn256/fr"
		"golang.org/x/crypto/sha3"
	)

	const mimcNbRounds = 91

	// BlockSize size that mimc consumes
	const BlockSize = 32

	// Params constants for the mimc hash function
	type Params []fr.Element

	// NewParams creates new mimc object
	func NewParams(seed string) Params {

		// set the constants
		res := make(Params, mimcNbRounds)

		rnd := sha3.Sum256([]byte(seed))
		value := new(big.Int).SetBytes(rnd[:])

		for i := 0; i < mimcNbRounds; i++ {
			rnd = sha3.Sum256(value.Bytes())
			value.SetBytes(rnd[:])
			res[i].SetBigInt(value)
		}

		return res
	}
{{ else if eq .Curve "BLS377" }}
	import (
		"encoding/binary"
		"hash"
		"math/big"

		"github.com/consensys/gurvy/bls377/fr"
		"golang.org/x/crypto/sha3"
	)

	const mimcNbRounds = 91

	// BlockSize size that mimc consumes
	const BlockSize = 32

	// Params constants for the mimc hash function
	type Params []fr.Element

	// NewParams creates new mimc object
	func NewParams(seed string) Params {

		// set the constants
		res := make(Params, mimcNbRounds)

		rnd := sha3.Sum256([]byte(seed))
		value := new(big.Int).SetBytes(rnd[:])

		for i := 0; i < mimcNbRounds; i++ {
			rnd = sha3.Sum256(value.Bytes())
			value.SetBytes(rnd[:])
			res[i].SetBigInt(value)
		}

		return res
	}
{{ else if eq .Curve "BLS381" }}
	import (
		"encoding/binary"
		"hash"
		"math/big"

		"github.com/consensys/gurvy/bls381/fr"
		"golang.org/x/crypto/sha3"
	)

	const mimcNbRounds = 91

	// BlockSize size that mimc consumes
	const BlockSize = 32

	// Params constants for the mimc hash function
	type Params []fr.Element

	// NewParams creates new mimc object
	func NewParams(seed string) Params {

		// set the constants
		res := make(Params, mimcNbRounds)

		rnd := sha3.Sum256([]byte(seed))
		value := new(big.Int).SetBytes(rnd[:])

		for i := 0; i < mimcNbRounds; i++ {
			rnd = sha3.Sum256(value.Bytes())
			value.SetBytes(rnd[:])
			res[i].SetBigInt(value)
		}

		return res
	}
{{end}}

{{end}}
`

const MimcCommon = `

{{ template "mimc_custom" . }}

// digest represents the partial evaluation of the checksum
// along with the params of the mimc function
type digest struct {
	Params Params
	h      fr.Element
	data   []byte // data to hash
}

// NewMiMC returns a MiMCImpl object, pure-go reference implementation
func NewMiMC(seed string) hash.Hash {
	d := new(digest)
	params := NewParams(seed)
	//d.Reset()
	d.Params = params
	d.Reset()
	return d
}

// Reset resets the Hash to its initial state.
func (d *digest) Reset() {
	d.data = nil
	d.h = fr.Element{0, 0, 0, 0}
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (d *digest) Sum(b []byte) []byte {
	buffer := d.checksum()
	d.data = nil // flush the data already hashed
	hash := buffer.Bytes()
	b = append(b, hash[:]...)
	return b
}

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (d *digest) Size() int {
	return BlockSize
}

// BlockSize returns the number of bytes Sum will return.
func (d *digest) BlockSize() int {
	return BlockSize
}

// Write (via the embedded io.Writer interface) adds more data to the running hash.
// It never returns an error.
func (d *digest) Write(p []byte) (n int, err error) {
	n = len(p)
	d.data = append(d.data, p...)
	return
}

// Hash hash using Miyaguchi–Preneel:
// https://en.wikipedia.org/wiki/One-way_compression_function
// The XOR operation is replaced by field addition, data is in Montgomery form
func (d *digest) checksum() fr.Element {

	var buffer [32]byte
	var x fr.Element

	// if data size is not multiple of BlockSizes we padd:
	// .. || 0xaf8 -> .. || 0x0000...0af8
	if len(d.data)%BlockSize != 0 {
		q := len(d.data) / BlockSize
		r := len(d.data) % BlockSize
		sliceq := make([]byte, q*BlockSize)
		copy(sliceq, d.data)
		slicer := make([]byte, r)
		copy(slicer, d.data[q*BlockSize:])
		sliceremainder := make([]byte, BlockSize-r)
		d.data = append(sliceq, sliceremainder...)
		d.data = append(d.data, slicer...)
	}

	if len(d.data) == 0 {
		d.data = make([]byte, 32)
	}

	nbChunks := len(d.data) / BlockSize

	for i := 0; i < nbChunks; i++ {
		copy(buffer[:], d.data[i*BlockSize:(i+1)*BlockSize])
		x.SetBytes(buffer[:])
		d.encrypt(x)
		d.h.Add(&x, &d.h)
	}

	return d.h
}

{{ template "encrypt" . }}

// Sum computes the mimc hash of msg from seed
func Sum(seed string, msg []byte) []byte {
	params := NewParams(seed)
	var d digest
	d.Params = params
	d.Write(msg)
	h := d.checksum()
	return h.Bytes()
}
`
