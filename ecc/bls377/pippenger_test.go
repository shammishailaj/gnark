package bls377

// git branch experimental/yet-another-pippenger
// Gus's experiments on Pippenger's algorithm

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/consensys/gnark/ecc/bls377/fr"
)

func TestGus549(t *testing.T) {
	curve := BLS377()
	var points []G1Jac
	var scalars []fr.Element
	var got G1Jac
	c := 4

	//
	// Test 1: testPointsG1multiExp
	//
	numPoints, wants := testPointsG1MultiExpResults()

	for i := range numPoints {
		if numPoints[i] > 1e4 {
			continue
		}
		points, scalars = testPointsG1MultiExp(numPoints[i])

		got.Gus549(curve, points, scalars, c)
		if !got.Equal(&wants[i]) {
			t.Error("Gus549 fail for points:", numPoints[i])
		}

		got.Gus549NonStupid(curve, points, scalars, c)
		if !got.Equal(&wants[i]) {
			t.Error("Gus549NonStupid fail for points:", numPoints[i])
		}
	}

	//
	// Test 2: testPointsG1()
	//
	p := testPointsG1()

	// scalars
	s1 := fr.Element{23872983, 238203802, 9827897384, 2372} // 14889285316340551032002176131108485811963550694615991316137431
	s2 := fr.Element{128923, 2878236, 398478, 187970707}    // 1179911251111561301561648964820473185772012989930899737079831459739
	s3 := fr.Element{9038947, 3947970, 29080823, 282739}    // 1774781467561494742381858548177178844765555009630735687022668899

	scalars = []fr.Element{
		s1,
		s2,
		s3,
	}

	got.Gus549(curve, p[17:20], scalars, c)
	if !got.Equal(&p[20]) {
		t.Error("Gus549 failed")
	}

	//
	// Test 3: edge cases
	//

	// one input point p[1]
	scalars[0] = fr.Element{32394, 0, 0, 0} // single-word scalar
	got.Gus549(curve, p[1:2], scalars[:1], c)
	if !got.Equal(&p[6]) {
		t.Error("Gus549 failed, scalar:", scalars[0])
	}

	scalars[0] = fr.Element{2, 0, 0, 0} // scalar = 2
	got.Gus549(curve, p[1:2], scalars[:1], c)
	if !got.Equal(&p[5]) {
		t.Error("Gus549 failed, scalar:", scalars[0])
	}
	scalars[0] = fr.Element{1, 0, 0, 0} // scalar = 1
	got.Gus549(curve, p[1:2], scalars[:1], c)
	if !got.Equal(&p[1]) {
		t.Error("Gus549 failed, scalar:", scalars[0])
	}
	scalars[0] = fr.Element{0, 0, 0, 0} // scalar = 0
	got.Gus549(curve, p[1:2], scalars[:1], c)
	if !got.Equal(&curve.g1Infinity) {
		t.Error("Gus549 failed, scalar:", scalars[0])
	}
	scalars[0] = fr.Element{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)} // scalar == (4-word maxuint)
	got.Gus549(curve, p[1:2], scalars[:1], c)
	if !got.Equal(&p[21]) {
		t.Error("Gus549 failed, scalar:", scalars[0])
	}

	// one input point curve.g1Infinity
	infinity := []G1Jac{curve.g1Infinity}

	scalars[0] = fr.Element{32394, 0, 0, 0} // single-word scalar
	got.Gus549(curve, infinity, scalars[:1], c)
	if !got.Equal(&curve.g1Infinity) {
		t.Error("Gus549 failed, scalar:", scalars[0])
	}
	scalars[0] = fr.Element{2, 0, 0, 0} // scalar = 2
	got.Gus549(curve, infinity, scalars[:1], c)
	if !got.Equal(&curve.g1Infinity) {
		t.Error("Gus549 failed, scalar:", scalars[0])
	}
	scalars[0] = fr.Element{1, 0, 0, 0} // scalar = 1
	got.Gus549(curve, infinity, scalars[:1], c)
	if !got.Equal(&curve.g1Infinity) {
		t.Error("Gus549 failed, scalar:", scalars[0])
	}
	scalars[0] = fr.Element{0, 0, 0, 0} // scalar = 0
	got.Gus549(curve, infinity, scalars[:1], c)
	if !got.Equal(&curve.g1Infinity) {
		t.Error("Gus549 failed, scalar:", scalars[0])
	}
	scalars[0] = fr.Element{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)} // scalar == (4-word maxuint)
	got.Gus549(curve, infinity, scalars[:1], c)
	if !got.Equal(&curve.g1Infinity) {
		t.Error("Gus549 failed, scalar:", scalars[0])
	}

	// two input points: p[1], curve.g1Infinity
	twoPoints := []G1Jac{p[1], curve.g1Infinity}

	scalars[0] = fr.Element{32394, 0, 0, 0} // single-word scalar
	scalars[1] = fr.Element{2, 0, 0, 0}     // scalar = 2
	got.Gus549(curve, twoPoints, scalars[:2], c)
	if !got.Equal(&p[6]) {
		t.Error("Gus549 failed, scalar:", scalars[0])
	}
	scalars[0] = fr.Element{2, 0, 0, 0} // scalar = 2
	scalars[1] = fr.Element{1, 0, 0, 0} // scalar = 1
	got.Gus549(curve, twoPoints, scalars[:2], c)
	if !got.Equal(&p[5]) {
		t.Error("Gus549 failed, scalar:", scalars[0])
	}
	scalars[0] = fr.Element{1, 0, 0, 0} // scalar = 1
	scalars[1] = fr.Element{0, 0, 0, 0} // scalar = 0
	got.Gus549(curve, twoPoints, scalars[:2], c)
	if !got.Equal(&p[1]) {
		t.Error("Gus549 failed, scalar:", scalars[0])
	}
	scalars[0] = fr.Element{0, 0, 0, 0}                                     // scalar = 0
	scalars[1] = fr.Element{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)} // scalar == (4-word maxuint)
	got.Gus549(curve, twoPoints, scalars[:2], c)
	if !got.Equal(&curve.g1Infinity) {
		t.Error("Gus549 failed, scalar:", scalars[0])
	}
	scalars[0] = fr.Element{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)} // scalar == (4-word maxuint)
	scalars[1] = fr.Element{32394, 0, 0, 0}                                 // single-word scalar
	got.Gus549(curve, twoPoints, scalars[:2], c)
	if !got.Equal(&p[21]) {
		t.Error("Gus549 failed, scalar:", scalars[0])
	}

	// TODO: Jacobian points with nontrivial Z coord?
}

//--------------------//
//     benches		  //
//--------------------//

func BenchmarkGus549(b *testing.B) {

	fmt.Println("GOMAXPROCS was", runtime.GOMAXPROCS(1))

	curve := BLS377()
	numPoints, _ := testPointsG1MultiExpResults()
	var exp G1Jac
	cs := [...]int{8}

	for j := range numPoints {
		points, scalars := testPointsG1MultiExp(numPoints[j])

		for _, c := range cs {
			b.Run(fmt.Sprintf("%d-Gus549-%d", numPoints[j], c), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					exp.Gus549(curve, points, scalars, c)
				}
			})
		}

		b.Run(fmt.Sprintf("%d-multiExp", numPoints[j]), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				exp.multiExp(curve, points, scalars)
			}
		})

		// MultiExp takes affine points, not Jacobian points
		pointsAffine := make([]G1Affine, len(points))
		for k := range pointsAffine {
			points[k].ToAffineFromJac(&pointsAffine[k])
		}

		b.Run(fmt.Sprintf("%d-MultiExp", numPoints[j]), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				<-exp.MultiExp(curve, pointsAffine, scalars)
			}
		})

	}
}

func BenchmarkGus549NonStupid(b *testing.B) {

	fmt.Println("GOMAXPROCS was", runtime.GOMAXPROCS(1))

	curve := BLS377()
	numPoints, _ := testPointsG1MultiExpResults()
	var exp G1Jac
	cs := [...]int{8}

	for j := range numPoints {
		points, scalars := testPointsG1MultiExp(numPoints[j])

		for _, c := range cs {
			b.Run(fmt.Sprintf("%d-Gus549-%d", numPoints[j], c), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					exp.Gus549(curve, points, scalars, c)
				}
			})
			b.Run(fmt.Sprintf("%d-Gus549NonStupid-%d", numPoints[j], c), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					exp.Gus549NonStupid(curve, points, scalars, c)
				}
			})
		}
	}
}
