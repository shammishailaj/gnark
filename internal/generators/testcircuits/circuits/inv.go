package circuits

func init() {
	// TODO inv here
	//fmt.Println("init inv")
	// circuit := frontend.New()

	// x := circuit.SECRET_INPUT("x")
	// y := circuit.PUBLIC_INPUT("y")
	// m := circuit.MUL(x, x)
	// z := circuit.INV(m)
	// circuit.MUSTBE_EQ(y, z)

	// // expected z
	// expectedY := fr.Element{}
	// expectedY.SetUint64(4)
	// expectedY.MulAssign(&expectedY).Inverse(&expectedY)

	// good := backend.NewAssignment()
	// good.Assign(backend.Secret, "x", 4)
	// good.Assign(backend.Public, "y", expectedY)

	// bad := backend.NewAssignment()
	// bad.Assign(backend.Secret, "x", 4)
	// bad.Assign(backend.Public, "y", 42)

	// r1cs := circuit.ToR1CS()

	// addEntry("inv", r1cs, good, bad)
}
