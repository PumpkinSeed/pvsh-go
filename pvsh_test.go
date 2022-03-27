package pvsh_test

import (
	"testing"

	"github.com/PumpkinSeed/pvsh-go"

	"github.com/alinush/go-mcl"
)

func TestPVSH(t *testing.T) {
	mcl.InitMclHelper(mcl.BLS12_381)
	mcl.SetETHserialization(false)

	// init
	fp1 := mcl.Fp{}
	fp1.SetInt64(1)
	fp2 := mcl.Fp{}
	fp2.SetInt64(0)

	tmp := mcl.Fp2{D: [2]mcl.Fp{fp1, fp2}}
	var tmpG2 mcl.G2
	mcl.MapToG2(&tmpG2, &tmp)

	// id
	id := mcl.Fr{}
	id.SetByCSPRNG()

	// sk / pk
	sk := mcl.Fr{}
	sk.SetByCSPRNG()

	var pk mcl.G2
	mcl.G2Mul(&pk, &tmpG2, &sk)

	// sh / ph
	sh := mcl.Fr{}
	sh.SetByCSPRNG()

	var ph mcl.G2
	mcl.G2Mul(&ph, &tmpG2, &sh)

	esh, err := pvsh.Encode(id, pk, sh, tmpG2)
	if err != nil {
		t.Fatal(err)
	}
	if err := pvsh.Verify(id, pk, ph, esh, tmpG2); err != nil {
		t.Fatal(err)
	}
	decodedSh, err := pvsh.Decode(id, pk, sk, esh)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("PK: ", string(pk.GetString(16)))
	t.Log("sk: ", string(sk.GetString(16)))
	t.Log("PH: ", string(ph.GetString(16)))
	t.Log("sh: ", string(sh.GetString(16)))
	t.Log("---------------------------------------")
	t.Log("sh': ", sh.GetString(16))
	t.Log("sh' is valid: ", decodedSh.IsEqual(&sh))
	t.Log("ESH: ", esh)

	if !decodedSh.IsEqual(&sh) {
		t.Errorf("Decoded sh isn't the same as original\n\tdecodedSh: %s\n\t       sh: %s", decodedSh.GetString(16), sh.GetString(16))
	}
}
