package database

import (
	"crypto/elliptic"
	"encoding/gob"
	"math/big"
)

func init() {
	gob.RegisterName("crypto/elliptic.p256Curve", &fakeEllipticP256{})
}

// fakeEllipticP256 implements elliptic.Curve.
// This struct is intended to decode the binary that encoded SignedCertificate in Go v1.18 or less.
// Therefore, fakeEllipticP256 must implement elliptic.Curve and is registered to the type map of gob as crypto/elliptic.p256Curve.
type fakeEllipticP256 struct{}

var _ elliptic.Curve = &fakeEllipticP256{}

func (f *fakeEllipticP256) Params() *elliptic.CurveParams {
	//TODO implement me
	panic("implement me")
}

func (f *fakeEllipticP256) IsOnCurve(x, y *big.Int) bool {
	//TODO implement me
	panic("implement me")
}

func (f *fakeEllipticP256) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	//TODO implement me
	panic("implement me")
}

func (f *fakeEllipticP256) Double(x1, y1 *big.Int) (x, y *big.Int) {
	//TODO implement me
	panic("implement me")
}

func (f *fakeEllipticP256) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	//TODO implement me
	panic("implement me")
}

func (f *fakeEllipticP256) ScalarBaseMult(k []byte) (x, y *big.Int) {
	//TODO implement me
	panic("implement me")
}
