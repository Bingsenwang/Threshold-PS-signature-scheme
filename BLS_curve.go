package blst

// #cgo CFLAGS: -I${SRCDIR}/.. -I${SRCDIR}/../../build -I${SRCDIR}/../../src -D__BLST_CGO__
// #cgo amd64 CFLAGS: -D__ADX__ -mno-avx
// #include "blst.h"
import "C"
import (
	"crypto/rand"
)

//
// Configuration
//
func Int_2_scalar(i int) *Scalar {
	if i == 0 {
		return Scalar_zero()
	}
	if i == 1 {
		return Scalar_one()
	}
	return Scalar_add(Int_2_scalar(i/2), Int_2_scalar(i-i/2))
}

func Scalar_sub(a, b *Scalar) *Scalar {
	return Scalar_add(a, Scalar_neg(b))
}

func P1_2_scalar(a *P1Affine) *Scalar {
	var A C.blst_p1
	C.blst_p1_from_affine(&A, a)
	var byts [96]C.byte
	C.blst_p1_serialize((*C.byte)(&byts[0]), &A)
	var rt Scalar
	C.blst_scalar_from_bendian(&rt, (*C.byte)(&byts[0]))
	return &rt
}

func P2_2_scalar(a *P2Affine) *Scalar {
	var A C.blst_p2
	C.blst_p2_from_affine(&A, a)
	var byts [196]C.byte
	C.blst_p2_serialize((*C.byte)(&byts[0]), &A)
	var rt Scalar
	C.blst_scalar_from_bendian(&rt, (*C.byte)(&byts[0]))
	return &rt
}

func Scalar_div(a, b *Scalar) *Scalar {
	return Scalar_mul(a, Scalar_inv(b))
}

func Scalar_rand() *Scalar {
	var ikm [32]byte
	_, _ = rand.Read(ikm[:])
	var rt Scalar
	rt = *(KeyGen(ikm[:]))
	return &rt
}
func Scalar_zero() *Scalar {
	var rt Scalar
	rt = *Scalar_add(&rt, Scalar_neg(&rt))
	return &rt
}
func Scalar_one() *Scalar {
	rt := Scalar_rand()
	rt = Scalar_mul(rt, Scalar_inv(rt))
	return rt
}

func Scalar_minus() *Scalar {
	return Scalar_neg(Scalar_one())
}

func Scalar_neg(a *Scalar) *Scalar {
	var A, C C.blst_fr
	C.blst_fr_from_scalar(&A, a)
	C.blst_fr_from_scalar(&C, a)
	C.blst_fr_sub(&C, &C, &A)
	C.blst_fr_sub(&C, &C, &A)
	var rt Scalar
	C.blst_scalar_from_fr(&rt, &C)
	return &rt
}

func Scalar_inv(a *Scalar) *Scalar {
	var A, C C.blst_fr
	C.blst_fr_from_scalar(&A, a)
	C.blst_fr_eucl_inverse(&C, &A)
	var rt Scalar
	C.blst_scalar_from_fr(&rt, &C)
	return &rt
}

func Scalar_mul(a, b *Scalar) *Scalar {
	var A, B, C C.blst_fr
	C.blst_fr_from_scalar(&A, a)
	C.blst_fr_from_scalar(&B, b)
	C.blst_fr_mul(&C, &A, &B)
	var rt Scalar
	C.blst_scalar_from_fr(&rt, &C)
	return &rt
}

func Scalar_add(a, b *Scalar) *Scalar {
	var A, B, C C.blst_fr
	C.blst_fr_from_scalar(&A, a)
	C.blst_fr_from_scalar(&B, b)
	C.blst_fr_add(&C, &A, &B)
	var rt Scalar
	C.blst_scalar_from_fr(&rt, &C)
	return &rt
}

func P1_add(a, b *P1Affine) *P1Affine {
	var b1, b2, c P1
	var rt P1Affine
	C.blst_p1_from_affine(&b1, a)
	C.blst_p1_from_affine(&b2, b)
	C.blst_p1_add(&c, &b1, &b2)
	C.blst_p1_to_affine(&rt, &c)
	return &rt
}

func P2_add(a, b *P2Affine) *P2Affine {
	var b1, b2, c P2
	var rt P2Affine
	C.blst_p2_from_affine(&b1, a)
	C.blst_p2_from_affine(&b2, b)
	C.blst_p2_add(&c, &b1, &b2)
	C.blst_p2_to_affine(&rt, &c)
	return &rt
}

func P1_generator() *P1Affine {
	rt := C.blst_p1_affine_generator()
	var b P1Affine
	b = *rt
	return &b
}

func Check(a, c *P1Affine, b, d *P2Affine) bool {
	var e1, e2 Fp12
	Pair(a, b, &e1)
	Pair(c, d, &e2)
	return (bool)(Fp12_eq(&e1, &e2))
}

func P2_generator() *P2Affine {
	rt := C.blst_p2_affine_generator()
	var b P2Affine
	b = *rt
	return &b
}

func P1_zero() *P1Affine {
	rt := P1_generator()
	rt = P1_add(rt, P1_mult_x(rt, Scalar_minus()))
	return rt
}

func P2_zero() *P2Affine {
	rt := P2_generator()
	rt = P2_add(rt, P2_mult_x(rt, Scalar_minus()))
	return rt
}

func P1_mult_x(h *P1Affine, x *Scalar) *P1Affine {
	var b P1
	C.blst_p1_from_affine(&b, h)
	var c P1
	C.blst_sign_pk_in_g2(&c, &b, x)
	var rt P1Affine
	C.blst_p1_to_affine(&rt, &c)
	return &rt
}

func P2_mult_x(h *P2Affine, x *Scalar) *P2Affine {
	var b P2
	C.blst_p2_from_affine(&b, h)
	var c P2
	C.blst_sign_pk_in_g1(&c, &b, x)
	var rt P2Affine
	C.blst_p2_to_affine(&rt, &c)
	return &rt
}

func M_encode(m Message) *Scalar {
	var rt Scalar
	C.blst_scalar_from_lendian(&rt, (*C.byte)(&m[0]))
	return &rt
}

func Pair(a *P1Affine, b *P2Affine, rt *Fp12) {
	C.blst_miller_loop(rt, b, a)
	C.blst_final_exp(rt, rt)
}

func P1_double(a *P1Affine) {
	var b P1
	C.blst_p1_from_affine(&b, a)
	var c P1
	C.blst_p1_double(&c, &b)
	C.blst_p1_to_affine(a, &c)
}

func P2_double(a *P2Affine) {
	var b P2
	C.blst_p2_from_affine(&b, a)
	var c P2
	C.blst_p2_double(&c, &b)
	C.blst_p2_to_affine(a, &c)
}

func Fp12_double(a *Fp12) {
	C.blst_fp12_sqr(a, a)
}

func Fp12_eq(a *Fp12, b *Fp12) C.bool {
	return C.blst_fp12_is_equal(a, b)
}
