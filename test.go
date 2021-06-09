package main

import (
	"blst/bindings/go"
	"fmt"
	"time"
)

type PublicKey = blst.P1Affine
type Signature = blst.P2Affine
type AggregateSignature = blst.P2Aggregate
type AggregatePublicKey = blst.P1Aggregate

func Shamir_test(n, t, c int) {
	P := make([]server, n+1)
	var U signer
	x, y := Shamir_Keygen(n, t, P, &U)
	for i := 0; i < c; i++ {
		me := blst.Scalar_rand()
		U.message = me
		sig1, sig2 := U.Shamir_Commit(n, t, P)
		Update_u(n, t, P)
		fmt.Println("finished", sig1, sig2, x, y)
		var e1, e2 blst.Fp12
		X2 := blst.P2_mult_x(U.g2, &x)
		Ym := blst.P2_mult_x(U.Y2, U.message)
		blst.Pair(sig1, blst.P2_add(X2, Ym), &e1)
		blst.Pair(sig2, U.g2, &e2)
		fmt.Println(blst.Fp12_eq(&e1, &e2))

	}
}

func Convert_test (n,t,c int){
	t1 := time.Now()
	P := make([]server, n+1)
	var U signer
	x, y := Convert_Keygen(n, t,c, P, &U)
	configtime := time.Since(t1)
	fmt.Println(configtime.Seconds())
	t2 := time.Now()
	for i := 0; i < c; i++ {
		me := blst.Scalar_rand()
		U.message = me
		sig1, sig2 := U.Shamir_Commit(n, t, P)
		Update_u(n, t, P)
		fmt.Println("finished", sig1, sig2, x, y)
		var e1, e2 blst.Fp12
		X2 := blst.P2_mult_x(U.g2, &x)
		Ym := blst.P2_mult_x(U.Y2, U.message)
		blst.Pair(sig1, blst.P2_add(X2, Ym), &e1)
		blst.Pair(sig2, U.g2, &e2)
		fmt.Println(blst.Fp12_eq(&e1, &e2))

	}
 sigtime := time.Since(t2)
 fmt.Println(sigtime.Seconds())
}

func main() {
	Convert_test(10, 3, 3)
}
