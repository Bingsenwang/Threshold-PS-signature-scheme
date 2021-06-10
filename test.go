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

func Shamir_test(n, t, c int) (float64,float64) {
	t1 := time.Now()
	P := make([]server, n+1)
	var U signer
	x, y := Shamir_Keygen(n, t, P, &U)
	configtime := time.Since(t1)
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
	return (float64)(configtime.Seconds()),(float64)(sigtime.Seconds())
}

func Convert_test (n,t,c int) (float64,float64) {
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
	return (float64)(configtime.Seconds()),(float64)(sigtime.Seconds())
}

func Rep_test(n,t,c int)(float64,float64) {
	t1 := time.Now()
	P := make([]server, n+1)
	var U signer
	x, y := Rep_Keygen(n, t, P, &U)
	configtime := time.Since(t1)
	fmt.Println(configtime.Seconds())
	t2 := time.Now()
	for i := 0; i < c; i++ {
		me := blst.Scalar_rand()
		U.message = me
		sig1, sig2 := U.Rep_Commit(n, t, P)
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
	return (float64)(configtime.Seconds()),(float64)(sigtime.Seconds())
}

func main() {
	//t := 1;
	tres := 200.0

/*
	res1 := make([][2]float64, 1000)
	res2 := make([][2]float64, 1000)
	res3 := make([][2]float64, 1000)
	for t = 1; t <= 30; t++ {
		con, sig := Rep_test(t*3+1, t, 5)
		res1[t][0] = con
		res1[t][1] = sig
		if con > tres || sig > tres {
			break
		}
	}

	for t = 1; t <= 30; t++ {
		con, sig := Shamir_test(t*3+1, t, 5)
		res2[t][0] = con
		res2[t][1] = sig
		if con > tres || sig > tres {
			break
		}
	}
	for t = 1; t <= 30; t++ {
		con, sig := Convert_test(t*3+1, t, 5)
		res3[t][0] = con
		res3[t][1] = sig
		if con > tres || sig > tres {
			break
		}
	} */
	res41 := make([]float64,1000000)
	res42 := make([]float64,1000000)
	res51 := make([]float64,1000000)
	res52 := make([]float64,1000000)
	res61 := make([]float64,1000000)
	res62 := make([]float64,1000000)
	for i := 1; i <= 10000000; i = i * 2 {
		con, sig := Rep_test(7, 2, i)
		res41[i] = con
		res42[i] = sig
		if con > tres || sig > tres {
			break
		}
	}
	for i := 1; i <= 10000000; i = i * 2 {
		con, sig := Shamir_test(7, 2, i)
		res51[i] = con
		res52[i] = sig
		if con > tres || sig > tres {
			break
		}
	}

	for i := 1; i <= 10000000; i = i * 2 {
		con, sig := Convert_test(7, 2, i)
		res61[i] = con
		res62[i] = sig
		if con > tres || sig > tres {
			break
		}
	}






/*
	t = 50
	fmt.Println("rep")
	for i := 0; i <= t; i++ {
		fmt.Println("(", i*3+1, ",", res1[i][0]/(float64)(i+1), ")")
	}
	fmt.Println("rep")
	for i := 0; i <= t; i++ {
		fmt.Println("(", i*3+1, ",", res1[i][1]/(float64)(i+1), ")")
	}
	fmt.Println("sha")
	for i := 0; i <= t; i++ {
		fmt.Println("(", i*3+1, ",", res2[i][0]/(float64)(i+1), ")")
	}
	fmt.Println("sha")
	for i := 0; i <= t; i++ {
		fmt.Println("(", i*3+1, ",", res2[i][1]/(float64)(i+1), ")")
	}
	fmt.Println("con")
	for i := 0; i <= t; i++ {
		fmt.Println("(", i*3+1, ",", res3[i][0]/(float64)(i+1), ")")
	}
	fmt.Println("con")
	for i := 0; i <= t; i++ {
		fmt.Println("(", i*3+1, ",", res3[i][1]/(float64)(i+1), ")")
	} */

	fmt.Println("rep")

	for i:=1;i<=1000000;i=i*2 {
		t:=res41[i]
		fmt.Println("(", i*3+1, ",", t/(float64)(7), ")")
	}
	fmt.Println("rep")
	for i:=1;i<=1000000;i=i*2 {
		t:=res42[i]
		fmt.Println("(", i*3+1, ",", t/(float64)(7), ")")
	}

	fmt.Println("sha")

	for i:=1;i<=1000000;i=i*2 {
		t:=res51[i]
		fmt.Println("(", i*3+1, ",", t/(float64)(7), ")")
	}
	fmt.Println("sha")
	for i:=1;i<=1000000;i=i*2{
		t:= res52[i]
		fmt.Println("(", i*3+1, ",", t/(float64)(7), ")")
	}

	fmt.Println("con")
	for  i:=1;i<=1000000;i=i*2 {
		t := res61[i]
		fmt.Println("(", i*3+1, ",", t/(float64)(7), ")")
	}
	fmt.Println("con")
	for i:=1;i<=1000000;i=i*2 {
		t := res62[i]
		fmt.Println("(", i*3+1, ",", t/(float64)(7), ")")

	}
}
