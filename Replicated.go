package main

import (
	"blst/bindings/go"
	"fmt"
	"math/bits"
)

type server struct {
	n,t,id,ui int
	a *blst.P1Affine
	rx *map[int]blst.Scalar
	rK *map[int]blst.Scalar
	ru *map[int]blst.Scalar
	Ru []blst.Scalar
	g1 *blst.P1Affine
	g2 *blst.P2Affine
}
type sig struct {
	sig1 *blst.P1Affine
	sig2 *blst.P1Affine
}

type signer struct {
	XT        *map[int]blst.P2Affine
	Y1        *blst.P1Affine
	Y2        *blst.P2Affine
	message   *blst.Scalar
	signature *sig
	g1        *blst.P1Affine
	g2        *blst.P2Affine
}

func Rep_Keygen(n, t int, P []server, U *signer) (blst.Scalar, blst.Scalar) {
	g1, g2 := blst.P1_generator(), blst.P2_generator()
	y := blst.Scalar_rand()
	rx, x := Generate_rep_share(n, t)
	rK, K := Generate_rep_share(n, t)
	for i := 1; i <= n; i++ {
		rxi, rKi := rep_share_for_i(i, rx, rK)
		P[i].rx = &rxi
		P[i].rK = &rKi
		P[i].g1 = g1
		P[i].g2 = g2
		P[i].id = i
		P[i].n=n
		P[i].t=t
	}
	X := make(map[int]blst.P2Affine)
	for T, v := range rx {
		X[T] = *blst.P2_mult_x(g2, &v)
	}
	(*U).XT = &X
	(*U).Y2 = blst.P2_mult_x(g2, y)
	(*U).Y1 = blst.P1_mult_x(g1, y)
	(*U).g1 = g1
	(*U).g2 = g2
	fmt.Println("secret key:")
	fmt.Println(x)
	fmt.Println("key for PRF:")
	fmt.Println(K)
	return x, *y
}

func (Pj *server) Rep_Sign(C *blst.P1Affine, T1, T2 int) (*blst.P1Affine, *blst.P1Affine, *blst.P1Affine) {
	if M_u_s_include(Pj.id, T1) || M_u_s_include(Pj.id, T2) {
		fmt.Println("error!")
	}

	rk := (*(Pj.rK))[T1]
	rx1 := (*(Pj.rx))[T2]
	rTu := PRF_1(C, &rk)
	a := blst.P1_mult_x(Pj.g1, rTu)
	b := blst.P1_mult_x(blst.P1_mult_x(Pj.g1, &rx1), rTu)
	c := blst.P1_mult_x(C, rTu)
	fmt.Println(T1, T2)
	fmt.Println("partial_sig_finished")

	return a, b, c

}

func (U *signer) Rep_Commit(n, t int, P []server) (*blst.P1Affine, *blst.P1Affine) {
	A, B, C := blst.P1_zero(), blst.P1_zero(), blst.P1_zero()
	flg := false
	w := blst.Scalar_rand()
	Commit := blst.P1_add(blst.P1_mult_x(U.g1, w), blst.P1_mult_x(U.Y1, U.message))
	for T1 := range *(U.XT) {
		flg = false
		for T2, v := range *(U.XT) {
			for i := 1; i <= 2*t+1; i++ {
				if M_u_s_include(i, T1) || M_u_s_include(i, T2) {
					continue
				}
				a, b, c := (&P[i]).Rep_Sign(Commit, T1, T2)

				che := blst.Check(a,
					blst.P1_add(blst.P1_mult_x(a, blst.Scalar_neg(w)), blst.P1_add(b, c)),
					blst.P2_add(&v, blst.P2_mult_x(U.Y2, U.message)),
					U.g2)
				fmt.Println("partial signature correct", che)
				if !flg {
					flg = true
					A = blst.P1_add(a, A)
					C = blst.P1_add(c, C)
				}
				B = blst.P1_add(b, B)
				break
			}
			if !flg {
				fmt.Println(T1, T2, "mistake!!!!!!!!!!!!!!!!!!")
			}
		}
	}

	sig2 := blst.P1_add(B, C)
	sig2 = blst.P1_add(sig2, blst.P1_mult_x(A, blst.Scalar_neg(w)))
	return A, sig2
}

func rep_share_for_i(i int, rx, rK map[int]blst.Scalar) (map[int]blst.Scalar, map[int]blst.Scalar) {
	rxi := make(map[int]blst.Scalar)
	rKi := make(map[int]blst.Scalar)
	for T, v := range rx {
		if !M_u_s_include(i, T) {
			rxi[T] = v
		}
	}
	for T, v := range rK {
		if !M_u_s_include(i, T) {
			rKi[T] = v
		}
	}
	return rxi, rKi
}

func number_of_T(T int) int {
	return bits.OnesCount(uint(T))
}

func Generate_rep_share(n, t int) (map[int]blst.Scalar, blst.Scalar) {
	rt := make(map[int]blst.Scalar)
	sum := *blst.Scalar_zero()
	for i := 1; i < (1 << n); i++ {
		if number_of_T(i) != t {
			continue
		}
		rtn := *(blst.Scalar_rand())
		sum = *blst.Scalar_add(&sum, &rtn)
		rt[i] = rtn
	}
	return rt, sum
}

func PRF_1(C *blst.P1Affine, x *blst.Scalar) *blst.Scalar {
	c := blst.P1_2_scalar(C)
	rt := blst.Scalar_mul(c, x)
	return rt
}

func PRF_2(C *blst.P2Affine, x *blst.Scalar) *blst.Scalar {
	c := blst.P2_2_scalar(C)
	rt := blst.Scalar_mul(c, x)
	return rt
}

func M_u_s_include(i, T int) bool {
	return (1<<(i-1))&(T) > 0
}

