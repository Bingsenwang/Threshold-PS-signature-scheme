package main

import (
	blst "blst/bindings/go"
)

func Convert_Keygen(n, t, c int, P []server, U *signer) (blst.Scalar, blst.Scalar) {
	g1, g2 := blst.P1_generator(), blst.P2_generator()
	y := blst.Scalar_rand()
	rx, x := Generate_shamir_share(n, t)
	ru, _ := Generate_shamir_share(n, t)
	rK, _ := Generate_rep_share(n, t)
	//fmt.Println("begin_figP")
	for i := 1; i <= n; i++ {
		rxi, rui := shamir_share_for_i(i, rx), shamir_share_for_i(i, ru)
		_, rKi := rep_share_for_i(i, rx, rK)
		P[i].rx = &rxi
		P[i].ru = &rui
		P[i].rK = &rKi
		P[i].g1 = g1
		P[i].g2 = g2
		P[i].id = i
		P[i].n = n
		P[i].t = t
		var A blst.P1Affine
		A = *blst.P1_mult_x(blst.P1_generator(), blst.Int_2_scalar(n))
		P[i].a = &A
		//fmt.Println("Pia",P[i].a)
		P[i].share_convert(c)
	}
	//fmt.Println("finishconfigP")
	X := make(map[int]blst.P2Affine)
	for i := 1; i <= 2*t+1; i++ {
		rxi := rx[i]
		X[i] = *blst.P2_mult_x(g2, &rxi)
	}
	(*U).XT = &X
	(*U).Y2 = blst.P2_mult_x(g2, y)
	(*U).Y1 = blst.P1_mult_x(g1, y)
	(*U).g1 = g1
	(*U).g2 = g2
	//fmt.Println("secret key:")
	//fmt.Println(x)
	return x, *y
}

func (P *server) share_convert(c int) {

	P.Ru = make([]blst.Scalar, c)

	for i := 0; i < c; i++ {
		P.Ru[i] = Rep_to_Shamir(P.n, P.t, P.id, *P.rK)

		P.updatek()

	}
	//fmt.Println("finish_share_convert")
}
func (P *server) updatek() {
	//fmt.Println("begin_update_k")
	for t, v := range *P.rK {
		var C blst.P1Affine
		//fmt.Println(P.a)
		C = *P.a
		var V blst.Scalar
		V = v
		nk := PRF_1(&C, &V)
		(*P.rK)[t] = *nk
	}
}

func Rep_to_Shamir(n, t, j int, rj map[int]blst.Scalar) blst.Scalar {
	rt := blst.Scalar_zero()
	for i := 1; i < (1 << n); i++ {
		if number_of_T(i) != t || M_u_s_include(j, i) {
			continue
		}
		sam := convert_sample(i)
		rjn := rj[i]
		rt = blst.Scalar_add(rt, blst.Scalar_mul(&rjn, Lag(sam, j)))
	}
	return *rt
}

func convert_sample(A int) map[int]blst.Scalar {
	i := 1
	rt := make(map[int]blst.Scalar)
	for A > 0 {
		if A%2 == 1 {
			rt[i] = *blst.Scalar_zero()
		}
		A = A / 2
		i = i + 1
	}
	rt[0] = *blst.Scalar_one()
	return rt
}
