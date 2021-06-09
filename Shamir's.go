package main

import (
	"blst/bindings/go"
	"fmt"
	"sort"
)

func Shamir_Keygen(n, t int, P []server, U *signer) (blst.Scalar, blst.Scalar) {
	g1, g2 := blst.P1_generator(), blst.P2_generator()
	y := blst.Scalar_rand()
	rx, x := Generate_shamir_share(n, t)
	ru, _ := Generate_shamir_share(n, t)
	for i := 1; i <= n; i++ {
		rxi, rui := shamir_share_for_i(i, rx), shamir_share_for_i(i, ru)
		P[i].rx = &rxi
		P[i].ru = &rui
		P[i].g1 = g1
		P[i].g2 = g2
		P[i].id = i
		P[i].n = n
		P[i].t = t
	}
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
	fmt.Println("secret key:")
	fmt.Println(x)
	return x, *y
}

func (Pj *server) Shamir_Sign(C *blst.P1Affine, l1, l2 *blst.Scalar) (*blst.P1Affine, *blst.P1Affine, *blst.P1Affine) {
	i := Pj.id
	g := Pj.g1
	fi1 := (*Pj.ru)[i]
	if Pj.Ru != nil {
		fi1 = Pj.Ru[Pj.ui]
		Pj.ui++
	}
	//fmt.Println("fi1", fi1)
	fi2 := (*Pj.rx)[i]
	id1 := &fi1
	id2 := &fi1
	id2 = blst.Scalar_mul(id2, &fi2)
	return blst.P1_mult_x(g, id1), blst.P1_mult_x(g, id2), blst.P1_mult_x(C, id1)
}

func (U *signer) Shamir_Commit(n, t int, P []server) (*blst.P1Affine, *blst.P1Affine) {
	A, B, C := blst.P1_zero(), blst.P1_zero(), blst.P1_zero()
	w := blst.Scalar_rand()
	Commit := blst.P1_add(blst.P1_mult_x(U.g1, w), blst.P1_mult_x(U.Y1, U.message))
	for i := 1; i <= t*2+1; i++ {
		l2 := Li(first_t_keys(2*t+1), i, 0)
		l1 := l2
		if i <= (t + 1) {
			l1 = Li(first_t_keys(t+1), i, 0)
		}
		a, b, c := P[i].Shamir_Sign(Commit, l1, l2)
		v := (*U.XT)[i]
		//fmt.Println(v)
		che := blst.Check(a,
			blst.P1_add(blst.P1_mult_x(a, blst.Scalar_neg(w)), blst.P1_add(b, c)),
			blst.P2_add(&v, blst.P2_mult_x(U.Y2, U.message)),
			U.g2)
		fmt.Println("partial signature correct", che)
		a = blst.P1_mult_x(a, l1)
		b = blst.P1_mult_x(b, l2)
		c = blst.P1_mult_x(c, l1)
		//fmt.Println("abc",a,b,c)
		if i <= (t + 1) {
			A = blst.P1_add(A, a)
			C = blst.P1_add(C, c)
		}
		B = blst.P1_add(B, b)
	}
	sig2 := blst.P1_add(B, C)
	sig2 = blst.P1_add(sig2, blst.P1_mult_x(A, blst.Scalar_neg(w)))
	return A, sig2
}

func Update_u(n, t int, P []server) {
	ru, _ := Generate_shamir_share(n, t)
	for i := 1; i <= n; i++ {
		rui := shamir_share_for_i(i, ru)
		P[i].ru = &rui
	}
}
func first_t_keys(t int) []int {
	rt := make([]int, t)
	for i := 0; i < t; i++ {
		rt[i] = i + 1
	}
	return rt
}

func shamir_share_for_i(i int, rx map[int]blst.Scalar) map[int]blst.Scalar {
	rt := make(map[int]blst.Scalar)
	rt[i] = rx[i]
	return rt
}

func Generate_shamir_share(n, t int) (map[int]blst.Scalar, blst.Scalar) {
	rt := make(map[int]blst.Scalar)
	Rt := make(map[int]blst.Scalar)
	for i := 1; i <= t+1; i++ {
		rt[i] = *blst.Scalar_rand()
	}
	s1 := Lag(rt, 0)
	for i := 0; i <= n; i++ {
		Rt[i] = *Lag(rt, i)
	}
	return Rt, *s1
}

func Getkeys(m map[int]blst.Scalar) []int {
	j := 0
	keys := make([]int, len(m))
	for k := range m {
		keys[j] = k
		j++
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	return keys
}

func Li(x []int, j, X int) *blst.Scalar {
	t := len(x) - 1
	j = j - 1
	rt := blst.Scalar_one()
	for i := 0; i <= t; i++ {
		if j == i {
			continue
		}
		rt = blst.Scalar_mul(rt, blst.Scalar_div(blst.Scalar_sub(blst.Int_2_scalar(X), blst.Int_2_scalar(x[i])),
			blst.Scalar_sub(blst.Int_2_scalar(x[j]), blst.Int_2_scalar(x[i]))))
	}
	return rt
}

func Lag(sample map[int]blst.Scalar, x int) *blst.Scalar {
	rt := blst.Scalar_zero()
	t := len(sample) - 1
	keys := Getkeys(sample)
	for j := 1; j <= t+1; j++ {
		v := sample[keys[j-1]]
		v = *blst.Scalar_mul(&v, Li(keys, j, x))
		rt = blst.Scalar_add(rt, &v)
	}
	return rt
}
