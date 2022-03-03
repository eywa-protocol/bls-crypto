package bls

import (
	"crypto/sha256"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

// Multisig is a BLS multisignature proof that anyone may provide to
// convince the verifier that the listed nodes has signed the message
type Multisig struct {
	PartSignature Signature // aggregated partial signature
	PartPublicKey PublicKey // aggregated partial public key
	PartMask      *big.Int  // bitmask of participants
}

// NewZeroMultisig returns zero multisignature
func NewZeroMultisig() Multisig {
	return Multisig{
		PartSignature: ZeroSignature(),
		PartPublicKey: ZeroPublicKey(),
		PartMask:      ZeroMultisigMask(),
	}
}

// Verify checks the BLS multisignature of the message against:
// * the aggregated public key of all its signers (whether signed or not),
// * the aggregated public key of participated signers (who really signed),
// * and the bitmask of signers
func (multi Multisig) Verify(aggPublicKey PublicKey, message []byte) bool {
	sum := new(bn256.G1).Set(&zeroG1)
	mask := new(big.Int).Set(multi.PartMask)
	for index := 0; mask.Sign() != 0; index++ {
		if multi.PartMask.Bit(index) != 0 {
			mask.SetBit(mask, index, 0)
			sum.Add(sum, hashToPointIndex(aggPublicKey.p, byte(index)))
		}
	}

	a := []*bn256.G1{new(bn256.G1).Neg(multi.PartSignature.p), hashToPointMsg(aggPublicKey.p, message), sum}
	b := []*bn256.G2{&g2, multi.PartPublicKey.p, aggPublicKey.p}
	return bn256.PairingCheck(a, b)
}

// CalculateAntiRogueCoefficients returns an array of bigints used for
// subsequent key aggregations:
//
// Ai = hash(Pi, {P1, P2, ...})
func CalculateAntiRogueCoefficients(pubs []PublicKey) []big.Int {
	as := make([]big.Int, len(pubs))
	data := pubs[0].p.Marshal()
	for i := 0; i < len(pubs); i++ {
		data = append(data, pubs[i].p.Marshal()...)
	}

	for i := 0; i < len(pubs); i++ {
		cur := pubs[i].p.Marshal()
		copy(data[0:len(cur)], cur)
		hash := sha256.Sum256(data)
		as[i].SetBytes(hash[:])
	}
	return as
}

// AggregateSignatures sums the given array of signatures
func AggregateSignatures(sigs []Signature, anticoefs []big.Int) Signature {
	p := *new(bn256.G1).Set(&zeroG1)
	for i, sig := range sigs {
		point := new(bn256.G1).Set(sig.p)
		point.ScalarMult(sig.p, &anticoefs[i])
		p.Add(&p, point)
	}
	return Signature{p: &p}
}

// AggregatePublicKeys calculates P1*A1 + P2*A2 + ...
func AggregatePublicKeys(pubs []PublicKey, anticoefs []big.Int) PublicKey {
	res := *new(bn256.G2).Set(&zeroG2)
	for i := 0; i < len(pubs); i++ {
		res.Add(&res, new(bn256.G2).ScalarMult(pubs[i].p, &anticoefs[i]))
	}
	return PublicKey{p: &res}
}
