package bls

import (
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/keep-network/keep-core/pkg/altbn128"
)

type Signature struct {
	p *bn256.G1
}

// ZeroSignature returns zero signature (point at infinity)
func ZeroSignature() Signature {
	return Signature{p: new(bn256.G1).Set(&zeroG1)}
}

// Verify checks the BLS signature of the message against the public key of its signer
func (signature Signature) Verify(publicKey PublicKey, message []byte) bool {
	hashPoint := altbn128.G1HashToPoint(message)

	a := []*bn256.G1{new(bn256.G1).Neg(signature.p), hashPoint}
	b := []*bn256.G2{&g2, publicKey.p}
	return bn256.PairingCheck(a, b)
}

// VerifyMembershipKeyPart verifies membership key part i ((a⋅pk)×H(P, i))
// against aggregated public key (P) and public key of the party (pk×G)
func (signature Signature) VerifyMembershipKeyPart(aggPublicKey PublicKey, partPublicKey PublicKey, anticoef big.Int, index byte) bool {
	hashPoint := hashToPointIndex(aggPublicKey.p, index)
	pub := new(bn256.G2).ScalarMult(partPublicKey.p, &anticoef)

	a := []*bn256.G1{new(bn256.G1).Neg(signature.p), hashPoint}
	b := []*bn256.G2{&g2, pub}
	return bn256.PairingCheck(a, b)
}

// Aggregate adds the given signatures
func (signature Signature) Aggregate(onemore Signature) Signature {
	var p *bn256.G1
	if signature.p == nil {
		p = new(bn256.G1).Set(&zeroG1)
	} else {
		p = new(bn256.G1).Set(signature.p)
	}
	p.Add(p, onemore.p)
	return Signature{p: p}
}

func (signature Signature) Marshal() []byte {
	if signature.p == nil {
		return nil
	}
	return signature.p.Marshal()
}

func UnmarshalSignature(raw []byte) (Signature, error) {
	if raw == nil || len(raw) == 0 {
		return Signature{}, nil
	}
	p := new(bn256.G1)
	_, err := p.Unmarshal(raw)
	return Signature{p: p}, err
}
