package test

import (
	"log"
	"math/big"
	"math/bits"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/eywa-protocol/bls-crypto/bls"
	"github.com/stretchr/testify/require"
)

var (
	mks = AggregateMembershipKeys(privs, pubs, aggPub, as)
)

func Test_VerifyMultisigDemo(t *testing.T) {
	priv0, pub0 := bls.GenerateRandomKey()
	priv1, pub1 := bls.GenerateRandomKey()
	priv2, pub2 := bls.GenerateRandomKey()
	Simple := *big.NewInt(1) // in real life use coeficients against anti rogue key attack

	// Aggregated public key of all participants
	allPub := pub0.Aggregate(pub1).Aggregate(pub2)

	// Setup phase - generate membership keys
	mk0 := priv0.GenerateMembershipKeyPart(0, allPub, Simple).
		Aggregate(priv1.GenerateMembershipKeyPart(0, allPub, Simple)).
		Aggregate(priv2.GenerateMembershipKeyPart(0, allPub, Simple))
	mk2 := priv0.GenerateMembershipKeyPart(2, allPub, Simple).
		Aggregate(priv1.GenerateMembershipKeyPart(2, allPub, Simple)).
		Aggregate(priv2.GenerateMembershipKeyPart(2, allPub, Simple))

	// Sign only by #0 and #2
	sig0 := priv0.Multisign(msg, allPub, mk0)
	sig2 := priv2.Multisign(msg, allPub, mk2)
	subSig := sig0.Aggregate(sig2)
	subPub := pub0.Aggregate(pub2)

	// Verify in Golang
	mask := big.NewInt(0b101)
	multi := bls.Multisig{PartSignature: subSig, PartPublicKey: subPub, PartMask: mask}
	require.True(t, multi.Verify(allPub, msg))

	// Verify in EVM
	_, err := blsSignatureTest.VerifyMultisignature(owner, allPub.Marshal(), subPub.Marshal(), msg, subSig.Marshal(), mask)
	require.NoError(t, err)
	backend.Commit()
	verifiedSol, err := blsSignatureTest.Verified(&bind.CallOpts{})
	require.True(t, verifiedSol)
}

// signMultisigPartially signs BLS multisignarure by only the specified members
func signMultisigPartially(bitmask *big.Int) (bls.PublicKey, bls.Signature) {
	pub := bls.ZeroPublicKey()
	sig := bls.ZeroSignature()
	for i := 0; i < len(pubs); i++ {
		if bitmask.Bit(i) != 0 {
			s := privs[i].Multisign(msg, aggPub, mks[i])
			sig = sig.Aggregate(s)
			pub = pub.Aggregate(pubs[i])
		}
	}
	return pub, sig
}

// verifyMultisigTest verifies the multisignature is both Solidity and Go code
func verifyMultisigTest(t *testing.T, mask int64) {
	bitmask := big.NewInt(mask)
	pub, sig := signMultisigPartially(bitmask)

	// verify in solidity
	tx, err := blsSignatureTest.VerifyMultisignature(owner, aggPub.Marshal(), pub.Marshal(), msg, sig.Marshal(), bitmask)
	require.NoError(t, err)
	log.Printf("Signers: %3d/%d, gas: %d", bits.OnesCount64(uint64(mask)), len(pubs), tx.Gas())
	backend.Commit()
	verifiedSol, err := blsSignatureTest.Verified(&bind.CallOpts{})
	require.True(t, verifiedSol)

	// verify in golang code as well
	multi := bls.Multisig{PartSignature: sig, PartPublicKey: pub, PartMask: bitmask}
	require.True(t, multi.Verify(aggPub, msg))
}

func Test_VerifyMultisigManual(t *testing.T) {
	if len(pubs) < 256 {
		t.Skip("This test needs 256 or more PARTICIPANTS_NUMBER. Skipping.")
	}
	bitmask := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil), big.NewInt(1))
	//log.Println(bitmask.Text(16))

	pub, sig := signMultisigPartially(bitmask)
	tx, err := blsSignatureTest.VerifyMultisignature(owner, aggPub.Marshal(), pub.Marshal(), msg, sig.Marshal(), bitmask)
	require.NoError(t, err)
	log.Printf("Signers: %d, gas: %d", len(pubs), tx.Gas())
	backend.Commit()
	verifiedSol, err := blsSignatureTest.Verified(&bind.CallOpts{})
	require.True(t, verifiedSol)

	//bitmask = new(big.Int).SetBit(bitmask, 0, 0)
	multi := bls.Multisig{PartSignature: sig, PartPublicKey: pub, PartMask: bitmask}
	require.True(t, multi.Verify(aggPub, msg))
}

func Test_Verify63MultisigInSolidity(t *testing.T) {
	if len(pubs) < 63 {
		t.Skip("This test needs 63 or more PARTICIPANTS_NUMBER. Skipping.")
	}
	verifyMultisigTest(t, 0x7FFFFFFFFFFFFFFF)
}

func Test_Verify32MultisigInSolidity(t *testing.T) {
	verifyMultisigTest(t, 0xFFFFFFFF)
}

func Test_Verify17MultisigInSolidity(t *testing.T) {
	verifyMultisigTest(t, 0xF0F0F0F1)
}

func Test_Verify16MultisigInSolidity(t *testing.T) {
	verifyMultisigTest(t, 0x0F0F0F0F)
}

func Test_Verify8MultisigInSolidity(t *testing.T) {
	verifyMultisigTest(t, 0x11111111)
}

func Test_Verify4MultisigInSolidity(t *testing.T) {
	verifyMultisigTest(t, 0x10101010)
}

func Test_Verify2MultisigInSolidity(t *testing.T) {
	verifyMultisigTest(t, 0x80000001)
}

func Test_Verify1MultisigInSolidity(t *testing.T) {
	verifyMultisigTest(t, 1)
}

func Test_MembershipKeysInSolidity(t *testing.T) {
	// Make sure that H(P, i) is the signature of the i-th membership key
	msgPoint := bls.HashToPointIndex(aggPub, 0)
	_, err := blsSignatureTest.VerifySignaturePoint(owner, aggPub.Marshal(), msgPoint.Marshal(), mks[0].Marshal())
	require.NoError(t, err)
	backend.Commit()
	verifiedSol, err := blsSignatureTest.Verified(&bind.CallOpts{})
	require.True(t, verifiedSol)
}
