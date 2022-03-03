package test

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/eywa-protocol/bls-crypto/bls"
	"github.com/stretchr/testify/require"
)

type Message struct {
	Privs      []bls.PrivateKey
	Multis     []bls.Multisig
	Mask       *big.Int
	PrivEmpty  bls.PrivateKey
	MultiEmpty bls.Multisig
}

func Test_MarshallUnmarshallJson(t *testing.T) {
	N := 3
	privs, pubs := GenerateRandomKeys(N)
	signs := make([]bls.Signature, N)
	multis := make([]bls.Multisig, N)
	for i, priv := range privs {
		signs[i] = priv.Sign(msg)
		multis[i] = bls.Multisig{
			PartSignature: signs[i],
			PartPublicKey: pubs[i],
			PartMask:      big.NewInt(int64(i)),
		}
	}

	outmsg := Message{
		Privs:  privs,
		Multis: multis,
	}
	raw, err := json.Marshal(outmsg)
	require.NoError(t, err)
	//log.Print(string(raw))

	var inmsg Message
	err = json.Unmarshal(raw, &inmsg)
	require.NoError(t, err)
	require.Equal(t, len(inmsg.Multis), len(outmsg.Multis))
	require.Equal(t, inmsg.Multis, outmsg.Multis)
	for i, _ := range inmsg.Privs {
		require.Equal(t, 0, bytes.Compare(inmsg.Privs[i].Marshal(), privs[i].Marshal()))
		require.Equal(t, 0, bytes.Compare(inmsg.Multis[i].PartPublicKey.Marshal(), pubs[i].Marshal()))
		require.Equal(t, 0, bytes.Compare(inmsg.Multis[i].PartSignature.Marshal(), signs[i].Marshal()))
		require.Equal(t, inmsg.Multis[i].PartMask.Int64(), int64(i))
	}
	require.Equal(t, []byte("0"), inmsg.PrivEmpty.Marshal())
	require.Equal(t, inmsg.MultiEmpty.PartPublicKey.Marshal(), outmsg.MultiEmpty.PartPublicKey.Marshal())
	require.Equal(t, inmsg.MultiEmpty.PartSignature.Marshal(), outmsg.MultiEmpty.PartSignature.Marshal())
	require.Equal(t, inmsg.MultiEmpty.PartMask.String(), outmsg.MultiEmpty.PartMask.String())
}

func Test_MarshalUnmarshaKeys(t *testing.T) {
	_, err := bls.ReadPrivateKey("hi")
	require.Error(t, err)

	priv, pub := bls.GenerateRandomKey()

	privm, err := bls.UnmarshalPrivateKey(priv.Marshal())
	require.NoError(t, err)
	require.Equal(t, priv, privm)

	pubm, err := bls.UnmarshalPublicKey(pub.Marshal())
	require.NoError(t, err)
	require.Equal(t, pub, pubm)
}

func Test_ReadKeys(t *testing.T) {
	_, err := bls.ReadPublicKey("hi")
	require.Error(t, err)

	priv, err := bls.ReadPrivateKey("194cd886f74a0a5a064d24855dea732bf1474954b61ecb0ee55b4fb58b7346b5")
	require.NoError(t, err)
	pub, err := bls.ReadPublicKey("11d1c9610cefbafc90e7638bc572800f4b1c1d6e7aea39b277475cf2b57c57c901e4e4d0857808c70ea813ec7190abd0fc8fbc06ecc80466744d9d7d7f1037fc208c0be5cdec252156ccfb41ffb25e0d1032213e6758ef95a775f5dcdd94e19b0b3cc0241c3fac049f4c7fd0a31b0ec7bf6140061d7cdb4f97781b32170b9aa8")
	require.NoError(t, err)
	require.Equal(t, priv.PublicKey().Marshal(), pub.Marshal())

	sig, err := bls.ReadSignature("2776b457fc6dd82cf65960534933272437ea784eb5a0470f5c68912343b11b3d22d45a35728d407bf17a50ac14023eb2f35ae7d904307b9655e155afe93ed3f0")
	require.NoError(t, err)
	require.Equal(t, sig.Marshal(), priv.Sign([]byte("Hello world!")).Marshal())
}
