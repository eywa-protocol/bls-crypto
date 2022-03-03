package bls

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
)

func (secretKey PrivateKey) MarshalJSON() ([]byte, error) {
	if secretKey.p == nil {
		return json.Marshal(nil)
	}
	return secretKey.p.MarshalJSON()
}

func (secretKey *PrivateKey) UnmarshalJSON(data []byte) error {
	priv, err := UnmarshalPrivateKey(data)
	*secretKey = priv
	return err
}

func ReadPrivateKey(str string) (PrivateKey, error) {
	bin, err := hex.DecodeString(str)
	if err != nil {
		return PrivateKey{}, err
	}
	p := new(big.Int).SetBytes(bin)
	return PrivateKey{p: p}, err
}

func (publicKey PublicKey) MarshalJSON() ([]byte, error) {
	raw := publicKey.Marshal()
	if raw == nil {
		return json.Marshal(raw)
	}
	return json.Marshal(hex.EncodeToString(raw))
}

func (publicKey *PublicKey) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	raw, err := hex.DecodeString(str)
	if err != nil {
		return err
	}
	sig, err := UnmarshalPublicKey(raw)
	*publicKey = sig
	return err
}

func ReadPublicKey(str string) (PublicKey, error) {
	raw, err := hex.DecodeString(str)
	if err != nil {
		return PublicKey{}, err
	}
	return UnmarshalPublicKey(raw)
}

func (signature Signature) MarshalJSON() ([]byte, error) {
	raw := signature.Marshal()
	if raw == nil {
		return json.Marshal(raw)
	}
	return json.Marshal(hex.EncodeToString(raw))
}

func (signature *Signature) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	raw, err := hex.DecodeString(str)
	if err != nil {
		return err
	}
	sig, err := UnmarshalSignature(raw)
	*signature = sig
	return err
}

func ReadSignature(str string) (Signature, error) {
	raw, err := hex.DecodeString(str)
	if err != nil {
		return Signature{}, err
	}
	return UnmarshalSignature(raw)
}

func MarshalBitmask(mask *big.Int) []byte {
	if mask == nil {
		return nil
	}
	return mask.Bytes()
}

func UnmarshalBitmask(data []byte) *big.Int {
	if data == nil {
		return nil
	}
	return new(big.Int).SetBytes(data)
}
