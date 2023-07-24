package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"testing"

	"github.com/foxboron/swtpm_test"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

var (
	pin         = []byte("123456")
	srkTemplate = tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(nil),
				},
			},
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}

	eccKeyDecryptTemplate = tpm2.Create{
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				Decrypt:             true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					CurveID: tpm2.TPMECCNistP256,
					Scheme: tpm2.TPMTECCScheme{
						Scheme: tpm2.TPMAlgECDH,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgECDH,
							&tpm2.TPMSKeySchemeECDH{
								HashAlg: tpm2.TPMAlgSHA256,
							},
						),
					},
				},
			),
		}),
	}
)

func TestECDHKey(t *testing.T) {

	tpm := swtpm_test.NewSwtpm(t.TempDir())
	socket, err := tpm.Socket()
	if err != nil {
		t.Fatal(err)
	}
	rwc, err := transport.OpenTPM(socket)
	if err != nil {
		t.Fatal(err)
	}

	var rsp *tpm2.CreatePrimaryResponse
	rsp, err = srkTemplate.Execute(rwc)
	if err != nil {
		t.Fatalf("failed srkTemplate Execute: %v", err)
	}

	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: rsp.ObjectHandle,
		}
		_, err := flush.Execute(rwc)
		if err != nil {
			t.Fatalf("could not flush EK: %v", err)
		}
	}()

	srkHandle := rsp.ObjectHandle
	srkPublic, err := rsp.OutPublic.Contents()
	if err != nil {
		t.Fatalf("failed getting public")
	}

	fmt.Println(string(rsp.Name.Buffer))
	eccKeyDecryptTemplate.ParentHandle = tpm2.AuthHandle{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
		Auth:   tpm2.PasswordAuth([]byte("")),
	}

	var eccRsp *tpm2.CreateResponse

	eccRsp, err = eccKeyDecryptTemplate.Execute(rwc,
		tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptIn),
			tpm2.Salted(srkHandle, *srkPublic)))
	if err != nil {
		t.Fatalf("%v", err)
	}

	externalKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	externalPubKey := externalKey.PublicKey()

	loadBlobCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: rsp.ObjectHandle,
			Name:   rsp.Name,
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		InPrivate: eccRsp.OutPrivate,
		InPublic:  eccRsp.OutPublic,
	}
	loadBlobRsp, err := loadBlobCmd.Execute(rwc)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer func() {
		// Flush the blob
		flushBlobCmd := tpm2.FlushContext{FlushHandle: loadBlobRsp.ObjectHandle}
		if _, err := flushBlobCmd.Execute(rwc); err != nil {
			t.Errorf("%v", err)
		}
	}()

	var shared [32]byte
	t.Run("External shared key", func(t *testing.T) {

		outPub, err := eccRsp.OutPublic.Contents()
		if err != nil {
			t.Fatalf("%v", err)
		}
		tpmPub, err := outPub.Unique.ECC()
		if err != nil {
			t.Fatalf("%v", err)
		}

		ecdhKey, err := ecdh.P256().NewPublicKey(elliptic.Marshal(elliptic.P256(),
			big.NewInt(0).SetBytes(tpmPub.X.Buffer),
			big.NewInt(0).SetBytes(tpmPub.Y.Buffer),
		))
		if err != nil {
			t.Fatalf("failed new ecc key: %v", err)
		}

		b, err := externalKey.ECDH(ecdhKey)
		if err != nil {
			t.Fatalf("can't run ecdh with TPM key")
		}
		shared = sha256.Sum256(b)
	})

	fmt.Println(shared)

	var tpmSharedKey [32]byte
	t.Run("TPM create shared key", func(t *testing.T) {

		x, y := elliptic.Unmarshal(elliptic.P256(), externalPubKey.Bytes())

		swPub := tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: x.FillBytes(make([]byte, 32))},
			Y: tpm2.TPM2BECCParameter{Buffer: y.FillBytes(make([]byte, 32))},
		}

		ecdh := tpm2.ECDHZGen{
			KeyHandle: tpm2.AuthHandle{
				Handle: loadBlobRsp.ObjectHandle,
				Name:   loadBlobRsp.Name,
				Auth:   tpm2.PasswordAuth([]byte("")),
			},
			InPoint: tpm2.New2B(swPub),
		}

		ecdhRsp, err := ecdh.Execute(rwc,
			tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
				tpm2.AESEncryption(128, tpm2.EncryptIn),
				tpm2.Salted(srkHandle, *srkPublic)))
		if err != nil {
			t.Fatalf("ECDH_ZGen failed: %v", err)
		}

		outPoint, err := ecdhRsp.OutPoint.Contents()
		if err != nil {
			t.Fatalf("%v", err)
		}
		tpmSharedKey = sha256.Sum256(outPoint.X.Buffer)

		fmt.Printf("%x\n", tpmSharedKey)
		fmt.Printf("%x\n", shared)
		if tpmSharedKey != shared {
			t.Fatalf("shared key is not the same")
		}
	})
}

func TestSealing(t *testing.T) {

	tpm := swtpm_test.NewSwtpm(t.TempDir())
	socket, err := tpm.Socket()
	if err != nil {
		t.Fatal(err)
	}
	rwc, err := transport.OpenTPM(socket)
	if err != nil {
		t.Fatal(err)
	}

	externalKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	_ = externalKey.PublicKey()

	rsp, err := srkTemplate.Execute(rwc)
	if err != nil {
		t.Fatalf("failed srkTemplate Execute: %v", err)
	}

	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: rsp.ObjectHandle,
		}
		_, err := flush.Execute(rwc)
		if err != nil {
			t.Fatalf("could not flush EK: %v", err)
		}
	}()

	data := []byte("this is a cert")

	createBlobCmd := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: rsp.ObjectHandle,
			Name:   rsp.Name,
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: data,
				}),
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: true,
				NoDA:         true,
			},
		}),
	}

	createBlobCmd.ParentHandle = tpm2.AuthHandle{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
		Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth([]byte("")), tpm2.AESEncryption(128, tpm2.EncryptOut)),
	}

	var createBlobRsp *tpm2.CreateResponse

	createBlobRsp, err = createBlobCmd.Execute(rwc)
	if err != nil {
		t.Fatalf("%v", err)
	}

	var pub []byte
	pub = append(pub, tpm2.Marshal(createBlobRsp.OutPublic)...)
	pub = append(pub, tpm2.Marshal(createBlobRsp.OutPrivate)...)

	public, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pub)
	if err != nil {
		log.Fatal(err)
	}

	private, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](pub[len(public.Bytes())+2:])
	if err != nil {
		log.Fatal(err)
	}

	// Load the sealed blob
	loadBlobCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: rsp.ObjectHandle,
			Name:   rsp.Name,
			Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth([]byte(""))),
		},
		InPrivate: *private,
		InPublic:  *public,
	}
	loadBlobRsp, err := loadBlobCmd.Execute(rwc)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer func() {
		// Flush the blob
		flushBlobCmd := tpm2.FlushContext{FlushHandle: loadBlobRsp.ObjectHandle}
		if _, err := flushBlobCmd.Execute(rwc); err != nil {
			t.Errorf("%v", err)
		}
	}()

	unsealCmd := tpm2.Unseal{
		ItemHandle: tpm2.NamedHandle{
			Handle: loadBlobRsp.ObjectHandle,
			Name:   loadBlobRsp.Name,
		},
	}
	unsealCmd.ItemHandle = tpm2.AuthHandle{
		Handle: loadBlobRsp.ObjectHandle,
		Name:   loadBlobRsp.Name,
		Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth([]byte("")),
			tpm2.AESEncryption(128, tpm2.EncryptOut)),
	}
	unsealRsp, err := unsealCmd.Execute(rwc)
	if err != nil {
		t.Errorf("%v", err)
	}
	if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
		t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
	}
}

func TestPassword(t *testing.T) {

	tpm := swtpm_test.NewSwtpm(t.TempDir())
	socket, err := tpm.Socket()
	if err != nil {
		t.Fatal(err)
	}
	rwc, err := transport.OpenTPM(socket)
	if err != nil {
		t.Fatal(err)
	}

	var rsp *tpm2.CreatePrimaryResponse
	rsp, err = srkTemplate.Execute(rwc)
	if err != nil {
		t.Fatalf("failed srkTemplate Execute: %v", err)
	}

	fmt.Printf("0x%x\n", rsp.ObjectHandle.HandleValue())

	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: rsp.ObjectHandle,
		}
		_, err := flush.Execute(rwc)
		if err != nil {
			t.Fatalf("could not flush EK: %v", err)
		}
	}()

	srkHandle := rsp.ObjectHandle
	srkPublic, err := rsp.OutPublic.Contents()
	if err != nil {
		t.Fatalf("failed getting public")
	}

	eccKeyDecryptTemplate.ParentHandle = tpm2.AuthHandle{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
		Auth:   tpm2.PasswordAuth([]byte("")),
	}

	eccKeyDecryptTemplate.InSensitive = tpm2.TPM2BSensitiveCreate{
		Sensitive: &tpm2.TPMSSensitiveCreate{
			UserAuth: tpm2.TPM2BAuth{
				Buffer: pin,
			},
		},
	}

	var eccRsp *tpm2.CreateResponse

	eccRsp, err = eccKeyDecryptTemplate.Execute(rwc,
		tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptIn),
			tpm2.Salted(srkHandle, *srkPublic)))
	if err != nil {
		t.Fatalf("%v", err)
	}

	externalKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	externalPubKey := externalKey.PublicKey()

	loadBlobCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: rsp.ObjectHandle,
			Name:   rsp.Name,
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		InPrivate: eccRsp.OutPrivate,
		InPublic:  eccRsp.OutPublic,
	}
	loadBlobRsp, err := loadBlobCmd.Execute(rwc)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer func() {
		// Flush the blob
		flushBlobCmd := tpm2.FlushContext{FlushHandle: loadBlobRsp.ObjectHandle}
		if _, err := flushBlobCmd.Execute(rwc); err != nil {
			t.Errorf("%v", err)
		}
	}()

	var shared [32]byte
	t.Run("External shared key", func(t *testing.T) {

		outPub, err := eccRsp.OutPublic.Contents()
		if err != nil {
			t.Fatalf("%v", err)
		}
		tpmPub, err := outPub.Unique.ECC()
		if err != nil {
			t.Fatalf("%v", err)
		}

		ecdhKey, err := ecdh.P256().NewPublicKey(elliptic.Marshal(elliptic.P256(),
			big.NewInt(0).SetBytes(tpmPub.X.Buffer),
			big.NewInt(0).SetBytes(tpmPub.Y.Buffer),
		))
		if err != nil {
			t.Fatalf("failed new ecc key: %v", err)
		}

		b, err := externalKey.ECDH(ecdhKey)
		if err != nil {
			t.Fatalf("can't run ecdh with TPM key")
		}
		shared = sha256.Sum256(b)
	})

	fmt.Println(shared)

	var tpmSharedKey [32]byte
	t.Run("TPM create shared key", func(t *testing.T) {

		x, y := elliptic.Unmarshal(elliptic.P256(), externalPubKey.Bytes())

		swPub := tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: x.FillBytes(make([]byte, 32))},
			Y: tpm2.TPM2BECCParameter{Buffer: y.FillBytes(make([]byte, 32))},
		}

		ecdh := tpm2.ECDHZGen{
			KeyHandle: tpm2.AuthHandle{
				Handle: loadBlobRsp.ObjectHandle,
				Name:   loadBlobRsp.Name,
				Auth:   tpm2.PasswordAuth(pin),
			},
			InPoint: tpm2.New2B(swPub),
		}

		ecdhRsp, err := ecdh.Execute(rwc,
			tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
				tpm2.AESEncryption(128, tpm2.EncryptIn),
				tpm2.Salted(srkHandle, *srkPublic)))
		if err != nil {
			t.Fatalf("ECDH_ZGen failed: %v", err)
		}

		outPoint, err := ecdhRsp.OutPoint.Contents()
		if err != nil {
			t.Fatalf("%v", err)
		}
		tpmSharedKey = sha256.Sum256(outPoint.X.Buffer)

		fmt.Printf("%x\n", tpmSharedKey)
		fmt.Printf("%x\n", shared)
		if tpmSharedKey != shared {
			t.Fatalf("shared key is not the same")
		}
	})
}

func TestECDHSigning(t *testing.T) {
	rwc, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}

	var rsp *tpm2.CreatePrimaryResponse
	rsp, err = srkTemplate.Execute(rwc)
	if err != nil {
		t.Fatalf("failed srkTemplate Execute: %v", err)
	}

	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: rsp.ObjectHandle,
		}
		_, err := flush.Execute(rwc)
		if err != nil {
			t.Fatalf("could not flush EK: %v", err)
		}
	}()

	// srkHandle := rsp.ObjectHandle
	// srkPublic, err := rsp.OutPublic.Contents()
	// if err != nil {
	// 	t.Fatalf("failed getting public")
	// }

	eccKeyDecryptTemplate = tpm2.Create{
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				SignEncrypt:         true,
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					CurveID: tpm2.TPMECCNistP256,
					Scheme: tpm2.TPMTECCScheme{
						Scheme: tpm2.TPMAlgECDSA,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgECDSA,
							&tpm2.TPMSSigSchemeECDSA{
								HashAlg: tpm2.TPMAlgSHA256,
							},
						),
					},
				},
			),
		}),
	}

	eccKeyDecryptTemplate.ParentHandle = tpm2.AuthHandle{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
		Auth:   tpm2.PasswordAuth([]byte("")),
	}

	var eccRsp *tpm2.CreateResponse

	eccRsp, err = eccKeyDecryptTemplate.Execute(rwc)
	if err != nil {
		t.Fatalf("%v", err)
	}

	loadBlobCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: rsp.ObjectHandle,
			Name:   rsp.Name,
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		InPrivate: eccRsp.OutPrivate,
		InPublic:  eccRsp.OutPublic,
	}
	loadBlobRsp, err := loadBlobCmd.Execute(rwc)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer func() {
		// Flush the blob
		flushBlobCmd := tpm2.FlushContext{FlushHandle: loadBlobRsp.ObjectHandle}
		if _, err := flushBlobCmd.Execute(rwc); err != nil {
			t.Errorf("%v", err)
		}
	}()

	b := sha256.Sum256([]byte("heyho"))
	digest := tpm2.TPM2BDigest{Buffer: b[:]}

	sign := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: loadBlobRsp.ObjectHandle,
			Name:   loadBlobRsp.Name,
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		Digest: digest,
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	rspSign, err := sign.Execute(rwc)
	if err != nil {
		t.Fatalf("Failed to Sign Digest: %v", err)
	}

	eccsig, err := rspSign.Signature.Signature.ECDSA()
	if err != nil {
		t.Fatalf("%v", err)
	}

	fmt.Println(eccsig)

	eccRsp.OutPublic.Contents()

	pub, err := eccRsp.OutPublic.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}

	eccDetails, err := pub.Parameters.ECCDetail()
	if err != nil {
		t.Fatalf("%v", err)
	}

	eccUnique, err := pub.Unique.ECC()
	if err != nil {
		t.Fatalf("%v", err)
	}

	ecdsaPub, err := tpm2.ECCPub(eccDetails, eccUnique)
	if err != nil {
		t.Fatalf("%v", err)
	}

	fmt.Println(ecdsaPub)

	ecdsaKey := &ecdsa.PublicKey{Curve: elliptic.P256(),
		X: ecdsaPub.X,
		Y: ecdsaPub.Y,
	}

	r := big.NewInt(0).SetBytes(eccsig.SignatureR.Buffer)
	s := big.NewInt(0).SetBytes(eccsig.SignatureS.Buffer)

	if !ecdsa.Verify(ecdsaKey, b[:], r, s) {
		t.Fatalf("doesn't match")
	}
}
