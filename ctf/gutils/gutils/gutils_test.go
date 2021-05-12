package gutils

import (
	"bytes"
	"encoding/hex"
	"testing"
)

const FatalfErrFmt string = "Failed: %q \ngot: %q"

func TestDecodeHexString(t *testing.T) {
	input1 := "4141"
	actual, err := DecodeHexString(input1)
	if !bytes.Equal(actual, []byte{0x41, 0x41}) {
		t.Fatalf(FatalfErrFmt, err, actual)
	}

	input2 := "gopher"
	actual, err = DecodeHexString(input2)
	if !bytes.Equal(actual, []byte{}) {
		t.Fatalf(FatalfErrFmt, err, actual)
	}

	input3 := ""
	actual, err = DecodeHexString(input3)
	if !bytes.Equal(actual, []byte{}) {
		t.Fatalf(FatalfErrFmt, err, actual)
	}
}

func TestBase64Encode(t *testing.T) {
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	buffer, err := DecodeHexString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	if err != nil {
		t.Fatalf(FatalfErrFmt, err, buffer)
	}

	actual := Base64Encode(buffer)
	if actual != expected {
		t.Fatalf(FatalfErrFmt, "", actual)
	}

	actual = Base64Encode(nil)
	if actual != "" {
		t.Fatalf(FatalfErrFmt, "", actual)
	}
}

func TestXorBytes(t *testing.T) {
	expected := "746865206b696420646f6e277420706c6179"
	buffer, err := DecodeHexString("1c0111001f010100061a024b53535009181c")
	if err != nil {
		t.Fatal(FatalfErrFmt, err, buffer)
	}
	key, err := DecodeHexString("686974207468652062756c6c277320657965")
	if err != nil {
		t.Fatal(err)
	}

	actual := XorBytes(buffer, key)
	if hex.EncodeToString(actual) != expected {
		t.Fatalf(FatalfErrFmt, "", actual)
	}
	actual = XorBytes([]byte{}, key)
	if hex.EncodeToString(actual) != "" {
		t.Fatalf(FatalfErrFmt, "", actual)
	}
	actual = XorBytes(buffer, []byte{})
	if hex.EncodeToString(actual) != hex.EncodeToString(buffer) {
		t.Fatalf(FatalfErrFmt, "", actual)
	}
}

func TestIsAlpha(t *testing.T) {
	if IsAlpha([]byte{0x20, 0x21, 0x7e}) != true {
		t.Fatal("Failed")
	}
	if IsAlpha([]byte{0x20, 0x10, 0x7e}) != false {
		t.Fatal("Failed")
	}
	if IsAlpha([]byte{}) != true {
		t.Fatal("Failed")
	}
}

func TestSingleByteXor(t *testing.T) {
	expected := "Cooking MC's like a pound of bacon"
	buffer, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	actual, err := SingleByteXor(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if expected != string(actual) {
		t.Fatalf(FatalfErrFmt, "", actual)
	}
}

func TestGetSingleByteXor(t *testing.T) {
	message := "HELLO, WORLD!"
	key, err := GetSingleByteXor(XorBytes([]byte(message), []byte{1}))
	if err != nil {
		t.Fatalf(FatalfErrFmt, err, key)
	}
	if key != byte(0x1) {
		t.Fatalf(FatalfErrFmt, "", key)
	}
	message = "HELLO, WORLD!"
	key, err = GetSingleByteXor(XorBytes([]byte(message), []byte{42}))
	if err != nil {
		t.Fatalf(FatalfErrFmt, err, key)
	}
	if key != byte(42) {
		t.Fatalf(FatalfErrFmt, "", key)
	}
}

func TestGetHammingDistance(t *testing.T) {
	s1 := []byte("karolin")
	s2 := []byte("kathrin")
	hammingDist := GetHammingDistance(s1, s2)
	if hammingDist != 9 {
		t.Fatalf(FatalfErrFmt, "", hammingDist)
	}
	s1 = []byte("this is a test")
	s2 = []byte("wokka wokka!!!")
	hammingDist = GetHammingDistance(s1, s2)
	if hammingDist != 37 {
		t.Fatalf(FatalfErrFmt, "", hammingDist)
	}
}

func TestGetPkcs7Padded(t *testing.T) {
	blockLength := 16
	res := GetPkcs7Padded([]byte("Hello, World"), blockLength)
	if !bytes.Equal(res, []byte("Hello, World\x04\x04\x04\x04")) {
		t.Fatalf(FatalfErrFmt, "", res)
	}
	res = GetPkcs7Padded([]byte("Hello, World!!!!"), blockLength)
	paddedBlock := make([]byte, blockLength)
	Memset(paddedBlock, 0x10)
	if !bytes.Equal(res, bytes.Join([][]byte{[]byte("Hello, World!!!!"), paddedBlock}, []byte{})) {
		t.Fatalf(FatalfErrFmt, "", res)
	}
	blockLength = 10
	res = GetPkcs7Padded([]byte("Hello, World"), blockLength)
	if !bytes.Equal(res, []byte("Hello, World\x08\x08\x08\x08\x08\x08\x08\x08")) {
		t.Fatalf(FatalfErrFmt, "", res)
	}
}

func TestGetPkcs7Unpadded(t *testing.T) {
	blockLength := 16
	res := GetPkcs7Unpadded(GetPkcs7Padded([]byte("Hello, World"), blockLength), blockLength)
	res2 := GetPkcs7Unpadded(GetPkcs7Padded([]byte("Hello, World!!!!"), blockLength), blockLength)
	blockLength = 10
	res3 := GetPkcs7Unpadded(GetPkcs7Padded([]byte("Hello, World"), blockLength), blockLength)

	if !bytes.Equal(res, []byte("Hello, World")) {
		t.Fatalf(FatalfErrFmt, "", res)
	}
	if !bytes.Equal(res2, []byte("Hello, World!!!!")) {
		t.Fatalf(FatalfErrFmt, "", res2)
	}
	if !bytes.Equal(res3, []byte("Hello, World")) {
		t.Fatalf(FatalfErrFmt, "", res3)
	}
}

func TestGetNrandBytes(t *testing.T) {
	lenBuff := 1
	buff, err := GetNrandBytes(uint(lenBuff))
	if err != nil {
		t.Fatalf(FatalfErrFmt, err, "")
	}
	if len(buff) != lenBuff {
		t.Fatal("Length mismatch")
	}

	lenBuff = 16
	buff, err = GetNrandBytes(uint(lenBuff))
	if err != nil {
		t.Fatalf(FatalfErrFmt, err, "")
	}
	if len(buff) != lenBuff {
		t.Fatal("Length mismatch")
	}
}
