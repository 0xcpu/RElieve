package gutils

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// DecodeHexString decodes `hexStr` hex encoded string, ex: `4141` -> [65 65]
func DecodeHexString(hexStr string) ([]byte, error) {
	hexBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}

	return hexBytes, err
}

// Base64Encode is a base64 wrapper to encode `data`
func Base64Encode(data []byte) string {
	return base64.RawStdEncoding.EncodeToString(data)
}

// XorBytes xors `data` and `key` buffers. Returns a new buffer.
// if `len(data)` or `len(key)` is 0, return `data`
func XorBytes(data, key []byte) []byte {
	if len(data) == 0 || len(key) == 0 {
		return data
	}

	xoredBytes := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		xoredBytes[i] = data[i] ^ key[i%len(key)]
	}

	return xoredBytes
}

// SumFrequencies sums letter frequencies for bytes in [A..Z ]
// https://en.wikipedia.org/wiki/Letter_frequency
func SumFrequencies(data []byte) float64 {
	// Letter frequency for English
	var letterFreq = map[byte]float64{
		'E': 12.0,
		'T': 9.10,
		'A': 8.12,
		'O': 7.68,
		'I': 7.31,
		'N': 6.95,
		'S': 6.28,
		'R': 6.02,
		'H': 5.92,
		'D': 4.32,
		'L': 3.98,
		'U': 2.88,
		'C': 2.71,
		'M': 2.61,
		'F': 2.30,
		'Y': 2.11,
		'W': 2.09,
		'G': 2.03,
		'P': 1.82,
		'B': 1.49,
		'V': 1.11,
		'K': 0.69,
		'X': 0.17,
		'Q': 0.11,
		'J': 0.10,
		'Z': 0.07,
		' ': 13.0,
	}
	score := 0.0
	for _, b := range data {
		if v, p := letterFreq[b]; p {
			score += v
		}
	}

	return score
}

// IsAlpha return true if all elements in `data` are >= 0x20 and <= 0x7e and not LF
func IsAlpha(data []byte) bool {
	for _, b := range data {
		if (b < 0x20 || b > 0x7e) && b != 0xa {
			return false
		}
	}

	return true
}

func SingleByteXor(data []byte) ([]byte, error) {
	maxFreqSum := 0.0
	finalOutput := make([]byte, len(data))
	output := make([]byte, len(data))
	for i := 1; i < 0x100; i++ {
		for j, b := range data {
			output[j] = b ^ byte(i)
		}

		if IsAlpha(output) {
			freqSum := SumFrequencies(output)
			if freqSum > maxFreqSum {
				maxFreqSum = freqSum
				if len(output) != copy(finalOutput, output) {
					return nil, errors.New("copy failed")
				}
			}
		}
	}

	return finalOutput, nil
}

// GetSingleByteXor attempts to obtain the single by XOR key
// Encrypted buffer is in `data`. Key is determined base on the heuristic
// that the original buffer is an english plaintext.
func GetSingleByteXor(data []byte) (byte, error) {
	if len(data) == 0 {
		return byte(0), errors.New("empty input buffer")
	}

	maxFreqSum := 0.0
	finalKey := byte(0)
	output := make([]byte, len(data))
	for i := 1; i < 0x100; i++ {
		for j, b := range data {
			output[j] = b ^ byte(i)
		}

		if IsAlpha(output) {
			freqSum := SumFrequencies(output)
			if freqSum > maxFreqSum {
				maxFreqSum = freqSum
				finalKey = byte(i)
			}
		}
	}

	return finalKey, nil
}

func GetMin(a, b int) int {
	if a <= b {
		return a
	} else {
		return b
	}
}

// GetHammingDistance compute Hamming distance between 2 strings at bit level
// Example: `this is a test` and `wokka wokka!!!` has `37` as Hamming distance
// https://en.wikipedia.org/wiki/Hamming_distance
func GetHammingDistance(str1, str2 []byte) uint64 {
	var arr1 []string
	for _, c := range str1 {
		arr1 = append(arr1, fmt.Sprintf("%.8b", c))
	}
	var arr2 []string
	for _, c := range str2 {
		arr2 = append(arr2, fmt.Sprintf("%.8b", c))
	}

	var hammingDistance uint64
	binStr1 := strings.Join(arr1, "")
	binStr2 := strings.Join(arr2, "")
	minLen := GetMin(len(binStr1), len(binStr2))
	for i := 0; i < minLen; i++ {
		if binStr1[i] != binStr2[i] {
			hammingDistance += 1
		}
	}

	return hammingDistance
}

func GetPkcs7Padded(input []byte, blockLength int) []byte {
	padLength := len(input) % blockLength
	if padLength == 0 {
		return append(input, make([]byte, blockLength)...)
	} else {
		padLength = blockLength - padLength
		var i int
		var output []byte = input
		for i < padLength {
			output = append(output, byte(padLength))

			i++
		}

		return output
	}
}

func GetPkcs7Unpadded(input []byte, blockLength int) []byte {
	if len(input) == 0 || len(input)%int(blockLength) != 0 {
		return input
	}

	if bytes.Equal(input[len(input)-blockLength:], make([]byte, blockLength)) {
		return input[:len(input)-blockLength]
	} else {
		count := input[len(input)-1]
		return input[:len(input)-int(count)]
	}
}
