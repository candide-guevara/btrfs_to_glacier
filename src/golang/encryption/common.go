package encryption

import (
  "crypto/aes"
  "crypto/cipher"
  "crypto/rand"
  "crypto/sha256"
  "encoding/base64"
  "fmt"
  "io"
  "reflect"
  "syscall"
  "unsafe"

  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"

  "golang.org/x/crypto/ssh/terminal"
)

func BuildPwPromt(mes string) types.PwPromptF {
  prompt := func() (types.SecretKey, error) {
    null_key := types.SecretKey{[]byte("")}
    fmt.Print(mes)
    // Should NOT copy `byte_pass` because it may contain sensible pw that will stick until GC.
    byte_pass, err := terminal.ReadPassword(int(syscall.Stdin))
    if err != nil { return null_key, err }
    if len(byte_pass) < 12 { return null_key, fmt.Errorf("Password is too short") }

    err = util.IsOnlyAsciiString(byte_pass, false)
    if err != nil { return null_key, err }

    hash_pw := BytesToXorKey(byte_pass)

    // remove password from memory, not sure how reliable this is...
    for idx,_ := range byte_pass { byte_pass[idx] = 0 }
    for idx,_ := range byte_pass { byte_pass[idx] = byte(idx) }
    return hash_pw, err
  }
  return prompt
}

func GetSecretMaterialVerbatim(mes string) (types.SecretString, error) {
  null_str := types.SecretString{""}
  fmt.Print(mes)
  byte_in, err := terminal.ReadPassword(int(syscall.Stdin))
  if err != nil { return null_str, err }
  if len(byte_in) == 0 { return null_str, fmt.Errorf("Got no input") }

  err = util.IsOnlyAsciiString(byte_in, false)
  return types.SecretString{string(byte_in)}, err
}

func TestOnlyFixedPw() (types.SecretKey, error) {
  // xor_key=`sha256sum <(echo -n "chocolat") | cut -f1 -d' ' | sed -r 's/(..)/\\\\x\1/g'`
  const dummy_pw = "chocolat"
  return BytesToXorKey([]byte(dummy_pw)), nil
}

func TestOnlyAnotherPw() (types.SecretKey, error) {
  const dummy_pw = "mr_monkey"
  return BytesToXorKey([]byte(dummy_pw)), nil
}

func BytesToXorKey(pw []byte) types.SecretKey {
  hash := sha256.Sum256(pw)
  return types.SecretKey{hash[:]}
}

func NoCopyByteSliceToString(bytes []byte) string {
  hdr := *(*reflect.SliceHeader)(unsafe.Pointer(&bytes))
  return *(*string)(unsafe.Pointer(&reflect.StringHeader{
    Data: hdr.Data,
    Len:  hdr.Len,
  }))
}

func NoCopyStringToByteSlice(str string) []byte {
  hdr := *(*reflect.StringHeader)(unsafe.Pointer(&str))
  return *(*[]byte)(unsafe.Pointer(&reflect.SliceHeader{
    Data: hdr.Data,
    Len:  hdr.Len,
    Cap:  hdr.Len,
  }))
}

// Builds a stream with "Explicit initialization vectors" by prepending a single random block to the plaintext.
func AesStreamEncrypter(key types.SecretKey) cipher.Stream {
  block, err := aes.NewCipher(key.B)
  if err != nil { util.Fatalf("aes.NewCipher: %v", err) }
  iv := make([]byte, block.BlockSize())
  if _, err := io.ReadFull(rand.Reader, iv); err != nil {
    util.Fatalf("IV failed; %v", err)
  }
  return cipher.NewCFBEncrypter(block, iv)
}

// Builds a stream with "Explicit initialization vectors" by discarding the first block.
func AesStreamDecrypter(key types.SecretKey) cipher.Stream {
  block, err := aes.NewCipher(key.B)
  if err != nil { util.Fatalf("aes.NewCipher: %v", err) }
  null_iv := make([]byte, block.BlockSize())
  return cipher.NewCFBDecrypter(block, null_iv)
}

func AesEncryptString(key types.SecretKey, clear types.SecretString) types.PersistableString {
  null_first_block := make([]byte, aes.BlockSize)
  padded_obfus := make([]byte, len(clear.S) + aes.BlockSize)
  stream := AesStreamEncrypter(key)
  stream.XORKeyStream(padded_obfus, null_first_block)
  stream.XORKeyStream(padded_obfus[aes.BlockSize:], NoCopyStringToByteSlice(clear.S))
  return types.PersistableString{base64.StdEncoding.EncodeToString(padded_obfus)}
}

func AesDecryptString(key types.SecretKey, obfus types.PersistableString) (types.SecretString, error) {
  null_str := types.SecretString{""}
  obfus_bytes, err_dec := base64.StdEncoding.DecodeString(obfus.S)
  if err_dec != nil { return null_str, err_dec }
  if len(obfus_bytes) < aes.BlockSize {
    return null_str, fmt.Errorf("Obfuscated string is too short, expecting some larger than 1 block")
  }

  padded_plain := make([]byte, len(obfus_bytes))
  stream := AesStreamDecrypter(key)
  stream.XORKeyStream(padded_plain, obfus_bytes)
  plain := NoCopyByteSliceToString(padded_plain[aes.BlockSize:])
  return types.SecretString{plain}, nil
}

