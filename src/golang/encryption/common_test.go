package encryption

import (
  "testing"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"
)

func TestAesEncryptDecryptString(t *testing.T) {
  key, _ := TestOnlyFixedPw()
  expect_plain := types.SecretString{"chocoloco plain text"}
  obfus := AesEncryptString(key, expect_plain)
  obfus_2 := AesEncryptString(key, expect_plain)
  if obfus.S  == obfus_2.S {
    t.Errorf("Encrypt of the same string should not produce the same obfuscated bytes")
  }

  plain, err := AesDecryptString(key, obfus)
  if err != nil { t.Fatalf("Could not decrypt: %v", err) }

  t.Logf("obfuscated:%x, plain:%s", obfus, plain)
  util.EqualsOrFailTest(t, "Bad decryption", plain, expect_plain)
}

