package types

import "context"
import "io"

// A version of `SecretKey` that has been encrypted.
// No secret can be deduced from a `PersistableKey` (unless the key-encrypting key is unknown).
// (PS: In go you cannot embed slice types.)
type PersistableKey struct { S string }
type SecretKey struct { B []byte }
type PersistableString struct { S string }
type SecretString struct { S string }

// Constant used when calling Decrypt functions, it signifies to use the current key for decryption.
var CurKeyFp = PersistableString{""}

// Returns the hashed content from a passphrase input by the user.
type PwPromptF = func() (SecretKey, error)

// Not thread-safe, `CreateNewEncryptionKey` may cause concurrent streams to be de/encrypted with different keys.
type Keyring interface {
  // Generates a random encryption key of a suitable length for the encryption algo.
  // The new key is stored in the keyring so that subsequent encrypts will use that key.
  // Returns a derived key that can be persisted.
  CreateNewEncryptionKey() (PersistableKey, error)
  // Returns the fingerprint of the secret key used to encrypt.
  CurrentKeyFingerprint() PersistableString
  // Encrypts all secret keys in the keyring with `pw_prompt`.
  // Does NOT change any internal state to prevent mixing different passwords.
  // Returns the re-encrypted keys in the keyword and the hash of all unencrypted keys.
  // That hash can later be used to detect tampering and password typos.
  // Respects the order of keys to keep the same current key.
  OutputEncryptedKeyring(pw_prompt PwPromptF) ([]PersistableKey, PersistableString, error)
}

// Encryption is a double edge sword.
// If a backup really needs to be done from scratch we need a way to retrieve the keys used to encrypt it.
// Ultimatelly only 2 passwords need to be remembered by a human :
// * The cloud provider login
// * The passphrase to decrypt the keys used to encrypt the backup data
type Codec interface {
  Keyring
  // Returns the header (aka IV) added to the beginning of encrypted streams.
  // Depending on the block chaining type it may be 0.
  EncryptionHeaderLen() int
  // Encrypts `input` and outputs obfuscated bytes to a new ReadEndIf.
  // Takes ownership of `input` and will close it once done.
  EncryptStream(ctx context.Context, input ReadEndIf) (ReadEndIf, error)
  // Decrypts `input` and outputs plaintext bytes to a new ReadEndIf.
  // `key_fp` may be left empty to use the current encryption key.
  // Takes ownership of `input` and will close it once done.
  DecryptStream(ctx context.Context, key_fp PersistableString, input ReadEndIf) (ReadEndIf, error)
  // Decrypts `input` and outputs plaintext bytes into `output`.
  // `key_fp` may be left empty to use the current encryption key.
  // Takes ownership of `input` and will close it once done.
  // `output` will NOT be closed (unless there is an error) so that it can be reused.
  // Returns when the whole stream has been decrypted.
  DecryptStreamLeaveSinkOpen(ctx context.Context, key_fp PersistableString, input ReadEndIf, output io.WriteCloser) error
}

