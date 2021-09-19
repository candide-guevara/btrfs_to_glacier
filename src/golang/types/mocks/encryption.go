package mocks

import (
  "context"
  "io"

  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"
)

// Does not encrypt, just forwards the input.
type Codec struct {
  Err error
  Fingerprint  types.PersistableString
  GenKeySecret types.SecretKey
  GenKeyPersistable types.PersistableKey
}

func (self *Codec) CreateNewEncryptionKey() (types.PersistableKey, error) {
  return self.GenKeyPersistable, self.Err
}

func (self *Codec) CurrentKeyFingerprint() types.PersistableString {
  return self.Fingerprint
}

func (self *Codec) FingerprintKey(key types.SecretKey) types.PersistableString {
  return self.Fingerprint
}

func (self *Codec) EncryptString(clear types.SecretString) types.PersistableString {
  return types.PersistableString{clear.S}
}

func (self *Codec) DecryptString(
    key_fp types.PersistableString, obfus types.PersistableString) (types.SecretString, error) {
  return types.SecretString{obfus.S}, self.Err
}

func (self *Codec) EncryptStream(ctx context.Context, input io.ReadCloser) (io.ReadCloser, error) {
  if self.Err != nil { return nil, self.Err }
  pipe := NewPipe()
  go func() {
    var err error
    defer func() { util.ClosePipeWithError(pipe, err) }()
    defer func() { util.CloseWithError(input, err) }()
    if ctx.Err() != nil { return }
    _, err = io.Copy(pipe.WriteEnd(), input)
  }()
  return pipe.ReadEnd(), nil
}

func (self *Codec) DecryptStream(
    ctx context.Context, key_fp types.PersistableString, input io.ReadCloser) (io.ReadCloser, error) {
  return self.EncryptStream(ctx, input)
}

func (self *Codec) DecryptStreamInto(
    ctx context.Context, key_fp types.PersistableString, input io.ReadCloser, output io.Writer) (<-chan error) {
  done := make(chan error, 1)
  if self.Err != nil { done <- self.Err; close(done); return done }
  go func() {
    var err error
    defer close(done)
    defer func() { util.CloseWithError(input, err) }()
    if ctx.Err() != nil { return }
    _, err = io.Copy(output, input)
    done <- err
  }()
  return done
}

func (self *Codec) ReEncryptKeyring(pw_prompt func() ([]byte, error)) ([]types.PersistableKey, error) {
  return []types.PersistableKey{self.GenKeyPersistable}, nil
}
