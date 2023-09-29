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

func (self *Codec) EncryptionHeaderLen() int { return 0 }

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

func (self *Codec) EncryptStream(ctx context.Context, input types.ReadEndIf) (types.ReadEndIf, error) {
  if self.Err != nil { return nil, self.Err }
  pipe := util.NewFileBasedPipe(ctx)
  go func() {
    var err error
    defer func() { util.CloseWriteEndWithError(pipe, util.Coalesce(input.GetErr(), err)) }()
    defer func() { util.CloseWithError(input, err) }()
    if ctx.Err() != nil { return }
    _, err = io.Copy(pipe.WriteEnd(), input)
  }()
  return pipe.ReadEnd(), nil
}

func (self *Codec) DecryptStream(
    ctx context.Context, key_fp types.PersistableString, input types.ReadEndIf) (types.ReadEndIf, error) {
  return self.EncryptStream(ctx, input)
}

func (self *Codec) DecryptStreamLeaveSinkOpen(
    ctx context.Context, key_fp types.PersistableString, input types.ReadEndIf, output io.WriteCloser) error {
  if self.Err != nil { return self.Err }
  var err error
  defer func() { util.CloseWithError(input, err) }()
  defer func() { util.OnlyCloseWhenError(output, util.Coalesce(input.GetErr(), err)) }()
  if ctx.Err() != nil { return ctx.Err() }
  _, err = io.Copy(output, input)
  return err
}

func (self *Codec) OutputEncryptedKeyring(
    pw_prompt types.PwPromptF) ([]types.PersistableKey, types.PersistableString, error) {
  return []types.PersistableKey{self.GenKeyPersistable}, types.PersistableString{""}, nil
}

