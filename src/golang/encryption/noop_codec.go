package encryption

import (
  "context"
  "fmt"
  "io"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"
)

// Does not encrypt, just forwards the input.
type NoopCodec struct {}

func NewNoopCodec(conf *pb.Config) (*NoopCodec, error) {
  if len(conf.Encryption.Keys) > 0 {
    return nil, fmt.Errorf("For NoopCodec config cannot hold encryption keys")
  }
  return new(NoopCodec), nil
}

func (self *NoopCodec) EncryptionHeaderLen() int { return 0 }

func (self *NoopCodec) CreateNewEncryptionKey() (types.PersistableKey, error) {
  util.Fatalf("NoopCodec CreateNewEncryptionKey not supported")
  return types.PersistableKey{""}, nil
}

func (self *NoopCodec) CurrentKeyFingerprint() types.PersistableString {
  return types.PersistableString{"noop_codec"}
}

func (self *NoopCodec) EncryptString(clear types.SecretString) types.PersistableString {
  return types.PersistableString{clear.S}
}

func (self *NoopCodec) DecryptString(
    key_fp types.PersistableString, obfus types.PersistableString) (types.SecretString, error) {
  return types.SecretString{obfus.S}, nil
}

func (self *NoopCodec) EncryptStream(ctx context.Context, input types.ReadEndIf) (types.ReadEndIf, error) {
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

func (self *NoopCodec) DecryptStream(
    ctx context.Context, key_fp types.PersistableString, input types.ReadEndIf) (types.ReadEndIf, error) {
  return self.EncryptStream(ctx, input)
}

func (self *NoopCodec) DecryptStreamLeaveSinkOpen(
    ctx context.Context, key_fp types.PersistableString, input types.ReadEndIf, output io.WriteCloser) error {
  var err error
  defer func() { util.CloseWithError(input, err) }()
  defer func() { util.OnlyCloseWhenError(output, util.Coalesce(input.GetErr(), err)) }()
  if ctx.Err() != nil { return ctx.Err() }
  _, err = io.Copy(output, input)
  return err
}

func (self *NoopCodec) ReEncryptKeyring(pw_prompt types.PwPromptF) ([]types.PersistableKey, error) {
  util.Fatalf("NoopCodec ReEncryptKeyring not supported")
  return nil, nil
}

