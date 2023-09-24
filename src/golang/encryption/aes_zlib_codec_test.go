package encryption

import (
  "bytes"
  "context"
  "fmt"
  "io"
  "testing"
  "time"
  //pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/types/mocks"
  "btrfs_to_glacier/util"
)

// persisted=`python3 -c "print(b''.join((b'$secret'[i] ^ b'$xor_key'[i]).to_bytes(1,'big') for i in range(32)).hex(), end='')" | xxd -r -p | base64`
const persisted_key_1 = "OC0aSSg2woV0bUfw0Ew1+ej5fYCzzIPcTnqbtuKXzk8="
// fp=`sha512sum <(printf 'secret') | head -c 32 | xxd -r -p | base64`
const fp_persisted_key_1 = "vcshfZbP1EYCcGE66Cznmg=="
const secret_key_1 = "\xb5\x3b\x53\xcd\x7b\x86\xff\xc1\x54\xb4\x44\x92\x07\x52\x59\xcf\x53\xec\x19\x2e\x59\x9f\x70\xb3\x6e\x1d\xdd\x51\x29\xcd\x9f\x3a"
const persisted_key_2 = "auMCZBaDihSsq0rN8loA/i4OBdWcxcsLSEeWbmD/mDI="
const secret_key_2 = "\xe7\xf5\x4b\xe0\x45\x33\xb7\x50\x8c\x72\x49\xaf\x25\x44\x6c\xc8\x95\x1b\x61\x7b\x76\x96\x38\x64\x68\x20\xd0\x89\xab\xa5\xc9\x47"
const fp_persisted_key_2 = "RWgSa2EIDmUr5FFExM7AgQ=="
var init_keys []string

func buildTestCodec(t *testing.T) *aesZlibCodec {
  TestOnlyFlush()
  init_keys = []string {persisted_key_1, persisted_key_2,}
  return buildTestCodecChooseEncKey(t, init_keys)
}

func buildTestCodecChooseEncKey(t *testing.T, keys []string) *aesZlibCodec {
  conf := util.LoadTestConf()
  conf.Encryption.Keys = keys
  codec, err := NewCodecHelper(conf, TestOnlyFixedPw)
  if err != nil { t.Fatalf("Could not create codec: %v", err) }
  return codec.(*aesZlibCodec)
}

func TestAesZlibCodecGlobalState_BuildKeyring(t *testing.T) {
  keys := []string {persisted_key_1, persisted_key_2,}
  state := NewAesZlibCodecGlobalState()
  if err := state.DerivatePassphrase(false, TestOnlyFixedPw); err != nil {
    t.Fatalf("state.DerivatePassphrase: %v", err)
  }
  uniq_fp := make(map[string]bool)
  uniq_key := make(map[string]bool)
  expect_key_count := len(keys)

  for _,k := range keys {
    dec_key, fp := state.DecodeAndAddToKeyring(types.PersistableKey{k})
    uniq_fp[fp.S] = true
    uniq_key[string(dec_key.B)] = true
  }
  util.EqualsOrFailTest(t, "Bad uniq_fp", len(uniq_fp), expect_key_count)
  util.EqualsOrFailTest(t, "Bad uniq_key", len(uniq_key), expect_key_count)
  util.EqualsOrFailTest(t, "Bad keyring", len(state.Keyring), expect_key_count)
}

func TestAesZlibCodecGlobalState_BuildKeyring_Idempotent(t *testing.T) {
  keys := []string {persisted_key_1, persisted_key_2, persisted_key_1, persisted_key_2, persisted_key_2,}
  state := NewAesZlibCodecGlobalState()
  if err := state.DerivatePassphrase(false, TestOnlyFixedPw); err != nil {
    t.Fatalf("state.DerivatePassphrase: %v", err)
  }
  expect_key_count := 2

  for _,k := range keys {
    state.DecodeAndAddToKeyring(types.PersistableKey{k})
  }
  util.EqualsOrFailTest(t, "Bad keyring", len(state.Keyring), expect_key_count)
}

func TestCodecDefaultKey(t *testing.T) {
  codec := buildTestCodec(t)
  first_persisted := types.PersistableKey{codec.conf.Encryption.Keys[0]}
  first_secret := TestOnlyDecodeEncryptionKey(first_persisted)
  first_fp := FingerprintKey(first_secret)
  if codec.cur_fp.S != first_fp.S { t.Errorf("Wrong default fingerprint, must be first in config.") }
  if bytes.Compare(first_secret.B, codec.cur_key.B) != 0 {
    t.Errorf("Bad persisted key decoding: %x != %x", first_secret.B, secret_key_1)
  }
}

func TestCreateNewEncryptionKey(t *testing.T) {
  codec := buildTestCodec(t)
  old_fp := codec.CurrentKeyFingerprint()
  old_key := codec.cur_key
  expect_key_count := len(init_keys) + 1

  persisted, err := codec.CreateNewEncryptionKey()
  if err != nil { t.Fatalf("Could not create new key: %v", err) }
  if len(persisted.S) < 1 { t.Errorf("Bad persisted key") }
  if old_fp.S == codec.cur_fp.S || len(codec.cur_fp.S) < 1 {
    t.Errorf("Bad new fingerprint")
  }
  if bytes.Compare(old_key.B, codec.cur_key.B) == 0 || len(codec.cur_key.B) < 1 {
    t.Errorf("Bad new secret key")
  }
  util.EqualsOrFailTest(t, "Bad key count", TestOnlyKeyCount(), expect_key_count)
}

func QuickEncryptString(
    t *testing.T, codec types.Codec, plain string) []byte {
  ctx,cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  read_pipe := util.ReadEndFromBytes([]byte(plain))
  encoded_pipe, err := codec.EncryptStream(ctx, read_pipe)
  if err != nil { t.Fatalf("Could not encrypt: %v", err) }

  done := make(chan []byte)
  go func() {
    defer close(done)
    data, err := io.ReadAll(encoded_pipe)
    if err != nil { t.Errorf("ReadAll: %v", err) }
    done <- data
  }()

  select {
    case data := <-done: return data
    case <-ctx.Done(): t.Fatalf("QuickEncryptString timeout")
  }
  return nil
}

func QuickDecryptString(
    t *testing.T, codec types.Codec, obfus []byte) string {
  ctx,cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  read_pipe := util.ReadEndFromBytes(obfus)
  encoded_pipe, err := codec.DecryptStream(ctx, types.CurKeyFp, read_pipe)
  if err != nil { t.Fatalf("Could not decrypt: %v", err) }

  done := make(chan []byte)
  go func() {
    defer close(done)
    data, err := io.ReadAll(encoded_pipe)
    if err != nil { t.Errorf("ReadAll: %v", err) }
    done <- data
  }()

  select {
    case data := <-done: return string(data)
    case <-ctx.Done(): t.Fatalf("QuickDecryptString timeout")
  }
  return ""
}

func TestReEncryptKeyring(t *testing.T) {
  expect_plain := "chocoloco plain text"
  codec := buildTestCodec(t)
  obfus := QuickEncryptString(t, codec, expect_plain)
  expect_key_count := len(init_keys)

  persisted_keys, err := codec.ReEncryptKeyring(TestOnlyAnotherPw)
  if err != nil { t.Fatalf("Could not re-encrypt: %v", err) }
  if len(persisted_keys) != expect_key_count { t.Fatalf("Bad number of keys") }
  util.EqualsOrFailTest(t, "Bad key count", TestOnlyKeyCount(), expect_key_count)

  new_conf := util.LoadTestConf()
  for _,k := range persisted_keys {
    //t.Logf("Adding persisted key: %x", k.S)
    new_conf.Encryption.Keys = append(new_conf.Encryption.Keys, k.S)
    for _,old_k := range codec.conf.Encryption.Keys {
      if old_k == k.S { t.Fatalf("Re-encrypted keys are the same: %v", k.S) }
    }
  }
  new_codec, err2 := NewCodecHelper(new_conf, TestOnlyAnotherPw)
  if err2 != nil { t.Fatalf("Could not create codec: %v", err2) }

  plain := QuickDecryptString(t, new_codec, obfus)
  util.EqualsOrFailTest(t, "Bad decryption", plain, expect_plain)
}

func TestReEncryptKeyring_WithFlush(t *testing.T) {
  expect_plain := "chocoloco plain text"
  codec := buildTestCodec(t)
  obfus := QuickEncryptString(t, codec, expect_plain)

  persisted_keys, err := codec.ReEncryptKeyring(TestOnlyAnotherPw)
  if err != nil { t.Fatalf("Could not re-encrypt: %v", err) }

  new_conf := util.LoadTestConf()
  for _,k := range persisted_keys {
    new_conf.Encryption.Keys = append(new_conf.Encryption.Keys, k.S)
  }

  TestOnlyFlush()
  new_codec, err2 := NewCodecHelper(new_conf, TestOnlyAnotherPw)
  if err2 != nil { t.Fatalf("Could not create codec: %v", err2) }

  plain := QuickDecryptString(t, new_codec, obfus)
  util.EqualsOrFailTest(t, "Bad decryption", plain, expect_plain)
}

func TestSecretToPersistedKey(t *testing.T) {
  codec := buildTestCodec(t)
  persisted, err := codec.CreateNewEncryptionKey()
  if err != nil { t.Fatalf("Could not create new key: %v", err) }
  secret := codec.cur_key
  t.Logf("secret:%x, persisted:%s", secret.B, persisted.S)

  dec_persisted := TestOnlyDecodeEncryptionKey(persisted)
  if bytes.Compare(secret.B, dec_persisted.B) != 0 {
    t.Errorf("Bad persisted key decoding: %x != %x", secret.B, dec_persisted.B)
  }
  persisted_p := TestOnlyEncodeEncryptionKey(dec_persisted)
  if persisted_p.S != persisted.S {
    t.Errorf("Persisted key round trip: %x != %x", persisted_p.S, persisted.S)
  }
  enc_secret := TestOnlyEncodeEncryptionKey(secret)
  if enc_secret.S != persisted.S {
    t.Errorf("Bad secret key encoding: %x != %x", enc_secret.S, persisted.S)
  }
  secret_p := TestOnlyDecodeEncryptionKey(enc_secret)
  if bytes.Compare(secret.B, secret_p.B) != 0 {
    t.Errorf("Secret key round trip: %x != %x", secret.B, secret_p.B)
  }
}

func TestFingerprintKey(t *testing.T) {
  fp := FingerprintKey(types.SecretKey{[]byte(secret_key_1)})
  t.Logf("persisted:%s, fingerprint:%s", persisted_key_1, fp)
  if fp.S != fp_persisted_key_1 { t.Errorf("Bad fingerprint calculation: %s != %s", fp, fp_persisted_key_1) }
}

type source_t struct { io.ReadCloser ; closed bool }
func (self *source_t) Close() error { self.closed = true; return nil }
func (self *source_t) GetErr() error { return nil }
func TestEncryptStream_ClosesStreams(t *testing.T) {
  codec := buildTestCodec(t)
  read_pipe := &source_t{ ReadCloser:io.NopCloser(bytes.NewReader([]byte("coucou"))), }
  ctx,cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  encoded_pipe, err := codec.EncryptStream(ctx, read_pipe)
  if err != nil { t.Fatalf("Could not encrypt: %v", err) }

  done := make(chan error)
  go func() {
    defer close(done)
    defer encoded_pipe.Close()
    _, err := io.ReadAll(encoded_pipe) // only returns if codec closes the write end.
    if err != nil { t.Errorf("ReadAll: %v", err) }
  }()

  util.WaitForClosure(t, ctx, done)
  if !read_pipe.closed { t.Errorf("source not closed") }
}

type decrypt_f = func(types.Codec, context.Context, types.ReadEndIf) (io.ReadCloser, error)
func testEncryptDecryptStream_Helper(
    t *testing.T, read_pipe types.ReadEndIf, decrypt_lambda decrypt_f) []byte {
  codec := buildTestCodec(t)
  ctx,cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  var err error
  encoded_pipe, err := codec.EncryptStream(ctx, read_pipe)
  if err != nil { t.Fatalf("Could not encrypt: %v", err) }
  decoded_pipe, err := decrypt_lambda(codec, ctx, encoded_pipe)
  if err != nil { t.Fatalf("Could not decrypt: %v", err) }

  done := make(chan []byte)
  go func() {
    defer close(done)
    defer decoded_pipe.Close()
    data, err := io.ReadAll(decoded_pipe)
    if err != nil { t.Errorf("ReadAll: %v", err) }
    done <- data
  }()

  var data []byte
  select {
    case data = <-done:
    case <-ctx.Done(): t.Fatalf("testEncryptDecryptStream_Helper timeout")
  }
  return data
}

func TestEncryptStream_Simple(t *testing.T) {
  expect_msg := []byte("this is some plain text data")
  read_pipe := mocks.NewPreloadedPipe(expect_msg).ReadEnd()
  decrypt_lambda := func(
      codec types.Codec, ctx context.Context, input types.ReadEndIf) (io.ReadCloser, error) {
    return codec.DecryptStream(ctx, types.CurKeyFp, input)
  }
  data := testEncryptDecryptStream_Helper(t, read_pipe, decrypt_lambda)
  util.EqualsOrFailTest(t, "Bad encryption", data, expect_msg)
}

func TestEncryptStream_NonCurrentKey(t *testing.T) {
  expect_msg := []byte("this is some plain text data")
  read_pipe := mocks.NewPreloadedPipe(expect_msg).ReadEnd()
  decrypt_lambda := func(
      codec types.Codec, ctx context.Context, input types.ReadEndIf) (io.ReadCloser, error) {
    dec_fp := codec.CurrentKeyFingerprint()
    _, err := codec.CreateNewEncryptionKey()
    if err != nil { t.Fatalf("Could not create new key: %v", err) }
    return codec.DecryptStream(ctx, dec_fp, input)
  }
  data := testEncryptDecryptStream_Helper(t, read_pipe, decrypt_lambda)
  util.EqualsOrFailTest(t, "Bad encryption", data, expect_msg)
}

func TestEncryptStreamInto_SmallMsg(t *testing.T) {
  expect_msg := []byte("this is some plain text data")
  read_pipe := mocks.NewPreloadedPipe(expect_msg).ReadEnd()
  decrypt_lambda := func(
      codec types.Codec, ctx context.Context, input types.ReadEndIf) (io.ReadCloser, error) {
    pipe := util.NewInMemPipe(ctx)
    go func() {
      defer pipe.WriteEnd().Close()
      err := codec.DecryptStreamLeaveSinkOpen(ctx, types.CurKeyFp, input, pipe.WriteEnd())
      if err != nil { util.Fatalf("codec.DecryptStreamLeaveSinkOpen: %v", err) }
    }()
    return pipe.ReadEnd(), nil
  }
  data := testEncryptDecryptStream_Helper(t, read_pipe, decrypt_lambda)
  util.EqualsOrFailTest(t, "Bad encryption", data, expect_msg)
}

func TestEncryptStream_MoreData(t *testing.T) {
  read_pipe := util.ProduceRandomTextIntoPipe(context.TODO(), 4096, 32)
  decrypt_lambda := func(
      codec types.Codec, ctx context.Context, input types.ReadEndIf) (io.ReadCloser, error) {
    return codec.DecryptStream(ctx, types.CurKeyFp, input)
  }
  data := testEncryptDecryptStream_Helper(t, read_pipe, decrypt_lambda)
  util.EqualsOrFailTest(t, "Bad encryption len", len(data), 4096*32)
}

func TestEncryptStream_CompressibleData(t *testing.T) {
  ctx,cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  alphabet := []byte("repeat this short message forever and ever.")
  expect_msg := bytes.Repeat(alphabet, 1024)
  read_pipe := mocks.NewBigPreloadedPipe(ctx, expect_msg).ReadEnd()
  codec := buildTestCodec(t)

  var data_cod []byte
  done_cod := make(chan []byte)
  encoded_pipe, err := codec.EncryptStream(ctx, read_pipe)
  if err != nil { t.Fatalf("Could not encrypt: %v", err) }
  go func() {
    defer close(done_cod)
    defer encoded_pipe.Close()
    data, err := io.ReadAll(encoded_pipe)
    if err != nil { t.Errorf("ReadAll coding: %v", err) }
    done_cod <- data
  }()
  select {
    case data_cod = <-done_cod:
    case <-ctx.Done(): t.Fatalf("TestEncryptStream_CompressibleData coding timeout")
  }

  var data_dec []byte
  done_dec := make(chan []byte)
  coded_input := mocks.NewBigPreloadedPipe(ctx, data_cod).ReadEnd()
  decoded_pipe, err := codec.DecryptStream(ctx, types.CurKeyFp, coded_input)
  if err != nil { t.Fatalf("Could not decrypt: %v", err) }
  go func() {
    defer close(done_dec)
    defer decoded_pipe.Close()
    data, err := io.ReadAll(decoded_pipe)
    if err != nil { t.Errorf("ReadAll decoding: %v", err) }
    done_dec <- data
  }()
  select {
    case data_dec = <-done_dec:
    case <-ctx.Done(): t.Fatalf("TestEncryptStream_CompressibleData decoding timeout")
  }

  if bytes.Compare(data_dec, expect_msg) != 0 {
    t.Errorf("Bad encryption: %d / %d", len(expect_msg), len(data_dec))
  }
  if float64(len(data_cod)) > 0.5 * float64(len(expect_msg)) {
    t.Errorf("Bad compression: %d / %d", len(expect_msg), len(data_cod))
  }
}

func TestEncryptStreamInto_MoreData(t *testing.T) {
  read_pipe := util.ProduceRandomTextIntoPipe(context.TODO(), 4096, 32)
  decrypt_lambda := func(
      codec types.Codec, ctx context.Context, input types.ReadEndIf) (io.ReadCloser, error) {
    pipe := util.NewInMemPipe(ctx)
    go func() {
      defer pipe.WriteEnd().Close()
      err := codec.DecryptStreamLeaveSinkOpen(ctx, types.CurKeyFp, input, pipe.WriteEnd())
      if err != nil { util.Fatalf("codec.DecryptStreamLeaveSinkOpen: %v", err) }
    }()
    return pipe.ReadEnd(), nil
  }
  data := testEncryptDecryptStream_Helper(t, read_pipe, decrypt_lambda)
  util.EqualsOrFailTest(t, "Bad encryption len", len(data), 4096*32)
}

func TestDecryptStreamLeaveSinkOpen_OutputRemainsOpen(t *testing.T) {
  read_pipe := util.ProduceRandomTextIntoPipe(context.TODO(), 32, 1)
  pipe := util.NewFileBasedPipe(context.TODO()) // we use a file to avoid blocking on the last write
  decrypt_lambda := func(
      codec types.Codec, ctx context.Context, input types.ReadEndIf) (io.ReadCloser, error) {
    reader := util.NewLimitedReadEnd(pipe.ReadEnd(), 32) 
    codec.DecryptStreamLeaveSinkOpen(ctx, types.CurKeyFp, input, pipe.WriteEnd())
    return reader, nil
  }
  testEncryptDecryptStream_Helper(t, read_pipe, decrypt_lambda)
  select { case <-time.After(util.SmallTimeout): }
  _, err := pipe.WriteEnd().Write([]byte("coucou"))
  if err != nil { t.Errorf("could not write after decryption: %v", err) }
}

type streamf_t = func(context.Context, types.ReadEndIf) (types.ReadEndIf, error)
func testStream_TimeoutContinousReadUntilDeadline_Helper(t *testing.T, stream_f streamf_t) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  read_pipe := util.ProduceRandomTextIntoPipe(context.TODO(), 4096, /*infinite*/0)

  timely_close := make(chan bool)

  out, err := stream_f(ctx, read_pipe)
  if err != nil { t.Fatalf("Could process stream: %v", err) }
  go func() {
    buf := make([]byte, 32)
    defer out.Close()
    defer close(timely_close)
    for {
      _,err := out.Read(buf)
      if err != nil { return }
    }
  }()

  select {
    case <-timely_close:
    case <-time.After(util.LargeTimeout):
      t.Fatalf("codec did not react to context timeout: %v", ctx.Err())
  }
}

func testStream_TimeoutReadAfterClose_Helper(t *testing.T, stream_f streamf_t) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  read_pipe := util.ProduceRandomTextIntoPipe(context.TODO(), 4096, /*infinite*/0)

  timely_close := make(chan bool)
  out, err := stream_f(ctx, read_pipe)
  if err != nil { t.Fatalf("Could process stream: %v", err) }

  go func() {
    defer close(timely_close)
    defer out.Close()
    buf := make([]byte, 32)
    select { case <-ctx.Done(): }
    select { case <-time.After(util.SmallTimeout): out.Read(buf) }
  }()

  // Wait until we are done
  select {
    case <-timely_close: return
    case <-time.After(util.LargeTimeout):
      t.Fatalf("codec did not react to context timeout.")
  }
}

func TestEncryptStream_TimeoutContinousReads(t *testing.T) {
  codec := buildTestCodec(t)
  stream_f := func(ctx context.Context, in types.ReadEndIf) (types.ReadEndIf, error) {
    return codec.EncryptStream(ctx, in)
  }
  testStream_TimeoutContinousReadUntilDeadline_Helper(t, stream_f)
}

func TestDecryptStream_TimeoutContinousReads(t *testing.T) {
  codec := buildTestCodec(t)
  stream_f := func(ctx context.Context, in types.ReadEndIf) (types.ReadEndIf, error) {
    return codec.DecryptStream(ctx, types.CurKeyFp, in)
  }
  testStream_TimeoutContinousReadUntilDeadline_Helper(t, stream_f)
}

func TestDecryptStreamLeaveSinkOpen_TimeoutBlockingWrite(t *testing.T) {
  codec := buildTestCodec(t)
  stream_f := func(ctx context.Context, in types.ReadEndIf) (types.ReadEndIf, error) {
    write_end := util.NewWriteEndBlock(ctx, util.TestTimeout * 2)
    err := codec.DecryptStreamLeaveSinkOpen(ctx, types.CurKeyFp, in, write_end)
    if err == nil { t.Fatalf("codec.DecryptStreamLeaveSinkOpen should return err on blocking write") }
    return util.ReadEndFromBytes(nil), nil
  }
  testStream_TimeoutContinousReadUntilDeadline_Helper(t, stream_f)
}

func TestDecryptStreamLeaveSinkOpen_TimeoutContinousReads(t *testing.T) {
  codec := buildTestCodec(t)
  stream_f := func(ctx context.Context, in types.ReadEndIf) (types.ReadEndIf, error) {
    pipe := util.NewInMemPipe(ctx)
    go func() {
      if ctx.Err() != nil { util.Fatalf("wtf") }
      if codec.DecryptStreamLeaveSinkOpen(ctx, types.CurKeyFp, in, pipe.WriteEnd()) == nil {
        util.Fatalf("codec.DecryptStreamLeaveSinkOpen should return err, ctx: %v", ctx.Err())
      }
    }()
    return pipe.ReadEnd(), nil
  }
  testStream_TimeoutContinousReadUntilDeadline_Helper(t, stream_f)
}

func TestEncryptStream_TimeoutReadAfterClose(t *testing.T) {
  codec := buildTestCodec(t)
  stream_f := func(ctx context.Context, in types.ReadEndIf) (types.ReadEndIf, error) {
    return codec.EncryptStream(ctx, in)
  }
  testStream_TimeoutReadAfterClose_Helper(t, stream_f)
}

func TestDecryptStream_TimeoutReadAfterClose(t *testing.T) {
  codec := buildTestCodec(t)
  stream_f := func(ctx context.Context, in types.ReadEndIf) (types.ReadEndIf, error) {
    return codec.DecryptStream(ctx, types.CurKeyFp, in)
  }
  testStream_TimeoutReadAfterClose_Helper(t, stream_f)
}

func TestDecryptStreamLeaveSinkOpen_TimeoutReadAfterClose(t *testing.T) {
  codec := buildTestCodec(t)
  stream_f := func(ctx context.Context, in types.ReadEndIf) (types.ReadEndIf, error) {
    pipe := util.NewInMemPipe(ctx)
    go func() {
      err := codec.DecryptStreamLeaveSinkOpen(ctx, types.CurKeyFp, in, pipe.WriteEnd())
      if err == nil { util.Fatalf("codec.DecryptStreamLeaveSinkOpen reading after timeout should return error") }
    }()
    return pipe.ReadEnd(), nil
  }
  testStream_TimeoutReadAfterClose_Helper(t, stream_f)
}

func HelperEncryptStream_ErrPropagation(t *testing.T, err_injector func(types.Pipe)) {
  ctx,cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  codec := buildTestCodec(t)
  pipes := []types.Pipe{
    mocks.NewPreloadedPipe(util.GenerateRandomTextData(24)),
    util.NewFileBasedPipe(ctx),
    util.NewInMemPipe(ctx),
  }
  for _,pipe := range pipes {
    err_injector(pipe)
    encoded_pipe, err := codec.EncryptStream(ctx, pipe.ReadEnd())
    if err != nil { t.Logf("Could not encrypt: %v", err) }

    done := make(chan error)
    go func() {
      defer close(done)
      defer encoded_pipe.Close()
      data,_ := io.ReadAll(encoded_pipe)
      if encoded_pipe.GetErr() == nil { t.Errorf("Expected error propagation") }
      // Cannot guarantee an error will prevent garbage to be written
      if len(data) > codec.EncryptionHeaderLen() {
        t.Logf("Wrote %d bytes despite error input", len(data))
      }
    }()
    util.WaitForClosure(t, ctx, done)
  }
}
func TestEncryptStream_PrematurelyClosedInput(t *testing.T) {
  err_injector := func(p types.Pipe) { p.ReadEnd().Close() }
  HelperEncryptStream_ErrPropagation(t, err_injector)
}
func TestEncryptStream_WriteEndError(t *testing.T) {
  err_injector := func(p types.Pipe) { p.WriteEnd().SetErr(fmt.Errorf("inject_err")) }
  HelperEncryptStream_ErrPropagation(t, err_injector)
}

func HelperDecryptStream_ErrPropagation(t *testing.T, err_injector func(types.Pipe)) {
  ctx,cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  codec := buildTestCodec(t)
  pipes := []types.Pipe{
    mocks.NewPreloadedPipe(util.GenerateRandomTextData(99)),
    util.NewFileBasedPipe(ctx),
    util.NewInMemPipe(ctx),
  }
  for _,pipe := range pipes {
    err_injector(pipe)
    decoded_pipe, err := codec.DecryptStream(ctx, types.CurKeyFp, pipe.ReadEnd())
    if err != nil { t.Logf("Could not decrypt: %v", err) }
    // If we detect the error early no pipe is created.
    if decoded_pipe == nil { break }

    done := make(chan error)
    go func() {
      defer close(done)
      defer decoded_pipe.Close()
      data,_ := io.ReadAll(decoded_pipe)
      if decoded_pipe.GetErr() == nil { t.Errorf("Expected error propagation") }
      // Cannot guarantee an error will prevent garbage to be written
      if len(data) > 0 { t.Logf("Wrote %d bytes despite closed input", len(data)) }
    }()
    util.WaitForClosure(t, ctx, done)
  }
}
func TestDecryptStream_PrematurelyClosedInput(t *testing.T) {
  err_injector := func(p types.Pipe) { p.ReadEnd().Close() }
  HelperDecryptStream_ErrPropagation(t, err_injector)
}
func TestDecryptStream_WriteEndError(t *testing.T) {
  err_injector := func(p types.Pipe) { p.WriteEnd().SetErr(fmt.Errorf("inject_err")) }
  HelperDecryptStream_ErrPropagation(t, err_injector)
}

func HelperDecryptStreamLeaveSinkOpen_ErrPropagation(t *testing.T, err_injector func(types.Pipe)) {
  ctx,cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  sink := util.NewBufferWriteEnd()
  pipe := mocks.NewPreloadedPipe(util.GenerateRandomTextData(24))
  err_injector(pipe)
  codec := buildTestCodec(t)

  err := codec.DecryptStreamLeaveSinkOpen(ctx, types.CurKeyFp, pipe.ReadEnd(), sink)
  if err == nil { t.Errorf("Expected error propagation: %v", err) }
  // Cannot guarantee an error will prevent garbage to be written
  if sink.Len() > 0 { t.Logf("Wrote %d bytes despite closed input", sink.Len()) }
}
func TestDecryptStreamLeaveSinkOpen_PrematurelyClosedInput(t *testing.T) {
  err_injector := func(p types.Pipe) { p.ReadEnd().Close() }
  HelperDecryptStreamLeaveSinkOpen_ErrPropagation(t, err_injector)
}
func TestDecryptStreamLeaveSinkOpen_WriteEndError(t *testing.T) {
  err_injector := func(p types.Pipe) { p.WriteEnd().SetErr(fmt.Errorf("inject_err")) }
  HelperDecryptStreamLeaveSinkOpen_ErrPropagation(t, err_injector)
}

