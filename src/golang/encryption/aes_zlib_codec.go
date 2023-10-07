package encryption

import (
  "bytes"
  "context"
  "crypto/aes"
  "crypto/cipher"
  "crypto/rand"
  "crypto/sha512"
  "encoding/base64"
  "errors"
  "fmt"
  "io"
  "strings"
  "sync"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"
)

const AES_256_KEY_LEN = 32
var ErrNoCurrentKey = errors.New("no_current_key_loaded")

type FpKeyPair struct {
  Fp  types.PersistableString
  Key types.SecretKey
}

// Keeps key material in global state to ask for passwords just once.
type AesZlibCodecGlobalState struct {
  Mutex   *sync.Mutex
  Keyring []FpKeyPair
  XorKey  types.SecretKey
}
var globalState AesZlibCodecGlobalState

func NewAesZlibCodecGlobalState() *AesZlibCodecGlobalState {
  return &AesZlibCodecGlobalState{
    Mutex: new(sync.Mutex),
    Keyring: make([]FpKeyPair, 0),
    XorKey: types.SecretKey{[]byte("")},
  }
}

func init() {
  globalState = *NewAesZlibCodecGlobalState()
}

// This class uses "Explicit initialization vectors" by prepending a single random block to the plaintext.
// This way the Init Vector does not need to be stored anywhere.
type aesZlibCodec struct {
  conf       *pb.Config
  block_size int
  cur_fp     types.PersistableString
  cur_key    types.SecretKey
}

func NewCodec(conf *pb.Config) (types.Codec, error) {
  pw_prompt := BuildPwPromt("AesCodec input password to decrypt keyring: ")
  return NewCodecHelper(conf, pw_prompt)
}

func NewCodecHelper(conf *pb.Config, pw_prompt types.PwPromptF) (types.Codec, error) {
  codec := &aesZlibCodec{
    conf: conf,
    block_size: aes.BlockSize,
  }

  var err error
  codec.cur_key, codec.cur_fp, err = globalState.LoadKeyring(pw_prompt, conf.Encryption.Keys)
  if err != nil { return nil, err }

  if len(conf.Encryption.Hash) != 0 {
    if len(conf.Encryption.Keys) == 0 {
      return nil, fmt.Errorf("No encryption keys in the configuration")
    }
    hash, err := globalState.CalculateKeyringHash()
    if err != nil { return nil, err }
    if strings.Compare(hash.S, conf.Encryption.Hash) != 0 {
      return nil, fmt.Errorf("CompareKeyringToHash: '%s' != '%s'", hash.S, conf.Encryption.Hash)
    }
  }
  return codec, nil
}

// IMPORTANT: Will not ask for password twice.
// If `LoadKeyring` is called for different configurations there is undefined behavior.
// If `LoadKeyring` is called for the same configuration but keys have been added to the keyring there is undefined behavior.
func (self *AesZlibCodecGlobalState) LoadKeyring(
    pw_prompt types.PwPromptF, persisted_keys []string) (types.SecretKey, types.PersistableString, error) {
  null_fp := types.PersistableString{""}
  null_key := types.SecretKey{[]byte("")}
  self.Mutex.Lock()
  defer self.Mutex.Unlock()

  if len(self.XorKey.B) == 0 {
    //return null_key, null_fp, fmt.Errorf("Cannot load twice to prevent mixing keys with different encryptions.")
    hash_pw, err := pw_prompt()
    if err != nil { return null_key, null_fp, err }
    self.XorKey = hash_pw
  } else if len(persisted_keys) != 0 {
    return self.Keyring[0].Key, self.Keyring[0].Fp, nil
  }
  if len(persisted_keys) == 0 { return null_key, null_fp, nil }

  for _,k := range persisted_keys {
    dec_key := decodeEncryptionKey(types.PersistableKey{k}, self.XorKey)
    fp := FingerprintKey(dec_key)
    // Noop if key is already in globalState.Keyring
    self.Keyring = append(self.Keyring, FpKeyPair{fp, dec_key})
  }
  // Use the first key in the keyring to encrypt.
  return self.Keyring[0].Key, self.Keyring[0].Fp, nil
}

func (self *AesZlibCodecGlobalState) OutputEncryptedKeyring(
    pw_prompt types.PwPromptF) ([]types.PersistableKey, types.PersistableString, error) {
  null_hash := types.PersistableString{""}
  if len(self.Keyring) == 0 {
    return nil, null_hash, fmt.Errorf("OutputEncryptedKeyring: Keyring is empty")
  }

  self.Mutex.Lock()
  var err error
  xor_key := self.XorKey
  if pw_prompt != nil {
    xor_key, err = pw_prompt()
    if err != nil { return nil, null_hash, err }
  }
  keys := make([]types.PersistableKey, 0, len(self.Keyring))
  for _,pair := range self.Keyring {
    enc_key := encodeEncryptionKey(pair.Key, xor_key)
    keys = append(keys, enc_key)
  }

  self.Mutex.Unlock()
  hash, err := self.CalculateKeyringHash()
  return keys, hash, err
}

func (self *AesZlibCodecGlobalState) CalculateKeyringHash() (types.PersistableString, error) {
  k_salt := []byte("\xf7\x47\x2b\x45\x4b\x1e\xf8\x45\xe6\x23\x67\xbd\xbf\x05\x1a\x0a\xd9\x7a\x6d\xa3\xd1\xa4\x8e\x52\x00\x62\x95\x0b\xa9\x92\x37\xcd")
  null_hash := types.PersistableString{""}
  self.Mutex.Lock()
  defer self.Mutex.Unlock()
  buf_len := AES_256_KEY_LEN * (len(self.Keyring) + 2)
  backing := make([]byte, 0, buf_len)
  buf := bytes.NewBuffer(backing)

  _, err := buf.Write(k_salt)
  if err != nil { return null_hash, err }
  for _,pair := range self.Keyring {
    _, err := buf.Write(pair.Key.B)
    if err != nil { return null_hash, err }
  }
  if buf.Cap() != buf_len {
    return null_hash, fmt.Errorf("CalculateKeyringHash: bad buffer initial size")
  }
  raw_hash := sha512.Sum512(buf.Bytes())
  copy(backing, make([]byte, buf_len)) //zero-out
  str_hash := base64.StdEncoding.EncodeToString(raw_hash[:])
  return types.PersistableString{str_hash}, nil
}

// Generates a fingerprint for the key that can safely be stored in a non-secure place.
// The key should be impossible to deduce from the fingerprint.
// The fingerprint **must** be issued from a `SecretKey` so that it is not dependent on the method used to encrypt the keys.
func FingerprintKey(key types.SecretKey) types.PersistableString {
  const fp_size = sha512.Size / 4
  if fp_size * 2 > len(key.B) {
    util.Fatalf("Fingerprinting a key that is too small.")
  }
  full_fp := sha512.Sum512(key.B)
  //return fmt.Sprintf("%x", raw_fp)
  raw_fp := base64.StdEncoding.EncodeToString(full_fp[:fp_size])
  return types.PersistableString{raw_fp}
}

func decodeEncryptionKey(
    enc_key types.PersistableKey, xor_key types.SecretKey) types.SecretKey {

  enc_bytes, err := base64.StdEncoding.DecodeString(enc_key.S)
  if err != nil { util.Fatalf("Bad key base64 encoding: %v", err) }
  if len(enc_bytes) != len(xor_key.B) {
    util.Fatalf("Bad key length: %d/%d", len(enc_key.S), len(xor_key.B))
  }
  raw_key := make([]byte, len(enc_bytes))
  for idx,b := range enc_bytes {
    raw_key[idx] = b ^ xor_key.B[idx]
  }
  return types.SecretKey{raw_key}
}
func TestOnlyDecodeEncryptionKey(enc_key types.PersistableKey) types.SecretKey {
  globalState.Mutex.Lock()
  defer globalState.Mutex.Unlock()
  return decodeEncryptionKey(enc_key, globalState.XorKey)
}

func encodeEncryptionKey(
    dec_key types.SecretKey, xor_key types.SecretKey) types.PersistableKey {
  if len(dec_key.B) != len(xor_key.B) {
    util.Fatalf("Bad key length: %d / %d", len(dec_key.B), len(xor_key.B))
  }

  enc_bytes := make([]byte, len(dec_key.B))
  for idx,b := range dec_key.B {
    enc_bytes[idx] = b ^ xor_key.B[idx]
  }
  enc_str := base64.StdEncoding.EncodeToString(enc_bytes)
  return types.PersistableKey{enc_str}
}
func TestOnlyEncodeEncryptionKey(dec_key types.SecretKey) types.PersistableKey {
  globalState.Mutex.Lock()
  defer globalState.Mutex.Unlock()
  return encodeEncryptionKey(dec_key, globalState.XorKey)
}

func (self *AesZlibCodecGlobalState) AddToKeyringThenEncode(
    dec_key types.SecretKey) (types.PersistableKey, types.PersistableString, error) {
  self.Mutex.Lock()
  defer self.Mutex.Unlock()
  fp := FingerprintKey(dec_key)
  for _,pair := range self.Keyring {
    if strings.Compare(fp.S, pair.Fp.S) == 0 {
      null_fp := types.PersistableString{""}
      null_key := types.PersistableKey{""}
      return null_key, null_fp, fmt.Errorf("Fingerprint duplicated: '%s'", fp)
    }
  }
  enc_key := encodeEncryptionKey(dec_key, self.XorKey)
  self.Keyring = append([]FpKeyPair{ FpKeyPair{fp,dec_key} }, self.Keyring...)
  return enc_key, fp, nil
}

func (self *AesZlibCodecGlobalState) Get(fp types.PersistableString) (types.SecretKey, error) {
  self.Mutex.Lock()
  defer self.Mutex.Unlock()
  for _,pair := range self.Keyring {
    if strings.Compare(fp.S, pair.Fp.S) == 0 { return pair.Key, nil }
  }
  null_key := types.SecretKey{[]byte("")}
  return null_key, fmt.Errorf("Fingerprint not found: '%s'", fp)
}

func TestOnlyKeyCount() int {
  globalState.Mutex.Lock()
  defer globalState.Mutex.Unlock()
  return len(globalState.Keyring)
}

func TestOnlyResetGlobalKeyringState() {
  globalState.Mutex.Lock()
  defer globalState.Mutex.Unlock()
  globalState.Keyring = make([]FpKeyPair, 0)
  globalState.XorKey = types.SecretKey{[]byte("")}
}

func (self *aesZlibCodec) EncryptionHeaderLen() int { return self.block_size }

func (self *aesZlibCodec) CreateNewEncryptionKey() (types.PersistableKey, error) {
  null_key := types.PersistableKey{""}

  raw_key := make([]byte, AES_256_KEY_LEN)
  _, err := rand.Read(raw_key)
  if err != nil { util.Fatalf("Could not generate random key: %v", err) }
  dec_key := types.SecretKey{raw_key}

  enc_key, fp, err := globalState.AddToKeyringThenEncode(dec_key)
  if err != nil { return null_key, err }
  self.cur_fp = fp
  self.cur_key = dec_key
  return enc_key, nil
}

func (self *aesZlibCodec) CurrentKeyFingerprint() types.PersistableString {
  return self.cur_fp
}

func (self *aesZlibCodec) OutputEncryptedKeyring(
    pw_prompt types.PwPromptF) ([]types.PersistableKey, types.PersistableString, error) {
  return globalState.OutputEncryptedKeyring(pw_prompt)
}

func (self *aesZlibCodec) getStreamDecrypter(key_fp types.PersistableString) (cipher.Stream, error) {
  if len(self.cur_key.B) == 0 { return nil, ErrNoCurrentKey }
  var stream cipher.Stream
  if len(key_fp.S) == 0 || key_fp.S == self.cur_fp.S {
    stream = AesStreamDecrypter(self.cur_key)
  } else {
    dec_key, err := globalState.Get(key_fp)
    if err != nil { return nil, err }
    stream = AesStreamDecrypter(dec_key)
  }
  return stream, nil
}

func (self *aesZlibCodec) EncryptStream(
    ctx context.Context, input types.ReadEndIf) (types.ReadEndIf, error) {
  if len(self.cur_key.B) == 0 { return nil, ErrNoCurrentKey }
  pipe := util.NewInMemPipe(ctx)
  defer func() { util.OnlyCloseWriteEndWhenError(pipe, input.GetErr()) }()
  stream := AesStreamEncrypter(self.cur_key)
  block_buffer := make([]byte, 128 * self.block_size)

  go func() {
    var err error
    compressed_in := NewCompressingSource(input)
    defer func() { util.CloseWriteEndWithError(pipe, util.Coalesce(input.GetErr(), err)) }()
    defer func() {
      source_err := compressed_in.Close()
      util.CloseWithError(input, util.Coalesce(err, source_err))
    }()
    done := false

    first_block := block_buffer[0:self.block_size]
    // it is valid to reuse slice for output if offsets are the same
    stream.XORKeyStream(first_block, first_block)
    _, err = pipe.WriteEnd().Write(first_block)
    if err != nil { return }

    for !done && err == nil && ctx.Err() == nil {
      var count int
      count, err = compressed_in.Read(block_buffer)
      if err != nil && err != io.EOF { return }
      if count == 0 && err == nil { continue }
      if count == 0 && err == io.EOF { err = nil; return }
      done = (err == io.EOF)

      stream.XORKeyStream(block_buffer[:count], block_buffer[:count])
      _, err = pipe.WriteEnd().Write(block_buffer[:count])
      //util.Debugf("encrypt count=%d done=%v bytes=%x", count, done, block_buffer[:count])
    }
  }()
  return pipe.ReadEnd(), input.GetErr()
}

func (self *aesZlibCodec) decryptBlock_Helper(buffer []byte, stream cipher.Stream, input io.Reader, output io.Writer) (bool, int, error) {
  count, err := input.Read(buffer)
  if err != nil && err != io.EOF {
    return true, count, fmt.Errorf("DecryptStream failed reading: %v", err)
  }
  if count == 0 && err == nil { return false, 0, nil }
  if count == 0 && err == io.EOF { return true, 0, nil }
  // it is valid to reuse slice for output if offsets are the same
  stream.XORKeyStream(buffer[:count], buffer[:count])

  _, err = output.Write(buffer[:count])
  if err != nil { return true, count, err }
  //util.Debugf("decrypt count=%d done=%v bytes=%x", count, done, buffer[:count])
  return (err == io.EOF), count, nil
}

func (self *aesZlibCodec) decryptStream_BlockIterator(
    ctx context.Context, stream cipher.Stream, input io.Reader, output io.Writer) error {
  var err error
  var count int
  var done bool
  block_buffer := make([]byte, 128 * self.block_size)

  first_block := block_buffer[0:self.block_size]
  done, count, err = self.decryptBlock_Helper(first_block, stream, input, io.Discard)
  // The first block should always be there, if we get EOF something went really wrong.
  if err != nil || done || count != len(first_block) {
    return fmt.Errorf("First block not written correctly: %v", err)
  }

  for !done && err == nil && ctx.Err() == nil {
    done, _, err = self.decryptBlock_Helper(block_buffer, stream, input, output)
  }
  return util.Coalesce(err, ctx.Err())
}

func (self *aesZlibCodec) DecryptStream(
    ctx context.Context, key_fp types.PersistableString, input types.ReadEndIf) (types.ReadEndIf, error) {
  stream, err := self.getStreamDecrypter(key_fp)
  if err != nil || input.GetErr() != nil {
    util.CloseWithError(input, err)
    return nil, err
  }

  pipe := util.NewFileBasedPipe(ctx)

  go func() {
    uncompressed_out := NewDecompressingSink(ctx, pipe.WriteEnd())
    err = self.decryptStream_BlockIterator(ctx, stream, input, uncompressed_out)

    sink_err := uncompressed_out.Close()
    all_err := util.Coalesce(input.GetErr(), err, sink_err)
    util.CloseWriteEndWithError(pipe, all_err)
    util.CloseWithError(input, all_err)
  }()
  return pipe.ReadEnd(), nil
}

func (self *aesZlibCodec) DecryptStreamLeaveSinkOpen(
    ctx context.Context, key_fp types.PersistableString, input types.ReadEndIf, output io.WriteCloser) error {
  stream, err := self.getStreamDecrypter(key_fp)
  if err != nil {
    util.CloseWithError(output, err)
    util.CloseWithError(input, err)
    return err
  }

  uncompressed_out := NewDecompressingSink(ctx, output)
  err = self.decryptStream_BlockIterator(ctx, stream, input, uncompressed_out)

  sink_err := uncompressed_out.Close()
  all_err := util.Coalesce(input.GetErr(), err, sink_err)
  // We do not close on purpose, so that `output` can contain the chained streams from multiple calls.
  util.OnlyCloseWhenError(output, all_err)
  util.CloseWithError(input, all_err)
  return all_err
}

