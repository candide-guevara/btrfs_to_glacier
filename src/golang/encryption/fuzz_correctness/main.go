package main

import (
  "bytes"
  "context"
  "io"
  "math/rand"
  "time"
  "btrfs_to_glacier/encryption"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/types/mocks"
  "btrfs_to_glacier/util"
)

var gSeed int64
var gFuzzDuration time.Duration

func BuildTestCodec() types.Codec {
  conf := util.LoadTestConf()
  // dd if=/dev/urandom count=1 bs=32 | base64
  conf.Encryption.Keys = []string { "CWTTYSrZrXkW1K/mrsOZNQWMvg4ZcSZFuskaWM+sjLM=", }
  codec, err := encryption.NewCodecHelper(conf, encryption.TestOnlyFixedPw)
  if err != nil { util.Fatalf("Could not create codec: %v", err) }
  return codec
}

func FuzzCodec_CompressibleData_Once(
    ctx context.Context, codec types.Codec, gen *rand.Rand) {
  var err error
  var encoded_pipe, decoded_pipe types.ReadEndIf

  expect_msg := CompressibleInput(gen)
  read_pipe := mocks.NewBigPreloadedPipe(ctx, expect_msg).ReadEnd()
  encoded_pipe, err = codec.EncryptStream(ctx, read_pipe)
  if err != nil { util.Fatalf("Could not encrypt: %v", err) }
  decoded_pipe, err = codec.DecryptStream(ctx, types.CurKeyFp, encoded_pipe)
  if err != nil { util.Fatalf("Could not decrypt: %v", err) }

  done := make(chan []byte)
  go func() {
    defer close(done)
    defer decoded_pipe.Close()
    data, err := io.ReadAll(decoded_pipe)
    if err != nil { util.Fatalf("ReadAll: %v", err) }
    done <- data
  }()

  var data []byte
  select {
    case data = <-done:
    case <-ctx.Done(): util.Fatalf("testEncryptDecryptStream_Helper timeout")
  }
  if bytes.Compare(data, expect_msg) != 0 {
    util.Fatalf("Bad encryption: %d / %d", len(expect_msg), len(data))
  }
}

func CompressibleInput(gen *rand.Rand) []byte {
  alen := (gen.Int() % 128) + 16
  mlen := (gen.Int() % (1024*1024)) + 1024
  alphabet := util.GenerateRandomTextDataFrom(gen, alen)
  //util.Debugf("alphabet = %s", alphabet)
  return bytes.Repeat(alphabet, mlen/alen)
}

func FuzzCodec_CompressibleData(ctx context.Context) {
  gen := rand.New(rand.NewSource(gSeed))
  codec := BuildTestCodec()

  for until := time.Now().Add(gFuzzDuration); time.Now().Before(until); {
    FuzzCodec_CompressibleData_Once(ctx, codec, gen)
  }
}

// Not using testing.F because I do not see the interest.
func main() {
  gFuzzDuration = 30 * time.Second
  ctx, cancel := context.WithTimeout(context.Background(), 2*gFuzzDuration)
  defer cancel()
  gSeed = time.Now().UnixNano()
  FuzzCodec_CompressibleData(ctx)
  util.Infof("ALL DONE")
}

