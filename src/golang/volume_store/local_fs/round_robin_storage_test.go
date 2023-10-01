package local_fs

import (
  "context"
  "io"
  "testing"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/types/mocks"
  "btrfs_to_glacier/util"
)

func buildTestRoundRobinContentWithState(
    t *testing.T, state *pb.AllMetadata) (*RoundRobinContent, func()) {
  local_fs, clean_f := util.LoadTestMultiSinkBackupConf(3, state != nil)
  conf := util.LoadTestConfWithLocalFs(local_fs)
  codec := new(mocks.Codec)
  codec.Fingerprint = types.PersistableString{"some_fp"}

  content, err := NewRoundRobinContentAdmin(conf, mocks.NewLinuxutil(), codec, conf.Backups[0].Name)
  if err != nil {  t.Fatalf("NewRoundRobinContentAdmin %v", err) }
  return content.(*RoundRobinContent), clean_f
}

func TestBackupContentMultiReadWriteCycles(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  content,clean_f := buildTestRoundRobinContentWithState(t, &pb.AllMetadata{})
  defer clean_f()

  err := content.SetupBackupContent(ctx)
  if err != nil { t.Fatalf("SetupBackupContent err: %v", err) }
  chunkio := GetChunkIoForTest(content)

  for i:=0; i<3; i+=1 {
    expect_data := util.GenerateRandomTextData(32)
    pipe := mocks.NewPreloadedPipe(expect_data)
    val, err := content.WriteStream(ctx, 0, pipe.ReadEnd())
    if err != nil { t.Fatalf("ChunksOrError: %v", err) }
    util.EqualsOrFailTest(t, "Bad len", len(val.Chunks), 1)

    reader, err := content.ReadChunksIntoStream(ctx, val)
    if err != nil { t.Fatalf("storage.ReadChunksIntoStream: %v", err) }
    var got_data []byte
    done_r := make(chan error)
    go func() {
      defer close(done_r)
      defer reader.Close()
      got_data, err = io.ReadAll(reader)
      if err != nil { t.Fatalf("io.ReadAll: %v", err) }
    }()
    util.WaitForClosure(t, ctx, done_r)

    util.EqualsOrFailTest(t, "Bad chunk", got_data, expect_data)
    persisted_data, _ := chunkio.Get(val.Chunks[0].Uuid)
    util.EqualsOrFailTest(t, "Bad persisted chunk", persisted_data, expect_data)
  }
}

