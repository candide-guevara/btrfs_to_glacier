package local_fs

import (
  "context"
  "fmt"
  "os"
  "io/fs"
  fpmod "path/filepath"
  "testing"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/util"
  "btrfs_to_glacier/volume_store/mem_only"

  "github.com/google/uuid"
)

type SimpleDirRw struct {
  Part *pb.Backup_Partition
}

func PutStateInAllParts(local_fs *pb.Backup_Fs, state *pb.AllMetadata) {
  if state != nil {
    for _,p := range local_fs.Sinks {
      writer := SimpleDirRw{p}
      if err := writer.PutState(state); err != nil { util.Fatalf("%v", err) }
    }
  }
}

func (self *SimpleDirRw) PutState(state *pb.AllMetadata) error {
  if !fpmod.HasPrefix(self.Part.MountRoot, os.TempDir()) {
    return fmt.Errorf("HasPrefix('%s', '%s')", self.Part.MountRoot, os.TempDir())
  }
  err := os.MkdirAll(MetaDir(self.Part), fs.ModePerm)
  if err != nil { return fmt.Errorf("failed to create meta dir: %v", err) }
  if state == nil { return nil }

  store_path := fpmod.Join(MetaDir(self.Part), "dummystate")
  if err := MarshalCompressedPbFromPath(store_path, state); err != nil { return err }
  return os.Symlink(store_path, SymLink(self.Part))
}

func (self *SimpleDirRw) DeleteState(del_dir bool) {
  if del_dir {
    err := util.RemoveAll(self.Part.MountRoot)
    if err != nil && !util.IsNotExist(err) { util.Fatalf("DeleteState: %v", err) }
    return
  }
  err := os.Remove(SymLink(self.Part))
  if err != nil && !util.IsNotExist(err) { util.Fatalf("DeleteState: %v", err) }
}

func (self *SimpleDirRw) GetState() *pb.AllMetadata {
  state := &pb.AllMetadata{}
  err := UnmarshalCompressedPbFromPath(SymLink(self.Part), state)
  if err != nil && util.IsNotExist(err) { return nil }
  if err != nil { util.Fatalf("SimpleDirRw.GetState: %v", err) }
  return state
}

func buildTestSimpleDirMetadataWithConf(
    t *testing.T, conf *pb.Config) (*SimpleDirMetadata, *SimpleDirRw) {
  part := conf.Backups[0].Fs.Sinks[0]
  client := &SimpleDirRw{part}

  in_mem, err := mem_only.NewInMemMetadata(conf)
  if err != nil { t.Fatalf("NewInMemMetadata: %v", err) }
  meta := &SimpleDirMetadata{
    Metadata: in_mem,
    DirInfo: part,
    SymLink: SymLink(part),
    KeepLast: KeepLast,
  }
  return meta, client
}

func buildTestSimpleDirMetadataWithState(
    t *testing.T, state *pb.AllMetadata) (*SimpleDirMetadata, *SimpleDirRw, func()) {
  var err error
  local_fs, clean_f := util.LoadTestSimpleDirBackupConf()
  conf := util.LoadTestConfWithLocalFs(local_fs)
  meta, client := buildTestSimpleDirMetadataWithConf(t, conf)

  err = client.PutState(state)
  if err != nil { t.Fatalf("failed to set init state: %v", err) }
  meta.SetInMemState(state)
  return meta, client, clean_f
}

func buildTestSimpleDirMetadata_NilState(
    t *testing.T) (*SimpleDirMetadata, *SimpleDirRw, func()) {
  return buildTestSimpleDirMetadataWithState(t, nil)
}

func TestLoadPreviousStateFromDir_NoPartition(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  local_fs, clean_f := util.LoadTestSimpleDirBackupConf()
  defer clean_f()
  conf := util.LoadTestConfWithLocalFs(local_fs)
  _, err := NewSimpleDirMetadata(ctx, conf, uuid.NewString())
  if err == nil { t.Errorf("Expected error got: %v", err) }
}

func TestLoadPreviousStateFromDir_NoIniState(t *testing.T) {
  local_fs,clean_f := util.LoadTestSimpleDirBackupConf()
  defer clean_f()
  conf := util.LoadTestConfWithLocalFs(local_fs)
  meta, client := buildTestSimpleDirMetadataWithConf(t, conf)
  meta.SetInMemState(nil)

  meta.LoadPreviousStateFromDir(context.TODO())
  util.EqualsOrFailTest(t, "Bad object", client.GetState(), nil)
  mem_only.CompareStates(t, "expected empty state", meta.InMemState(), &pb.AllMetadata{})
}

func TestLoadPreviousStateFromDir_PreviousState(t *testing.T) {
  _, expect_state := util.DummyAllMetadata()
  meta,_,clean_f := buildTestSimpleDirMetadataWithState(t, expect_state)
  defer clean_f()
  meta.SetInMemState(nil)

  meta.LoadPreviousStateFromDir(context.TODO())
  mem_only.CompareStates(t, "expected empty state", meta.InMemState(), expect_state)
}

func TestSaveCurrentStateToDir_NoPrevState(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  _, expect_state := util.DummyAllMetadata()
  meta,client,clean_f := buildTestSimpleDirMetadataWithState(t, expect_state)
  defer clean_f()

  version, err := meta.SaveCurrentStateToDir(ctx)
  if err != nil { t.Errorf("Returned error: %v", err) }
  if len(version) < 1 { t.Errorf("empty version") }

  persisted_state := client.GetState()
  util.EqualsOrFailTest(t, "Bad state", persisted_state, expect_state)
}

func TestSaveCurrentStateToDir_WithPrevState(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  vol_uuid, prev_state := util.DummyAllMetadata()
  var expect_state pb.AllMetadata = *prev_state
  meta,client,clean_f := buildTestSimpleDirMetadataWithState(t, prev_state)
  defer clean_f()

  new_seq := util.DummySnapshotSequence(vol_uuid, uuid.NewString())
  head, err := meta.RecordSnapshotSeqHead(ctx, new_seq)
  if err != nil { t.Fatalf("RecordSnapshotSeqHead error: %v", err) }
  expect_state.Heads[0] = head

  version, err := meta.SaveCurrentStateToDir(ctx)
  if err != nil { t.Errorf("Returned error: %v", err) }
  if len(version) < 1 { t.Errorf("empty version") }

  persisted_state := client.GetState()
  util.EqualsOrFailTest(t, "Bad state", persisted_state, expect_state)
}

func TestSaveCurrentStateToDir_Err(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  _, prev_state := util.DummyAllMetadata()
  meta,_,clean_f := buildTestSimpleDirMetadataWithState(t, prev_state)
  defer clean_f()
  meta.DirInfo.MetadataDir = uuid.NewString() // this dir should not exist

  _, err := meta.SaveCurrentStateToDir(ctx)
  if err == nil { t.Errorf("Expected error got: %v", err) }
}

func TestSetupSimpleDirMetadata_Simple(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  meta_admin,_,clean_f := buildTestSimpleDirMetadata_NilState(t)
  defer clean_f()
  if meta_admin.InMemState() != nil { t.Errorf("State already loaded") }
  err := meta_admin.SetupMetadata(ctx)
  if err != nil { t.Errorf("Returned error: %v", err) }
}

func TestSetupSimpleDirMetadata_Fail(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  meta_admin,_,clean_f := buildTestSimpleDirMetadata_NilState(t)
  defer clean_f()
  meta_admin.DirInfo.MetadataDir = uuid.NewString() // this dir should not exist
  err := meta_admin.SetupMetadata(ctx)
  if err == nil { t.Errorf("Expected error in SetupMetadata") }
}

func TestSetupSimpleDirMetadata_Idempotent(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  meta_admin,client,clean_f := buildTestSimpleDirMetadata_NilState(t)
  defer clean_f()
  err := client.PutState(&pb.AllMetadata{})
  if err != nil { t.Fatalf("failed to set init state: %v", err) }

  for i:=0; i<2; i+=1 {
    err := meta_admin.SetupMetadata(ctx)
    if err != nil { t.Errorf("Returned error: %v", err) }
    if meta_admin.InMemState() == nil { t.Errorf("State not loaded") }
  }
}

func TestSetupSimpleDirMetadata_IdempotentNoState(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  meta_admin,_,clean_f := buildTestSimpleDirMetadata_NilState(t)
  defer clean_f()

  for i:=0; i<2; i+=1 {
    err := meta_admin.SetupMetadata(ctx)
    if err != nil { t.Errorf("Returned error: %v", err) }
    util.EqualsOrFailTest(t, "Bad state", meta_admin.InMemState(), &pb.AllMetadata{})
  }
}

