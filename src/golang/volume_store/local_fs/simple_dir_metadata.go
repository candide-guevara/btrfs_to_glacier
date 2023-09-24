package local_fs

import (
  "context"
  "errors"
  "fmt"
  "io/fs"
  fpmod "path/filepath"
  "os"
  "sort"
  "time"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"
  "btrfs_to_glacier/volume_store/mem_only"

  "github.com/google/uuid"
  "google.golang.org/protobuf/proto"
)

const (
  KeepLast = 3
)

type SimpleDirMetadata struct {
  *mem_only.Metadata
  DirInfo    *pb.Backup_Partition
  SymLink    string
  KeepLast   int
}

func MetaDir(dir_info *pb.Backup_Partition) string {
  return fpmod.Join(dir_info.MountRoot, dir_info.MetadataDir)
}
func SymLink(dir_info *pb.Backup_Partition) string {
  return fpmod.Join(dir_info.MountRoot, dir_info.MetadataDir, "metadata.pb.gz")
}

func NewSimpleDirMetadataAdmin(ctx context.Context, conf *pb.Config, fs_uuid string) (types.AdminMetadata, error) {
  var part *pb.Backup_Partition
  if p,err := util.BackupPartitionByUuid(conf, fs_uuid); err == nil {
    part = p
  } else {
    return nil, err
  }

  metadata := &SimpleDirMetadata{
    Metadata: &mem_only.Metadata{ Conf: conf, },
    DirInfo: part,
    SymLink: SymLink(part),
    KeepLast: KeepLast,
  }
  return metadata, nil
}

func NewSimpleDirMetadata(ctx context.Context, conf *pb.Config, part_uuid string) (types.Metadata, error) {
  return NewSimpleDirMetadataAdmin(ctx, conf, part_uuid)
}

func UnmarshalCompressedPbFromPath(path string, msg proto.Message) error {
  f, err := os.Open(path)
  if err != nil { return err }
  unm_err := util.UnmarshalCompressedPb(f, msg)
  cls_err := f.Close()
  return util.Coalesce(unm_err, cls_err)
}

func MarshalCompressedPbFromPath(path string, msg proto.Message) error {
  f, err := os.Create(path)
  if err != nil { return err }
  mrs_err := util.MarshalCompressedPb(f, msg)
  cls_err := f.Close()
  return util.Coalesce(mrs_err, cls_err)
}

func (self *SimpleDirMetadata) LoadPreviousStateFromDir(ctx context.Context) error {
  if self.InMemState() != nil { util.Fatalf("Cannot load state twice") }
  self.SetInMemState(&pb.AllMetadata{
    CreatedTs: uint64(time.Now().Unix()),
  })
  err := UnmarshalCompressedPbFromPath(self.SymLink, self.InMemState())
  if err != nil && !errors.Is(err, os.ErrNotExist) { return err }
  return nil
}

func (self *SimpleDirMetadata) MetaVer(ts uint64) string {
  name := fmt.Sprintf("metadata_%d.pb.gz", ts)
  return fpmod.Join(self.DirInfo.MountRoot, self.DirInfo.MetadataDir, name)
}

func (self *SimpleDirMetadata) CleanOldVersions(ctx context.Context) ([]string, error) {
  var cleaned_files []string
  var filter_entries []fs.DirEntry

  meta_dir := MetaDir(self.DirInfo)
  fs_dir := os.DirFS(meta_dir)
  entries, err := fs.ReadDir(fs_dir, ".")
  if err != nil { return cleaned_files, err }

  for _,e := range entries {
    info, err := e.Info()
    if err != nil { return cleaned_files, err }
    if e.IsDir() || info.Mode() & fs.ModeSymlink != 0 { continue }
    filter_entries = append(filter_entries, e)
  }
  sort.Slice(filter_entries, func(i,j int) bool {
    info_i, err := filter_entries[i].Info()
    if err != nil { util.Fatalf("failed to sort entries: %v", err) }
    info_j, err := filter_entries[j].Info()
    if err != nil { util.Fatalf("failed to sort entries: %v", err) }
    return info_j.ModTime().Before(info_i.ModTime())
  })

  if len(filter_entries) <= self.KeepLast { return cleaned_files, nil }
  for _,e := range filter_entries[self.KeepLast:] {
    path := fpmod.Join(meta_dir, e.Name())
    err := os.Remove(path)
    if err != nil { return cleaned_files, err }
    cleaned_files = append(cleaned_files, path)
  }
  return cleaned_files, nil
}

func (self *SimpleDirMetadata) SaveCurrentStateToDir(ctx context.Context) (string, error) {
  if self.InMemState() == nil { util.Fatalf("Cannot store nil state") }
  self.InMemState().CreatedTs = uint64(time.Now().Unix())
  version_id := fmt.Sprintf("%d_%s", self.InMemState().CreatedTs, uuid.NewString())
  prev_path,_ := fpmod.EvalSymlinks(self.SymLink)
  store_path := self.MetaVer(self.InMemState().CreatedTs)

  err := MarshalCompressedPbFromPath(store_path, self.InMemState())
  if err != nil { return "", err }

  if util.Exists(self.SymLink) {
    if err := os.Remove(self.SymLink); err != nil { return "", err }
  }
  err = os.Symlink(store_path, self.SymLink)
  if err != nil {
    // Attempt to add back the old path
    if len(prev_path) > 0 { os.Symlink(prev_path, self.SymLink) }
    return "", err
  }

  util.Infof("Saved metadata version: '%s'", version_id)
  _, err = self.CleanOldVersions(ctx)
  return version_id, err
}

func (self *SimpleDirMetadata) PersistCurrentMetadataState(ctx context.Context) (string, error) {
  return self.SaveCurrentStateToDir(ctx)
}

// Do not create anything, just check
func (self *SimpleDirMetadata) SetupMetadata(ctx context.Context) error {
  p := self.DirInfo
  if !util.IsDir(MetaDir(p)) {
    return fmt.Errorf("'%s' is not a directory", MetaDir(p))
  }
  if !util.Exists(SymLink(p)) {
    if self.InMemState() == nil { self.SetInMemState(&pb.AllMetadata{}) }
    return nil
  }
  if !util.IsSymLink(SymLink(p)) {
    return fmt.Errorf("'%s' is not a symlink", SymLink(p))
  }
  target,err := fpmod.EvalSymlinks(SymLink(p))
  if err != nil { return err }
  if !fpmod.HasPrefix(target, MetaDir(p)) {
    return fmt.Errorf("'%s' points outside of '%s'", SymLink(p), MetaDir(p))
  }
  if self.InMemState() == nil {
    return self.LoadPreviousStateFromDir(ctx)
  }
  return nil
}

func TestOnlySetInnerState(metadata types.Metadata, state *pb.AllMetadata) {
  if metadata == nil { util.Fatalf("metadata == nil") }
  impl,ok := metadata.(*SimpleDirMetadata)
  if !ok { util.Fatalf("called with the wrong impl") }
  impl.SetInMemState(proto.Clone(state).(*pb.AllMetadata))
}

