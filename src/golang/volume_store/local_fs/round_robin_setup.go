package local_fs

import (
  "context"
  "fmt"
  "os"
  "sync"
  "time"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"
)

type RoundRobinSetupState struct {
  Mutex       *sync.Mutex
  FsMounted   map[string]bool
}
var globalState RoundRobinSetupState

func init() {
  globalState = RoundRobinSetupState{
    Mutex: new(sync.Mutex),
    FsMounted: make(map[string]bool),
  }
}

// Thread safe implementation
type RoundRobinSetup struct {
  Sinks       []*pb.Backup_Partition
  Conf        *pb.Config
  Linuxutil   types.Linuxutil
}

// Does not initialize inner SimpleDirMetadata because filesystem may not be mounted yet.
func NewRoundRobinSetup(
    conf *pb.Config, lu types.Linuxutil, backup_name string) (*RoundRobinSetup, error) {
  setup := &RoundRobinSetup{
    Conf:  conf,
    Linuxutil: lu,
  }
  if b,err := util.BackupByName(conf, backup_name); err == nil {
    setup.Sinks = append(setup.Sinks, b.Fs.Sinks...)
    //util.PbInfof("b.Fs.Sinks: %s", b.Fs)
  } else {
    return nil, err
  }
  if len(setup.Sinks) < 1 {
    return nil, fmt.Errorf("Sink '%s' does not contain any partition", backup_name)
  }
  return setup, nil
}

func (self *RoundRobinSetup) MountAllSinkPartitions(ctx context.Context) error {
  globalState.Mutex.Lock()
  defer globalState.Mutex.Unlock()
  for _,part := range self.Sinks {
    if globalState.FsMounted[part.FsUuid] { continue }
    err := os.MkdirAll(part.MountRoot, 0755)
    if err != nil { return err }
    _, err = self.Linuxutil.Mount(ctx, part.FsUuid, part.MountRoot)
    if err != nil { return err }
    err = os.MkdirAll(MetaDir(part), 0755)
    if err != nil { return err }
    err = os.MkdirAll(StoreDir(part), 0755)
    if err != nil { return err }
    globalState.FsMounted[part.FsUuid] = true
  }
  return nil
}

func (self *RoundRobinSetup) UMountAllSinkPartitions(ctx context.Context) error {
  globalState.Mutex.Lock()
  defer globalState.Mutex.Unlock()
  for _,part := range self.Sinks {
    if !globalState.FsMounted[part.FsUuid] { continue }
    err := self.Linuxutil.UMount(ctx, part.FsUuid)
    if err != nil { return err }
    globalState.FsMounted[part.FsUuid] = false
  }
  return nil
}

func modTime(finfo os.FileInfo) time.Time {
  if finfo == nil {
    oldest_ts := time.Time{}
    if !oldest_ts.IsZero() { util.Fatalf("Failed to get zero time") }
    return oldest_ts
  }
  return finfo.ModTime()
}

func (self *RoundRobinSetup) FindOldestPartition() (*pb.Backup_Partition, error) {
  globalState.Mutex.Lock()
  defer globalState.Mutex.Unlock()
  oldest_ts := time.Now()
  var oldest_part *pb.Backup_Partition = nil

  for _,part := range self.Sinks {
    link := SymLink(part)
    finfo, err := os.Stat(link) // does follow symlinks
    if err != nil && !util.IsNotExist(err) { return nil, err }

    part_time := modTime(finfo)
    if part_time.Before(oldest_ts) || part_time.Equal(oldest_ts) {
      oldest_part = part
      oldest_ts = part_time
    }
  }
  if oldest_part == nil { util.Fatalf("Failed to get oldest partition") }
  return oldest_part, nil
}

