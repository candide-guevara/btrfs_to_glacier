package util

import (
  "fmt"
  "hash/adler32"
  "io/fs"
  "math/rand"
  fpmod "path/filepath"
  "os"
  "time"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"

  "github.com/google/uuid"
  "google.golang.org/protobuf/proto"
)

func DummyBtrfsSrc(sv_list []string, snap_list []string) *pb.Source {
  src := &pb.Source{
    Type: pb.Source_BTRFS,
    Name: uuid.NewString(),
  }
  def_snap_path := snap_list[0]
  for idx,sv := range sv_list {
    pair := &pb.Source_VolSnapPathPair{
      VolPath: sv,
      SnapPath: def_snap_path,
    }
    if len(snap_list) > idx { pair.SnapPath = snap_list[idx] }
    src.Paths = append(src.Paths, pair)
  }
  return src
}

func DummyMountEntryForSv(sv *pb.SubVolume) *types.MountEntry {
  if len(sv.MountedPath) < 1 || len(sv.TreePath) < 1 { Fatalf("bad subvol") }
  return DummyMountEntry(sv.VolId, sv.MountedPath, sv.TreePath)
}

func DummyMountEntry(btrfs_id uint64, mnt_path string, tree_path string) *types.MountEntry {
  id := int(adler32.Checksum([]byte(mnt_path)) + adler32.Checksum([]byte(tree_path)))
  dev := &types.Device{
    Name: uuid.NewString(),
    FsUuid: uuid.NewString(),
    GptUuid: uuid.NewString(),
    Minor: id,
    Major: id,
  }
  mnt := &types.MountEntry{
    Id: id,
    TreePath: tree_path,
    MountedPath: mnt_path,
    Device: dev,
    Options: nil,
    BtrfsVolId: btrfs_id,
  }
  var bind types.MountEntry = *mnt
  bind.Id = rand.Int()
  bind.MountedPath = fmt.Sprintf("/binds%s", mnt.MountedPath)
  mnt.Binds = []*types.MountEntry{ &bind, }
  return mnt
}

func DummyFilesystem(mnts []*types.MountEntry) *types.Filesystem {
  return &types.Filesystem{
    Uuid: uuid.NewString(),
    Label: uuid.NewString(),
    Devices: nil,
    Mounts: mnts,
  }
}

func DummyChunks(chunk_uuids ...string) *pb.SnapshotChunks {
  chunks := []*pb.SnapshotChunks_Chunk{}
  for i,u := range chunk_uuids {
    chunk := &pb.SnapshotChunks_Chunk {
      Uuid: u,
      Start: uint64(i*3),
      Size: uint64((i+1)*3),
    }
    chunks = append(chunks, chunk)
  }
  return &pb.SnapshotChunks{
    KeyFingerprint: "fp",
    Chunks: chunks,
  }
}

func DummySubVolumeFromMount(mnt *types.MountEntry) *pb.SubVolume {
  sv := DummySubVolume(uuid.NewString())
  sv.MountedPath = mnt.MountedPath
  sv.TreePath = mnt.TreePath
  sv.VolId = mnt.BtrfsVolId
  return sv
}

func DummySubVolume(vol_uuid string) *pb.SubVolume {
 return &pb.SubVolume{
    Uuid: vol_uuid,
    VolId: (uint64)(adler32.Checksum([]byte(vol_uuid))),
    TreePath: vol_uuid,
    MountedPath: fmt.Sprintf("/banana_stashes/%s", vol_uuid),
    CreatedTs: 666,
    OriginSys: &pb.SystemInfo{
      KernMajor: 1,
      BtrfsUsrMajor: 1,
      ToolGitCommit: "commit_hash",
    },
  }
}

func DummySnapshot(snap_uuid string, vol_uuid string) *pb.SubVolume {
  vol := DummySubVolume(snap_uuid)
  vol.ParentUuid = vol_uuid
  vol.TreePath = fmt.Sprintf("snaps/%s", snap_uuid)
  vol.MountedPath = ""
  vol.ReadOnly = true
  vol.CreatedTs += 111
  vol.GenAtCreation = 777
  vol.Data = DummyChunks(uuid.NewString())
  vol.Data.Chunks = nil
  return vol
}

func DummySnapshotSequence(vol_uuid string, seq_uuid string) *pb.SnapshotSequence {
  vol := DummySubVolume(vol_uuid)
  snap := fmt.Sprintf("%s_snap", vol_uuid)
  return &pb.SnapshotSequence{
    Uuid: seq_uuid,
    Volume: vol,
    SnapUuids: []string{snap},
  }
}

func DummySnapshotSeqHead(seq *pb.SnapshotSequence, prev ...string) *pb.SnapshotSeqHead {
  return &pb.SnapshotSeqHead{
    Uuid: seq.Volume.Uuid,
    CurSeqUuid: seq.Uuid,
    PrevSeqUuid: prev,
  }
}

func DummyAllMetadata() (string, *pb.AllMetadata) {
  vol_uuid := uuid.NewString()
  seq_uuid := uuid.NewString()
  expect_seq := DummySnapshotSequence(vol_uuid, seq_uuid)
  expect_head := DummySnapshotSeqHead(expect_seq)
  expect_snap := DummySnapshot(expect_seq.SnapUuids[0], vol_uuid)
  return vol_uuid, &pb.AllMetadata{
    CreatedTs: uint64(time.Now().Unix()),
    Heads: []*pb.SnapshotSeqHead{ expect_head, },
    Sequences: []*pb.SnapshotSequence{ expect_seq, },
    Snapshots: []*pb.SubVolume{ expect_snap, },
  }
}

func LoadTestConf() *pb.Config {
  source := &pb.Source{
    Type: pb.Source_BTRFS,
    Name: uuid.NewString(),
    Paths: []*pb.Source_VolSnapPathPair{
      &pb.Source_VolSnapPathPair{
        VolPath: "/tmp/subvol1",
        SnapPath: "/tmp/snaps",
      },
    },
    History: &pb.Source_SnapHistory{
      DaysKeepAll: 30,
      KeepOnePeriodDays: 30,
    },
  }
  backup := &pb.Backup{
    Type: pb.Backup_AWS,
    Name: uuid.NewString(),
    Aws:  &pb.Backup_Aws{
      DynamoDb: &pb.Backup_DynamoDb{ MetadataTableName: "coucou", },
      S3: &pb.Backup_S3{
        StorageBucketName: "coucou_store",
        MetadataBucketName: "coucou_meta",
        ChunkLen: 1024*1024,
      },
    },
  }
  aws_creds := &pb.Aws_Credential{}
  conf := &pb.Config {
    Sources: []*pb.Source{ source, },
    Backups: []*pb.Backup{ backup, },
    Encryption: &pb.Encryption{},
    Aws: &pb.Aws {
      Creds: []*pb.Aws_Credential{ aws_creds, },
      Region: "eu-central-1", // needs to be valid for unittests
    },
  }
  return conf
}

func LoadTestConfWithLocalFs(local_fs *pb.Backup_Fs) *pb.Config {
  conf := LoadTestConf()
  backup := &pb.Backup{
    Type: pb.Backup_FILESYSTEM,
    Name: uuid.NewString(),
    Fs:  proto.Clone(local_fs).(*pb.Backup_Fs),
  }
  conf.Backups = []*pb.Backup{ backup, }
  return conf
}

func LoadTestMultiSinkBackupConf(
    sink_cnt int, create_dirs bool) (*pb.Backup_Fs, func()) {
  local_fs := &pb.Backup_Fs{ Sinks: make([]*pb.Backup_Partition, sink_cnt), }
  for s_idx,_ := range local_fs.Sinks {
    local_fs_dir := fpmod.Join(os.TempDir(), uuid.NewString())
    if create_dirs {
      var err error
      local_fs_dir, err = os.MkdirTemp(os.TempDir(), "localfs_")
      if err != nil { Fatalf("failed to create tmp dir: %v", err) }
      err = os.Mkdir(fpmod.Join(local_fs_dir, "metadata"), fs.ModePerm)
      if err != nil { Fatalf("failed to create dir: %v", err) }
      err = os.Mkdir(fpmod.Join(local_fs_dir, "storage"), fs.ModePerm)
      if err != nil { Fatalf("failed to create dir: %v", err) }
    }

    local_fs.Sinks[s_idx] = &pb.Backup_Partition{
      FsUuid: uuid.NewString(),
      MountRoot: local_fs_dir,
      MetadataDir: "metadata",
      StorageDir: "storage",
    }
  }
  clean_f := func () {
    for _,p := range local_fs.Sinks { RemoveAll(p.MountRoot) }
  }
  return proto.Clone(local_fs).(*pb.Backup_Fs), clean_f
}

func LoadTestSimpleDirBackupConf() (*pb.Backup_Fs, func()) {
  return LoadTestMultiSinkBackupConf(1,true)
}

