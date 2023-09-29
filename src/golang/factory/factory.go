package factory

import (
  "context"
  "errors"
  "fmt"

  "btrfs_to_glacier/encryption"
  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/shim"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"
  aws_meta "btrfs_to_glacier/volume_store/aws_s3_metadata"
  aws_content "btrfs_to_glacier/volume_store/aws_s3_storage"
  "btrfs_to_glacier/volume_source"
  "btrfs_to_glacier/volume_store/local_fs"
  "btrfs_to_glacier/volume_store/mem_only"
  "btrfs_to_glacier/workflow/backup_manager"
  "btrfs_to_glacier/workflow/restore_manager"
  "btrfs_to_glacier/workflow/backup_restore_canary"
)

var ErrBadConfig = errors.New("bad_config_for_factory")

type Factory struct {
  Conf          *pb.Config
  Lu            types.Linuxutil
  Btrfsutil     types.Btrfsutil
  LazyVolAdmin  types.VolumeAdmin
}

func NewFactory(conf *pb.Config) (*Factory, error) {
  factory := &Factory{ Conf:conf, }
  var err error
  factory.Lu, err = shim.NewLinuxutil(conf)
  if err != nil { return nil, err }
  factory.Btrfsutil, err = shim.NewBtrfsutil(conf, factory.Lu)
  if err != nil { return nil, err }
  return factory, err
}

// Defer creation since BtrfsPathJuggler requires a mounted btrfs filesystem.
func (self Factory) volAdmin() (types.VolumeAdmin, error) {
  if self.LazyVolAdmin != nil { return self.LazyVolAdmin, nil }
  juggler, err := volume_source.NewBtrfsPathJuggler(self.Conf, self.Btrfsutil, self.Lu)
  if err != nil { return nil, err }
  self.LazyVolAdmin, err = volume_source.NewVolumeAdmin(self.Conf, self.Btrfsutil, self.Lu, juggler)
  return self.LazyVolAdmin, err
}

func (self Factory) BuildCodec() (types.Codec, error) {
  if self.Conf.Encryption == nil {
    return nil, fmt.Errorf("%w bad no encryption", ErrBadConfig)
  }
  if self.Conf.Encryption.Type == pb.Encryption_NOOP {
    return encryption.NewNoopCodec(self.Conf)
  }
  if self.Conf.Encryption.Type == pb.Encryption_AES_ZLIB {
    return encryption.NewCodec(self.Conf)
  }
  if self.Conf.Encryption.Type == pb.Encryption_AES_ZLIB_FOR_TEST {
    pw_prompt := func() (types.SecretKey, error) {
      return encryption.BytesToXorKey([]byte("some_pw")), nil
    }
    return encryption.NewCodecHelper(self.Conf, pw_prompt)
  }
  return nil, fmt.Errorf("%w bad encryption type", ErrBadConfig)
}

func (self *Factory) BuildBackupObjects(
    ctx context.Context, backup *pb.Backup) (types.AdminMetadata, types.AdminBackupContent, error) {
  var meta types.AdminMetadata
  var content types.AdminBackupContent

  codec, err := self.BuildCodec()
  if err != nil { return nil, nil, err }

  if backup.Type == pb.Backup_AWS {
    if backup.Aws == nil { return nil, nil, fmt.Errorf("%w missing aws config", ErrBadConfig) }
    // This is the only part of the building process where we need to wait :/
    aws_conf, err := encryption.NewAwsConfigFromTempCreds(ctx, self.Conf, pb.Aws_BACKUP_WRITER)
    if err != nil { return nil, nil, err }
    meta, err = aws_meta.NewMetadataAdmin(self.Conf, aws_conf, backup.Name)
    if err != nil { return nil, nil, err }
    content, err = aws_content.NewBackupContentAdmin(self.Conf, aws_conf, backup.Name, codec)
    if err != nil { return nil, nil, err }
  }
  if backup.Type == pb.Backup_FILESYSTEM {
    var err error
    if backup.Fs == nil { return nil, nil, fmt.Errorf("%w missing fs config", ErrBadConfig) }
    meta, err = local_fs.NewRoundRobinMetadataAdmin(self.Conf, self.Lu, backup.Name)
    if err != nil { return nil, nil, err }
    content, err = local_fs.NewRoundRobinContentAdmin(self.Conf, self.Lu, codec, backup.Name)
    if err != nil { return nil, nil, err }
  }
  if backup.Type == pb.Backup_MEM_EPHEMERAL {
    var err error
    meta, err = mem_only.NewMetadataAdmin(self.Conf)
    if err != nil { return nil, nil, err }
    content, err = mem_only.NewBackupContentAdmin(self.Conf, codec)
    if err != nil { return nil, nil, err }
  } else {
    return nil, nil, fmt.Errorf("%w bad backup type", ErrBadConfig)
  }
  return meta, content, nil
}

func (self *Factory) GetWorkflow(wf_name string) (types.ParsedWorkflow, error) {
  parsed_wf, err := util.WorkflowByName(self.Conf, wf_name)
  if err != nil { return parsed_wf, err }
  if parsed_wf.Backup.Type == pb.Backup_MEM_EPHEMERAL {
    return parsed_wf, nil
  }
  if (parsed_wf.Backup.Aws == nil) == (parsed_wf.Backup.Fs == nil) {
    return parsed_wf, fmt.Errorf("%w only one of aws or fs config needed", ErrBadConfig)
  }
  return parsed_wf, nil
}

func (self *Factory) BuildBackupManagerAdmin(
    ctx context.Context, wf_name string) (types.BackupManagerAdmin, error) {
  wf, err := self.GetWorkflow(wf_name) 
  if err != nil { return nil, err }
  meta, content, err := self.BuildBackupObjects(ctx, wf.Backup)
  if err != nil { return nil, err }
  vol_admin, err := self.volAdmin()
  if err != nil { return nil, err }

  mgr, err := backup_manager.NewBackupManagerAdmin(self.Conf, meta, content, vol_admin)
  return mgr, err
}

func (self *Factory) BuildRestoreManagerAdmin(
    ctx context.Context, wf_name string) (types.RestoreManagerAdmin, error) {
  wf, err := self.GetWorkflow(wf_name) 
  if err != nil { return nil, err }
  meta, content, err := self.BuildBackupObjects(ctx, wf.Backup)
  if err != nil { return nil, err }
  vol_admin, err := self.volAdmin()
  if err != nil { return nil, err }

  mgr, err := restore_manager.NewRestoreManagerAdmin(self.Conf, wf.Restore.Name, meta, content, vol_admin)
  return mgr, err
}

// Implementation detail for canary since both BackupManager and RestoreManager
// need to share the same metadata and backup storage objects.
// Not added to the public interface on purpose.
func (self *Factory) BuildBackupAndRestoreMgr(
    ctx context.Context, wf_name string) (types.BackupManagerAdmin, types.RestoreManagerAdmin, error) {
  wf, err := self.GetWorkflow(wf_name)
  if err != nil { return nil, nil, err }
  meta, content, err := self.BuildBackupObjects(ctx, wf.Backup)
  if err != nil { return nil, nil, err }
  vol_admin, err := self.volAdmin()
  if err != nil { return nil, nil, err }

  bck, err := backup_manager.NewBackupManagerAdmin(self.Conf, meta, content, vol_admin)
  if err != nil { return nil, nil, err }
  rst, err := restore_manager.NewRestoreManagerAdmin(self.Conf, wf.Restore.Name, meta, content, vol_admin)
  if err != nil { return nil, nil, err }
  return bck, rst, err
}

func (self *Factory) BuildBackupRestoreCanary(
    ctx context.Context, wf_name string) (types.BackupRestoreCanary, error) {
  return backup_restore_canary.NewBackupRestoreCanary(
    self.Conf, wf_name, self.Btrfsutil, self.Lu, self)
}

