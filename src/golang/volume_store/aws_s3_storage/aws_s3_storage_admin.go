package aws_s3_storage

import (
  "context"
  "fmt"
  "time"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"
  s3_common "btrfs_to_glacier/volume_store/aws_s3_common"

  "github.com/aws/aws-sdk-go-v2/service/s3"
  s3_types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
  // see https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/s3#Client.DeleteObjects
  delete_objects_max = 1000
  deep_glacier_trans_days = 30
  rule_name_suffix = "chunk.lifecycle"
)

type s3StorageAdmin struct {
  *s3Storage
  deep_glacier_trans_days int32
  remove_multipart_days   int32
  rule_name_suffix        string
}

func NewBackupContentAdmin(conf *pb.Config, aws_conf types.AwsConf, backup_name string,
    codec types.Codec) (types.AdminBackupContent, error) {
  storage, err := NewBackupContent(conf, aws_conf, backup_name, codec)
  if err != nil { return nil, err }

  del_storage := &s3StorageAdmin{ s3Storage: storage.(*s3Storage), }
  del_storage.injectConstants()
  return del_storage, nil
}

func (self *s3StorageAdmin) injectConstants() {
  self.s3Storage.injectConstants()
  self.deep_glacier_trans_days = deep_glacier_trans_days
  self.remove_multipart_days = s3_common.RemoveMultipartDays
  self.rule_name_suffix = rule_name_suffix
}

func (self *s3StorageAdmin) getTransitionType() s3_types.TransitionStorageClass {
  archive_storage_class := self.ChunkIo.(*ChunkIoImpl).ArchiveStorageClass
  for _,t := range s3_types.TransitionStorageClassDeepArchive.Values() {
    if string(archive_storage_class) == string(t) { return t }
  }
  util.Fatalf("No transition types corresponding to %v", archive_storage_class)
  return s3_types.TransitionStorageClassDeepArchive
}

// Bucket lifecycle configuration
// * Storage class applies to all objects in bucket (no prefix)
// * Transition for current objects Standard -> Deep Glacier after X days
// * Multipart uploads are removed after Y days
func (self *s3StorageAdmin) createLifecycleRule(
    ctx context.Context, bucket_name string) error {
  name := fmt.Sprintf("%s.%s.%d",
                      bucket_name, self.rule_name_suffix,
                      time.Now().Unix())
  transition := s3_types.Transition{
    Days: self.deep_glacier_trans_days,
    StorageClass: self.getTransitionType(),
  }
  global_filter := &s3_types.LifecycleRuleFilterMemberPrefix{ Value: "", }
  rule := s3_types.LifecycleRule{
    ID: &name,
    Status: s3_types.ExpirationStatusEnabled,
    Filter: global_filter,
    AbortIncompleteMultipartUpload: &s3_types.AbortIncompleteMultipartUpload{
      DaysAfterInitiation: self.remove_multipart_days,
    },
    Expiration: nil,
    NoncurrentVersionExpiration: nil,
    NoncurrentVersionTransitions: nil,
    Transitions: []s3_types.Transition{ transition },
  }
  lifecycle_in := &s3.PutBucketLifecycleConfigurationInput{
    Bucket: &bucket_name,
    LifecycleConfiguration: &s3_types.BucketLifecycleConfiguration{
      Rules: []s3_types.LifecycleRule{ rule },
    },
  }
  _, err := self.Client.PutBucketLifecycleConfiguration(ctx, lifecycle_in)
  if err != nil { return err }
  return nil
}

// object standard tier
// object no tags no metadata (that way we only need a simple kv store)
func (self *s3StorageAdmin) SetupBackupContent(ctx context.Context) error {
  bucket_name := self.common.BackupConf.StorageBucketName
  exists, err := self.common.CheckBucketExistsAndIsOwnedByMyAccount(ctx, bucket_name)
  if err != nil { return err }
  if exists { return nil }

  err = self.common.CreateBucket(ctx, bucket_name)
  if err != nil { return err }
  err = self.createLifecycleRule(ctx, bucket_name)
  return err
}

func (self *s3StorageAdmin) TearDownBackupContent(ctx context.Context) error {
  return nil //noop
}

func TestOnlySwapConf(storage types.BackupContent, conf *pb.Config) func() {
  s3_impl,ok := storage.(*s3StorageAdmin)
  if !ok { util.Fatalf("called with the wrong impl: %v", storage) }
  old_conf := s3_impl.Conf
  s3_impl.Conf = conf
  common_restore := s3_impl.common.TestOnlySwapConf(conf) // lint:OK
  return func() { common_restore(); s3_impl.Conf = old_conf }
}

func TestOnlyChangeIterationSize(storage types.BackupContent, size int32) func() {
  s3_impl,ok := storage.(*s3StorageAdmin)
  if !ok { util.Fatalf("called with the wrong impl: %v", storage) }
  chunkio := s3_impl.ChunkIo.(*ChunkIoImpl)
  old_size := chunkio.IterBufLen
  chunkio.IterBufLen = size
  return func() { chunkio.IterBufLen = old_size }
}

func (self *s3StorageAdmin) deleteBatch(
    ctx context.Context, chunks []*pb.SnapshotChunks_Chunk) error {
  del_in := &s3.DeleteObjectsInput{
    Bucket: &self.common.BackupConf.StorageBucketName,
    Delete: &s3_types.Delete{
      Objects: make([]s3_types.ObjectIdentifier, len(chunks)),
      Quiet: true,
    },
  }
  for i,c := range chunks {
    del_in.Delete.Objects[i].Key = &c.Uuid
  }
  del_out,err := self.Client.DeleteObjects(ctx, del_in)
  if err != nil { return err }
  if len(del_out.Errors) > 0 { return fmt.Errorf("failed to delete %d keys", len(del_out.Errors)) }
  return nil
}

func (self *s3StorageAdmin) DeleteChunks(
    ctx context.Context, chunks []*pb.SnapshotChunks_Chunk) error {
  if len(chunks) < 1 { return fmt.Errorf("cannot delete 0 keys") }

  for low_bound:=0; low_bound<len(chunks); low_bound+=delete_objects_max {
    up_bound := low_bound + delete_objects_max
    if up_bound > len(chunks) { up_bound = len(chunks) }
    err := self.deleteBatch(ctx, chunks[low_bound:up_bound])
    if err != nil { return err }
  }
  util.Infof("Deleted %d keys: '%s'...'%s'",
             len(chunks), chunks[0].Uuid, chunks[len(chunks)-1].Uuid)
  return nil
}

