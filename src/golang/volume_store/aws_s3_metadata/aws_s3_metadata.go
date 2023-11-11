package aws_s3_metadata

import (
  "bytes"
  "context"
  "fmt"
  "io"
  "time"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"
  s3_common "btrfs_to_glacier/volume_store/aws_s3_common"
  "btrfs_to_glacier/volume_store/mem_only"

  "github.com/aws/aws-sdk-go-v2/service/s3"
  s3_types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
  MetadataKey = "subvolume_metadata"
)

// The subset of the s3 client used.
// Convenient for unittesting purposes.
type usedS3If interface {
  GetObject          (
    context.Context, *s3.GetObjectInput,     ...func(*s3.Options)) (*s3.GetObjectOutput, error)
  PutBucketVersioning(
    context.Context, *s3.PutBucketVersioningInput, ...func(*s3.Options)) (*s3.PutBucketVersioningOutput, error)
  PutBucketLifecycleConfiguration(
    context.Context, *s3.PutBucketLifecycleConfigurationInput, ...func(*s3.Options)) (*s3.PutBucketLifecycleConfigurationOutput, error)
  PutObject          (
    context.Context, *s3.PutObjectInput,     ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

type S3Metadata struct {
  *mem_only.Metadata
  AwsConf    types.AwsConf
  Common     *s3_common.S3Common
  Client     usedS3If
  Key        string
}

func NewMetadata(
    conf *pb.Config, aws_conf types.AwsConf, backup_name string) (types.Metadata, error) {
  client := s3.NewFromConfig(*aws_conf.C)
  common, err := s3_common.NewS3Common(conf, aws_conf, backup_name, client)
  if err != nil { return nil, err }

  metadata := &S3Metadata{
    Metadata: &mem_only.Metadata{ Conf: conf, },
    AwsConf: aws_conf,
    Client: client,
    Common: common,
  }
  metadata.injectConstants()
  return metadata, nil
}

func (self *S3Metadata) injectConstants() {
  self.Key = MetadataKey
}

func (self *S3Metadata) LoadPreviousStateFromS3(ctx context.Context) error {
  if self.InMemState() != nil { util.Fatalf("Cannot load state twice") }
  self.SetInMemState(&pb.AllMetadata{
    CreatedTs: uint64(time.Now().Unix()),
  })

  get_in := &s3.GetObjectInput{
    Bucket: &self.Common.BackupConf.MetadataBucketName,
    Key: &self.Key,
  }
  get_out, err := self.Client.GetObject(ctx, get_in)
  if s3_common.IsS3Error(new(s3_types.NoSuchKey), err) { return nil }
  // If this is the first time we use the metadata bucket.
  if s3_common.IsS3Error(new(s3_types.NoSuchBucket), err) { return nil }
  if err != nil { return err }

  defer get_out.Body.Close()
  data, err := io.ReadAll(get_out.Body)
  if err != nil { return err }
  err = util.UnmarshalCompressedPb(bytes.NewReader(data), self.InMemState())
  return err
}

func (self *S3Metadata) SaveCurrentStateToS3(ctx context.Context) (string, error) {
  if self.InMemState() == nil { util.Fatalf("Cannot store nil state") }
  self.InMemState().CreatedTs = uint64(time.Now().Unix())

  content_type := "application/octet-stream"
  blob := new(bytes.Buffer)
  err := util.MarshalCompressedPb(blob, self.InMemState())
  if err != nil { return "", err }

  put_in := &s3.PutObjectInput{
    Bucket: &self.Common.BackupConf.MetadataBucketName,
    Key:    &self.Key,
    Body:   blob,
    ACL:    s3_types.ObjectCannedACLBucketOwnerFullControl,
    ContentType:  &content_type,
    StorageClass: s3_types.StorageClassStandard,
  }

  put_out, err := self.Client.PutObject(ctx, put_in)
  if err != nil { return "", err }
  if put_out.VersionId == nil {
    return "", fmt.Errorf("Got bad PutObjectOutput: %s", util.AsJson(put_out))
  }

  util.Infof("Saved metadata version: '%v'", *put_out.VersionId)
  return *put_out.VersionId, nil
}

func (self *S3Metadata) PersistCurrentMetadataState(ctx context.Context) (string, error) {
  return self.SaveCurrentStateToS3(ctx)
}

