package aws_s3_storage
// AFAIK S3, Glacier S3 and Glacier are all different *incompatible* APIs.
// This implementation will use the vanilla S3 API.
// * All objects are written to Standard class and the transitioned to Glacier using lifecycle rules.
//   * S3 has an extra deep Glacier class.
//   * Can use Standard class for testing without waiting for restores.
// * All objects can be listed no matter the storage class.
//   * Convenient but comes at a cost of 40Kb (see S3 docs)
//
// WTF is the deal between Bucket/Object ACLs, Bucket policies, IAM policies ?
// TL;DR only use IAM policies attached to AWS users/groups
// https://aws.amazon.com/blogs/security/iam-policies-and-bucket-policies-and-acls-oh-my-controlling-access-to-s3-resources

import (
  "bufio"
  "context"
  "fmt"
  "io"
  "regexp"
  "strconv"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"
  "btrfs_to_glacier/volume_store/mem_only"
  s3_common "btrfs_to_glacier/volume_store/aws_s3_common"

  "github.com/aws/aws-sdk-go-v2/aws"
  "github.com/aws/aws-sdk-go-v2/service/s3"
  s3mgr "github.com/aws/aws-sdk-go-v2/feature/s3/manager"
  s3_types "github.com/aws/aws-sdk-go-v2/service/s3/types"

  "github.com/google/uuid"
)

const (
  // Somehow the s3 library has not declared this error
  RestoreAlreadyInProgress = "RestoreAlreadyInProgress"
  s3_iter_buf_len = 1000
  restore_lifetime_days = 3
)

// The subset of the s3 client used.
// Convenient for unittesting purposes.
type usedS3If interface {
  s3_common.UsedS3If
  DeleteObjects(context.Context, *s3.DeleteObjectsInput, ...func(*s3.Options)) (*s3.DeleteObjectsOutput, error)
  GetObject    (context.Context, *s3.GetObjectInput,     ...func(*s3.Options)) (*s3.GetObjectOutput, error)
  HeadObject   (context.Context, *s3.HeadObjectInput,    ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
  ListObjectsV2(context.Context, *s3.ListObjectsV2Input, ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
  PutBucketLifecycleConfiguration(context.Context, *s3.PutBucketLifecycleConfigurationInput, ...func(*s3.Options)) (*s3.PutBucketLifecycleConfigurationOutput, error)
  RestoreObject(context.Context, *s3.RestoreObjectInput, ...func(*s3.Options)) (*s3.RestoreObjectOutput, error)
}

// Use to inject a mock for the object uploader.
type uploaderIf interface {
  Upload(context.Context, *s3.PutObjectInput, ...func(*s3mgr.Uploader)) (*s3mgr.UploadOutput, error)
}

type ChunkIoImpl struct {
  Parent     *s3Storage
  IterBufLen int32
  RestoreLifetimeDays int32
  StartStorageClass   s3_types.StorageClass
  ArchiveStorageClass s3_types.StorageClass
}

type s3Storage struct {
  *mem_only.BaseStorage
  Client     usedS3If
  Uploader   uploaderIf
  aws_conf   types.AwsConf
  common     *s3_common.S3Common
}

func NewBackupContent(conf *pb.Config, aws_conf types.AwsConf, backup_name string,
                codec types.Codec) (types.BackupContent, error) {
  client := s3.NewFromConfig(*aws_conf.C)
  // Uploading a non-seekable stream, parallelism is useless
  uploader := s3mgr.NewUploader(client,
                                func(u *s3mgr.Uploader) { u.LeavePartsOnError = false },
                                func(u *s3mgr.Uploader) { u.Concurrency = 1 })
  common, err := s3_common.NewS3Common(conf, aws_conf, backup_name, client)
  if err != nil { return nil, err }

  inner_storage := &mem_only.BaseStorage{
    Conf: conf,
    Codec: codec,
  }
  storage := &s3Storage{
    BaseStorage: inner_storage,
    Client: client,
    Uploader: uploader,
    aws_conf: aws_conf,
    common: common,
  }
  storage.ChunkIo = &ChunkIoImpl{ Parent:storage, }
  storage.injectConstants()
  return storage, nil
}

func (self *s3Storage) injectConstants() {
  self.ChunkIo.(*ChunkIoImpl).IterBufLen = s3_iter_buf_len
  self.ChunkIo.(*ChunkIoImpl).RestoreLifetimeDays = restore_lifetime_days
  self.ChunkIo.(*ChunkIoImpl).StartStorageClass = s3_types.StorageClassStandard
  self.ChunkIo.(*ChunkIoImpl).ArchiveStorageClass = s3_types.StorageClassDeepArchive
}

// We cannot use https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/s3/s3manager#Downloader
// since it uses io.WriterAt (for writing in parallel).
// In our case, the codec uses a stream cypher, parallel (out-of-order) downloads will make things much more complex.
// Not to mention for a home connection bandwidth, this is an overkill...
func (self *ChunkIoImpl) ReadOneChunk(
    ctx context.Context, key_fp types.PersistableString, chunk *pb.SnapshotChunks_Chunk, output io.WriteCloser) error {
  get_in := &s3.GetObjectInput{
    Bucket: &self.Parent.common.BackupConf.StorageBucketName,
    Key: aws.String(chunk.Uuid),
  }
  get_out, err := self.Parent.Client.GetObject(ctx, get_in)
  if s3_common.IsS3Error(new(s3_types.NoSuchKey), err) { return types.ErrChunkFound }
  if err != nil { return err }
  if get_out.ContentLength != int64(chunk.Size) {
    return fmt.Errorf("mismatched length with metadata: %d != %d", get_out.ContentLength, chunk.Size)
  }
  read_wrap := util.WrapPlainReaderCloser(get_out.Body)
  err = self.Parent.Codec.DecryptStreamLeaveSinkOpen(ctx, key_fp, read_wrap, output)
  return err
}

// Each chunk should be encrypted with a different IV,
// `start_offset` is NOT used to advance the stream only to return a correct return value.
func (self *ChunkIoImpl) WriteOneChunk(
    ctx context.Context, start_offset uint64, clear_input types.ReadEndIf) (*pb.SnapshotChunks_Chunk, bool, error) {
  content_type := "application/octet-stream"
  chunk_len := uint64(self.Parent.common.BackupConf.ChunkLen)
  key, err := uuid.NewRandom()
  key_str := key.String()
  if err != nil { return nil, false, err }

  limit_reader := util.NewLimitedReadEnd(clear_input, chunk_len)
  encrypted_reader, err := self.Parent.Codec.EncryptStream(ctx, limit_reader)
  if err != nil { return nil, false, err }
  defer encrypted_reader.Close()
  // The small buffer should be bypassed for bigger reads by the s3 uploader
  chunk_reader := bufio.NewReaderSize(encrypted_reader, 64)

  codec_hdr := self.Parent.Codec.EncryptionHeaderLen()
  _, err = chunk_reader.Peek(codec_hdr + 1)
  if err == io.EOF { return nil, false, nil }

  upload_in := &s3.PutObjectInput{
    Bucket: &self.Parent.common.BackupConf.StorageBucketName,
    Key:    &key_str,
    Body:   chunk_reader,
    ACL:    s3_types.ObjectCannedACLBucketOwnerFullControl,
    ContentType:  &content_type,
    StorageClass: self.StartStorageClass,
  }

  // Maybe we managed to read some data and actually wrote an object to S3.
  // Just forget about it, that object should remain orphan.
  _, err = self.Parent.Uploader.Upload(ctx, upload_in)
  if err != nil { return nil, false, err }

  write_cnt := uint64(codec_hdr) + chunk_len - uint64(limit_reader.N)
  // We leave the empty chunk in the fs as an orphan
  if mem_only.IsChunkEmpty(chunk_len, codec_hdr, write_cnt, limit_reader.N) { return nil, false, nil }
  if write_cnt < 1 { return nil, false, fmt.Errorf("cannot write empty chunk.") }
  if chunk_reader.Buffered() > 0 { return nil, false, fmt.Errorf("some bytes were read but not written.") }

  chunk := &pb.SnapshotChunks_Chunk{
    Uuid: key_str,
    Start: start_offset,
    Size: uint64(write_cnt),
  }
  return chunk, mem_only.HasMoreData(chunk_len, codec_hdr, write_cnt, limit_reader.N), nil
}

func (self *ChunkIoImpl) RestoreSingleObject(ctx context.Context, key string) types.ObjRestoreOrErr {
  restore_in := &s3.RestoreObjectInput{
    Bucket: &self.Parent.common.BackupConf.StorageBucketName,
    Key: aws.String(key),
    RestoreRequest: &s3_types.RestoreRequest{
      Days: self.RestoreLifetimeDays,
      // Be careful it is a trap ! There are 2 ways to specify the Tier, but one is invalid
      // (returns api error MalformedXML)
      //Tier: s3_types.TierStandard,
      GlacierJobParameters: &s3_types.GlacierJobParameters{ Tier: s3_types.TierStandard, },
    },
  }
  _, err := self.Parent.Client.RestoreObject(ctx, restore_in)
  //util.Debugf("restore_in: %+v\nbucket: %v, key: %v", restore_in, *restore_in.Bucket, *restore_in.Key)
  if s3_common.IsS3Error(s3_common.StrToApiErr(RestoreAlreadyInProgress), err) {
    return types.ObjRestoreOrErr{ Stx:types.Pending, }
  }
  // Probably this object is still in the standard storage class.
  if s3_common.IsS3Error(new(s3_types.InvalidObjectState), err) {
    return types.ObjRestoreOrErr{ Stx:types.Unknown, }
  }
  if s3_common.IsS3Error(new(s3_types.NoSuchKey), err) {
    return types.ObjRestoreOrErr{ Err: types.ErrChunkFound, }
  }
  if err != nil {
    return types.ObjRestoreOrErr{ Err:err, }
  }
  return types.ObjRestoreOrErr{ Stx:types.Unknown, }
}

func (self *ChunkIoImpl) ListChunks(
    ctx context.Context, continuation *string) ([]*pb.SnapshotChunks_Chunk, *string, error) {
  list_in := &s3.ListObjectsV2Input{
    Bucket: &self.Parent.common.BackupConf.StorageBucketName,
    ContinuationToken: continuation,
    MaxKeys: self.IterBufLen,
  }
  list_out, err := self.Parent.Client.ListObjectsV2(ctx, list_in)
  if err != nil { return nil, nil, err }
  //util.Debugf("response:\n%v", util.AsJson(list_out))

  codec_hdr := self.Parent.Codec.EncryptionHeaderLen()
  continuation = list_out.NextContinuationToken
  buffer := make([]*pb.SnapshotChunks_Chunk, 0, len(list_out.Contents))
  for _,item := range list_out.Contents {
    chunk := &pb.SnapshotChunks_Chunk{
      Uuid:  *item.Key,
      Start: 0, //unknown
      Size:  uint64(item.Size),
    }
    if chunk.Size <= uint64(codec_hdr) { return nil, nil, fmt.Errorf("chunks should not be empty: %v", chunk) }
    buffer = append(buffer, chunk)
  }

  if len(buffer) != int(list_out.KeyCount) { util.Fatalf("List yielded less than %d", list_out.KeyCount) }
  if list_out.IsTruncated && continuation == nil { util.Fatalf("Items left but no token: %v", list_out) }
  return buffer, continuation, nil
}

var restore_rx *regexp.Regexp
func init() {
  // Restore: 'ongoing-request="false", expiry-date="Thu, 09 Sep 2021 00:00:00 GMT"',
  restore_rx = regexp.MustCompile(`ongoing-request="(\w+)"`)
}

func (self *s3Storage) pollRestoreStatus(ctx context.Context, key string) types.ObjRestoreOrErr {
  chunkio := self.ChunkIo.(*ChunkIoImpl)
  head_in := &s3.HeadObjectInput{
    Bucket: &self.common.BackupConf.StorageBucketName,
    Key: aws.String(key),
  }
  head_out, err := self.Client.HeadObject(ctx, head_in)
  //util.Debugf("head_in: %+v\nhead_out: %+v", head_in, head_out)

  if err != nil { return types.ObjRestoreOrErr{ Err:err, } }
  // quirk see: https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/s3#HeadObjectOutput
  if head_out.StorageClass == chunkio.StartStorageClass || len(head_out.StorageClass) == 0 {
    return types.ObjRestoreOrErr{ Stx:types.Restored, }
  }
  if head_out.StorageClass != chunkio.ArchiveStorageClass {
    return types.ObjRestoreOrErr{ Err:fmt.Errorf("object should not be in storage class: %v", head_out.StorageClass), }
  }
  if head_out.Restore == nil { return types.ObjRestoreOrErr{ Stx:types.Unknown, } }

  match := restore_rx.FindStringSubmatch(*head_out.Restore)
  if match == nil || len(match) != 2 {
    return types.ObjRestoreOrErr{ Err:fmt.Errorf("restore status unknown: %v", *head_out.Restore), }
  }
  var ongoing bool
  ongoing, err = strconv.ParseBool(match[1])
  if err != nil { return types.ObjRestoreOrErr{ Err:err, } }
  if !ongoing { return types.ObjRestoreOrErr{ Stx:types.Restored, } }
  return types.ObjRestoreOrErr{ Stx:types.Pending, }
}

// AFAIK there is no way to ask for several restores at the same time.
// Same thing for getting the restore status (multiple keys in a HEAD request).
func (self *s3Storage) QueueRestoreObjects(
    ctx context.Context, keys []string) types.RestoreResult {
  result := make(types.RestoreResult)
  for _,key := range keys {
    stx := self.ChunkIo.RestoreSingleObject(ctx, key)
    result[key] = stx
    // restore request is successful for pending and completed restores.
    // we need to issue a head request to know which.
    if stx.Err == nil && stx.Stx == types.Unknown {
      head_stx := self.pollRestoreStatus(ctx, key)
      if head_stx.Err == nil && head_stx.Stx == types.Unknown {
        head_stx.Err = fmt.Errorf("head should have determined restore status for '%s'", key)
      }
      result[key] = head_stx
    }
  }
  util.Infof("Queued restore for %d objects.", len(keys))
  return result
}

