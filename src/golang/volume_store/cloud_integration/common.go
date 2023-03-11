package main

import (
  "bytes"
  "context"
  "flag"
  "fmt"
  "io"
  "time"

  "btrfs_to_glacier/encryption"
  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/util"

  "github.com/aws/aws-sdk-go-v2/aws"
  "github.com/aws/aws-sdk-go-v2/service/s3"
  s3_types "github.com/aws/aws-sdk-go-v2/service/s3/types"

  "google.golang.org/protobuf/proto"
)

var access_flag string
var secret_flag string
var session_flag string
var region_flag string
var table_flag string
var store_bucket_flag string
var meta_bucket_flag string

func init() {
  flag.StringVar(&access_flag,       "access",       "", "Access Key ID")
  flag.StringVar(&secret_flag,       "secret",       "", "Secret access key")
  flag.StringVar(&session_flag,      "session",      "", "Session token for temporal credentials")
  flag.StringVar(&region_flag,       "region",       "", "Default AWS region")
  flag.StringVar(&table_flag,        "table",        "", "Dynamodb table name")
  flag.StringVar(&store_bucket_flag, "store_bucket", "", "S3 storage bucket name")
  flag.StringVar(&meta_bucket_flag,  "meta_bucket",  "", "S3 metadata bucket name")
}

func overwriteWithFlags(conf *pb.Config, backup *pb.Backup_Aws) {
  flag.Parse()
  if region_flag       != "" { conf.Aws.Region = region_flag }
  if table_flag        != "" { backup.DynamoDb.MetadataTableName = table_flag }
  if store_bucket_flag != "" { backup.S3.StorageBucketName = store_bucket_flag }
  if meta_bucket_flag  != "" { backup.S3.MetadataBucketName = meta_bucket_flag }
}

func Backup(conf *pb.Config) *pb.Backup {
  return conf.Backups[0]
}

func LoadAwsTestConfWithFlagOverwrites() (*pb.Config, *aws.Config) {
  conf := util.LoadTestConf()
  overwriteWithFlags(conf, Backup(conf).Aws)
  aws_conf, err := encryption.TestOnlyAwsConfFromPlainKey(conf, access_flag, secret_flag, session_flag)
  if err != nil { util.Fatalf("TestOnlyAwsConfFromPlainKey: %v", err) }
  return conf, aws_conf
}

func DynTableName(conf *pb.Config) string {
  return Backup(conf).Aws.DynamoDb.MetadataTableName
}

func timedUuid(base_uuid string) string {
  return fmt.Sprintf("%s-%d", base_uuid, time.Now().UnixNano())
}

func GetObject(
    ctx context.Context, client *s3.Client, bucket string, key string) ([]byte, error) {
  in := &s3.GetObjectInput{
    Bucket: &bucket,
    Key: &key,
  }
  out, err := client.GetObject(ctx, in)
  if err != nil { return nil, err }

  defer out.Body.Close()
  var data []byte
  data, err = io.ReadAll(out.Body)
  if err == nil { util.Infof("Got object '%s' size=%d", key, len(data)) }
  return data, err
}

func GetProto(
    ctx context.Context, client *s3.Client, bucket string, key string, msg proto.Message) error {
  data, err := GetObject(ctx, client, bucket, key)
  if err != nil { return err }
  err = proto.Unmarshal(data, msg)
  return err
}

func PutObject(
    ctx context.Context, client *s3.Client, bucket string, key string, data []byte) error {
  reader := bytes.NewReader(data)
  in := &s3.PutObjectInput{
    Bucket: &bucket,
    Key: &key,
    Body: reader,
  }
  _, err := client.PutObject(ctx, in)
  return err
}

func PutProto(
    ctx context.Context, client *s3.Client, bucket string, key string, msg proto.Message) error {
  data, err := proto.Marshal(msg)
  if err != nil { return nil }
  return PutObject(ctx, client, bucket, key, data)
}

func GetObjectOrDie(
    ctx context.Context, client *s3.Client, bucket string, key string) []byte {
  data, err := GetObject(ctx, client, bucket, key)
  if err != nil { util.Fatalf("Failed to get object '%s': %v", key, err) }
  return data
}

func GetProtoOrDie(
    ctx context.Context, client *s3.Client, bucket string, key string, msg proto.Message) {
  err := GetProto(ctx, client, bucket, key, msg)
  if err != nil { util.Fatalf("Failed to get object '%s': %v", key, err) }
}

func PutObjectOrDie(
    ctx context.Context, client *s3.Client, bucket string, key string, data []byte) {
  err := PutObject(ctx, client, bucket, key, data)
  if err != nil { util.Fatalf("Failed to put object '%s': %v", key, err) }
}

func PutProtoOrDie(
    ctx context.Context, client *s3.Client, bucket string, key string, msg proto.Message) {
  err := PutProto(ctx, client, bucket, key, msg)
  if err != nil { util.Fatalf("Failed to put proto '%s': %v", key, err) }
}

func ListObjectVersions(
    ctx context.Context, client *s3.Client, bucket string, key string) ([]string, error) {
  var objectVersions []string
  list_in := &s3.ListObjectVersionsInput{
    Bucket: aws.String(bucket),
    Prefix: &key,
  }
  list_out, err := client.ListObjectVersions(ctx, list_in)
  if err != nil { return nil, err }
  if list_out.IsTruncated { return nil, fmt.Errorf("Too many versions") }

  //util.Debugf("list_in:%s\nlist_out:%s", util.AsJson(list_in), util.AsJson(list_out))
  for _, object := range list_out.Versions {
    if *object.Key != key { break }
    objectVersions = append(objectVersions, *object.VersionId)
  }
  return objectVersions, err
}

func ListObjectVersionsOrDie(
    ctx context.Context, client *s3.Client, bucket string, key string) []string {
  versions, err := ListObjectVersions(ctx, client, bucket, key)
  if err != nil { util.Fatalf("Failed to list object '%s': %v", key, err) }
  return versions
}

func DeleteBucket(ctx context.Context, client *s3.Client, bucket string) error {
  err := EmptyBucket(ctx, client, bucket)
  if err != nil { return err }
  _, err = client.DeleteBucket(ctx, &s3.DeleteBucketInput{ Bucket: &bucket, })
  return err
}

func EmptyBucketOrDie(ctx context.Context, client *s3.Client, bucket string) {
  err := EmptyBucket(ctx, client, bucket)
  if err != nil { util.Fatalf("Failed empty object: %v", err) }
}

func EmptyBucket(ctx context.Context, client *s3.Client, bucket string) error {
  //list_in := &s3.ListObjectsV2Input{
  //  Bucket: &bucket,
  //  MaxKeys: 1000,
  //}
  //out, err := client.ListObjectsV2(ctx, list_in)
  //if err != nil { return err }
  //if out.IsTruncated { return fmt.Errorf("needs more iterations to delete all") }
  //
  //to_del := &s3_types.Delete{ Quiet: true, }
  //for _,obj := range out.Contents {
  out, err := client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
    Bucket: aws.String(bucket),
    MaxKeys: 1000,
  })
  if err != nil { return err }
  if out.IsTruncated { return fmt.Errorf("needs more iterations to delete all") }

  to_del := &s3_types.Delete{ Quiet: true }
  for _, obj := range out.Versions {
    kv := s3_types.ObjectIdentifier{
      Key: obj.Key,
      VersionId: obj.VersionId,
    }
    to_del.Objects = append(to_del.Objects, kv)
  }
  util.Infof("In %v there are %d keys to delete", bucket, len(to_del.Objects))
  //util.Debugf("list_out: %s", util.AsJson(out))
  if len(to_del.Objects) < 1 { return nil }

  del_in := &s3.DeleteObjectsInput{
    Bucket: &bucket,
    Delete: to_del,
  }
  //util.Debugf("del_in: %s", util.AsJson(del_in))
  _, err = client.DeleteObjects(ctx, del_in)
  if err != nil { return err }
  return nil
}

func DeleteBucketOrDie(ctx context.Context, client *s3.Client, bucket string) {
  err := DeleteBucket(ctx, client, bucket)
  if err != nil { util.Fatalf("Failed bucket delete: %v", err) }
}

