package main

import (
  "context"
  "fmt"
  "strconv"
  "time"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/shim"
  "btrfs_to_glacier/util"
  "btrfs_to_glacier/volume_store/aws_s3_common"

  "github.com/aws/aws-sdk-go-v2/aws"

  "google.golang.org/protobuf/proto"
)

func main() {
  util.Infof("cloud_integration run")
  linuxutil, _ := shim.NewLinuxutil(nil)
  linuxutil.DropRootOrDie()

  ctx := context.Background()
  conf, aws_conf := LoadAwsConfForExperimentalUser(linuxutil)
  //conf = useUniqueInfrastructureNames(conf)

  TestCallerIdentity(ctx, conf, aws_conf)
  TestAllS3Storage(ctx, conf, aws_conf)
  TestAllS3Metadata(ctx, conf, aws_conf)
  TestAllDynamoDbMetadata(ctx, conf, aws_conf)
  util.Infof("ALL DONE")
}

func TestCallerIdentity(ctx context.Context, conf *pb.Config, aws_conf *aws.Config) {
  var err error
  var id_int int
  var account_id string
  account_id, err = aws_s3_common.GetAccountId(ctx, aws_conf)
  if err != nil { util.Fatalf("aws_s3_common.GetAccountId: %v", err) }
  id_int, err = strconv.Atoi(account_id)
  if err != nil || id_int < 1 { util.Fatalf("invalid account id") }
}

func useUniqueInfrastructureNames(conf *pb.Config) *pb.Config {
  new_conf := proto.Clone(conf).(*pb.Config)
  backup_conf := Backup(new_conf).Aws
  backup_conf.DynamoDb.MetadataTableName = fmt.Sprintf("%s%d", backup_conf.DynamoDb.MetadataTableName,
                                                       time.Now().Unix())
  backup_conf.S3.StorageBucketName = fmt.Sprintf("%s%d", backup_conf.S3.StorageBucketName,
                                                 time.Now().Unix())
  backup_conf.S3.MetadataBucketName = fmt.Sprintf("%s%d", backup_conf.S3.MetadataBucketName,
                                                  time.Now().Unix())
  return new_conf
}

