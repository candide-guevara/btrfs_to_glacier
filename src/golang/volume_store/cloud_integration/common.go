package main

import (
  "context"
  "fmt"
  "time"

  "btrfs_to_glacier/encryption"
  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/util"
  s3_com "btrfs_to_glacier/volume_store/aws_s3_common"
  "btrfs_to_glacier/types"
)

func Backup(conf *pb.Config) *pb.Backup {
  return conf.Backups[0]
}

// Pre-requisites
// * `K_ExperimentalUser` exists in .aws/config as explained in `encryption.TestOnlyAwsConfFromCredsFile`
// * `K_ExperimentalUser` IAM user must have root permissions on the test buckets and dynamo tables.
// * `K_ExperimentalRegion` is a valid aws region were the test infrastructure is locate.
func LoadAwsConfForExperimentalUser(linuxutil types.Linuxutil) (*pb.Config, types.AwsConf) {
  const kMetaDynTab = "dynamodb.integration.test"
  conf := util.LoadTestConf()
  conf.Aws.Region = s3_com.K_ExperimentalRegion
  Backup(conf).Aws.DynamoDb.MetadataTableName = kMetaDynTab
  Backup(conf).Aws.S3.StorageBucketName = s3_com.K_ExperimentalContentBucket
  Backup(conf).Aws.S3.MetadataBucketName = s3_com.K_ExperimentalMetaBucket
  ru, err := linuxutil.GetRealUser()
  if err != nil { util.Fatalf("TestOnlyAwsConfFromCredsFile: %v", err) }
  aws_conf, err := encryption.TestOnlyAwsConfFromCredsFile(
                     context.Background(), conf, ru.HomeDir, s3_com.K_ExperimentalUser)
  if err != nil { util.Fatalf("TestOnlyAwsConfFromCredsFile: %v", err) }
  return conf, aws_conf
}

func DynTableName(conf *pb.Config) string {
  return Backup(conf).Aws.DynamoDb.MetadataTableName
}

func timedUuid(base_uuid string) string {
  return fmt.Sprintf("%s-%d", base_uuid, time.Now().UnixNano())
}

