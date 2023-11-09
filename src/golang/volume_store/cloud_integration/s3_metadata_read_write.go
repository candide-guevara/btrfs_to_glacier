package main

import (
  "context"

  meta "btrfs_to_glacier/volume_store/aws_s3_metadata"
  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"
  s3_common "btrfs_to_glacier/volume_store/aws_s3_common"

  "github.com/aws/aws-sdk-go-v2/aws"
  "github.com/aws/aws-sdk-go-v2/service/s3"

  "github.com/google/uuid"
  "google.golang.org/protobuf/proto"
)

type s3MetaReadWriteTester struct {
  Conf *pb.Config
  Client *s3.Client
  Metadata types.AdminMetadata
}

func (self *s3MetaReadWriteTester) PutPersistedStateGetVersions(
    ctx context.Context, state *pb.AllMetadata, del_prev bool) []string {
  bucket := Backup(self.Conf).Aws.S3.MetadataBucketName
  meta.TestOnlySetInnerState(self.Metadata, proto.Clone(state).(*pb.AllMetadata))

  if del_prev {
    s3_common.EmptyBucketOrDie(ctx, self.Client, bucket)
    s3_common.PutProtoOrDie(ctx, self.Client, bucket, meta.MetadataKey, state)
    return nil
  }
  s3_common.PutProtoOrDie(ctx, self.Client, bucket, meta.MetadataKey, state)
  //time.Sleep(3*time.Second)
  versions := s3_common.ListObjectVersionsOrDie(ctx, self.Client, bucket, meta.MetadataKey)
  return versions
}

func (self *s3MetaReadWriteTester) GetPersistedStateAndVersions(ctx context.Context) (*pb.AllMetadata, []string) {
  bucket := Backup(self.Conf).Aws.S3.MetadataBucketName
  state := &pb.AllMetadata{}
  s3_common.GetProtoOrDie(ctx, self.Client, bucket, meta.MetadataKey, state)
  //time.Sleep(3*time.Second)
  versions := s3_common.ListObjectVersionsOrDie(ctx, self.Client, bucket, meta.MetadataKey)
  return state, versions
}

func (self *s3MetaReadWriteTester) TestPersistCurrentMetadataState_New(ctx context.Context) {
  s3_common.EmptyBucketOrDie(ctx, self.Client, Backup(self.Conf).Aws.S3.MetadataBucketName)
  meta.TestOnlySetInnerState(self.Metadata, &pb.AllMetadata{})
  new_seq := util.DummySnapshotSequence(uuid.NewString(), uuid.NewString())

  new_head, err := self.Metadata.RecordSnapshotSeqHead(ctx, new_seq)
  if err != nil { util.Fatalf("RecordSnapshotSeqHead %v", err) }
  version, err := self.Metadata.PersistCurrentMetadataState(ctx)
  if err != nil { util.Fatalf("PersistCurrentMetadataState %v", err) }
  if len(version) < 1 { util.Fatalf("empty version string") }

  state, _ := self.GetPersistedStateAndVersions(ctx)
  //util.Debugf("state: %s\nversions: %v", util.AsJson(state), versions)
  util.EqualsOrDie("Bad head", state.Heads[0], new_head)
}

func (self *s3MetaReadWriteTester) TestPersistCurrentMetadataState_Add(ctx context.Context) {
  vol_uuid, ini_state := util.DummyAllMetadata()
  self.PutPersistedStateGetVersions(ctx, ini_state, true)
  new_snap := util.DummySnapshot(uuid.NewString(), vol_uuid)

  new_seq, err := self.Metadata.AppendSnapshotToSeq(ctx, ini_state.Sequences[0], new_snap)
  if err != nil { util.Fatalf("AppendSnapshotToSeq %v", err) }
  version, err := self.Metadata.PersistCurrentMetadataState(ctx)
  if err != nil { util.Fatalf("PersistCurrentMetadataState %v", err) }
  if len(version) < 1 { util.Fatalf("empty version string") }

  state, versions := self.GetPersistedStateAndVersions(ctx)
  util.EqualsOrDie("Bad version count", len(versions), 2)
  util.EqualsOrDie("Bad sequence", state.Sequences[0], new_seq)
}

func TestAllS3Metadata(ctx context.Context, conf *pb.Config, aws_conf *aws.Config) {
  metadata, err := meta.NewMetadataAdmin(conf, aws_conf, Backup(conf).Name)
  if err != nil { util.Fatalf("%v", err) }
  client := meta.TestOnlyGetInnerClientToAvoidConsistencyFails(metadata)

  suite := s3MetaAdminTester {
    &s3MetaReadWriteTester{ Conf: conf, Client: client, Metadata: metadata, },
  }

  suite.TestS3MetadataSetup(ctx)
  suite.TestPersistCurrentMetadataState_New(ctx)
  suite.TestPersistCurrentMetadataState_Add(ctx)
  s3_common.DeleteBucketOrDie(ctx, client, Backup(conf).Aws.S3.MetadataBucketName)
}

