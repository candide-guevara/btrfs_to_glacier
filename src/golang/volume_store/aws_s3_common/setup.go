package aws_s3_common

import (
  "context"
  "errors"
  "fmt"
  "sync"
  "time"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"

  "github.com/aws/aws-sdk-go-v2/service/s3"
  "github.com/aws/aws-sdk-go-v2/aws/arn"
  "github.com/aws/aws-sdk-go-v2/service/sts"
  s3_types "github.com/aws/aws-sdk-go-v2/service/s3/types"
  "github.com/aws/smithy-go"
)

const (
  RemoveMultipartDays = 3
  bucket_wait_secs = 60
)

// The subset of the s3 client used.
// Convenient for unittesting purposes.
type UsedS3If interface {
  CreateBucket (context.Context, *s3.CreateBucketInput,  ...func(*s3.Options)) (*s3.CreateBucketOutput, error)
  HeadBucket   (context.Context, *s3.HeadBucketInput,    ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
  PutPublicAccessBlock(context.Context, *s3.PutPublicAccessBlockInput, ...func(*s3.Options)) (*s3.PutPublicAccessBlockOutput, error)
}

type S3Common struct {
  Conf        *pb.Config
  Aws_conf    types.AwsConf
  BackupConf  *pb.Backup_S3
  Client      UsedS3If
  BucketWait  time.Duration
  AccountId   string
}

var kS3Clients map[string]*s3.Client
var kS3ClientsMutex sync.Mutex

func init() {
  kS3Clients = make(map[string]*s3.Client)
}

// Although operations on objects have read-after-write consistency, that does not apply to buckets.
// Deleting and creating buckets in quick succession and reading objects on that bucket
// with a **different client object** may return NoSuchBucket errors.
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html#ConsistencyModel
//
// Any client object in aws v2 API is designed to be thread safe.
// https://aws.github.io/aws-sdk-go-v2/docs/making-requests/#concurrently-using-service-clients
func GetS3Singleton(aws_conf types.AwsConf) *s3.Client {
  kS3ClientsMutex.Lock()
  defer kS3ClientsMutex.Unlock()
  client, ok := kS3Clients[aws_conf.Id]
  if !ok {
    client = s3.NewFromConfig(*aws_conf.C)
    kS3Clients[aws_conf.Id] = client
  }
  return client
}

func NewS3Common(
    conf *pb.Config, aws_conf types.AwsConf, backup_name string, client UsedS3If) (*S3Common, error) {
  common := &S3Common{
    Conf: conf,
    Aws_conf: aws_conf,
    Client: client,
    BucketWait: bucket_wait_secs * time.Second,
    AccountId: "", // lazy fetch
  }
  if aws,err := util.BackupAwsByName(conf, backup_name); err == nil {
    common.BackupConf = aws.S3
  } else {
    return nil, err
  }
  return common, nil
}

func StrToApiErr(code string) smithy.APIError {
  return &smithy.GenericAPIError{ Code: code, }
}

// Ugly fix because this does not do sh*t 
// if errors.As(err, new(s3_types.NoSuchBucket)) { ... }
func IsS3Error(err_to_compare error, err error) bool {
  if err != nil {
    // Be careful it is a trap ! This will not take into account the underlying type
    //if errors.As(err, &fixed_err) { return true }
    var ae smithy.APIError
    if !errors.As(err, &ae) { util.Fatalf("Got an aws error of unexpected type: %v", err) }

    //util.Debugf("%v ? %v", err_to_compare, err)
    switch fixed_err := err_to_compare.(type) {
      case smithy.APIError:
        return ae.ErrorCode() == fixed_err.ErrorCode()
      default:
        return ae.ErrorCode() == fixed_err.Error()
    }
  }
  return false
}

func (self *S3Common) TestOnlySwapConf(conf *pb.Config) func() {
  old_conf := self.Conf
  self.Conf = conf
  return func() { self.Conf = old_conf }
}

func (self *S3Common) GetAccountIdOrDie(ctx context.Context) *string {
  if len(self.AccountId) < 1 {
    var err error
    self.AccountId, err = GetAccountId(ctx, self.Aws_conf)
    if err != nil { util.Fatalf("Failed to get account id: %v", err) }
  }
  return &self.AccountId
}

// Returns false if the bucket does not exist.
func (self *S3Common) CheckBucketExistsAndIsOwnedByMyAccount(
    ctx context.Context, bucket_name string) (bool, error) {
  var err error
  head_in := &s3.HeadBucketInput{
    Bucket: &bucket_name,
    ExpectedBucketOwner: self.GetAccountIdOrDie(ctx),
  }
  _, err = self.Client.HeadBucket(ctx, head_in)

  if IsS3Error(new(s3_types.NotFound), err) || IsS3Error(new(s3_types.NoSuchBucket), err) {
    util.Debugf("Bucket '%s' does not exist", bucket_name)
    return false, nil
  }
  if err != nil { return false, err }
  return true, nil
}

// Bucket creation parameters:
// * no server side encryption
// * no object lock, not versioning for objects
// * block all public access
func (self *S3Common) CreateBucket(ctx context.Context, bucket_name string) error {
  var err error
  var bucket_location s3_types.BucketLocationConstraint

  bucket_location, err = self.locationConstraintFromConf()
  if err != nil { return err }

  create_in := &s3.CreateBucketInput{
    Bucket: &bucket_name,
    ACL: s3_types.BucketCannedACLPrivate,
    CreateBucketConfiguration: &s3_types.CreateBucketConfiguration{
      LocationConstraint: bucket_location,
    },
    ObjectLockEnabledForBucket: false,
  }
  _, err = self.Client.CreateBucket(ctx, create_in)
  if err != nil { return err }

  waiter := s3.NewBucketExistsWaiter(self.Client)
  wait_rq := &s3.HeadBucketInput{ Bucket: &bucket_name, }
  err = waiter.Wait(ctx, wait_rq, self.BucketWait)
  if err != nil { return err }

  access_in := &s3.PutPublicAccessBlockInput{
    Bucket: &bucket_name,
    PublicAccessBlockConfiguration: &s3_types.PublicAccessBlockConfiguration{
      BlockPublicAcls: true,
      IgnorePublicAcls: true,
      BlockPublicPolicy: true,
      RestrictPublicBuckets: true,
    },
  }
  _, err = self.Client.PutPublicAccessBlock(ctx, access_in)
  if err != nil { return err }
  return nil
}

func (self *S3Common) locationConstraintFromConf() (s3_types.BucketLocationConstraint, error) {
  var invalid s3_types.BucketLocationConstraint = ""
  for _,region := range s3_types.BucketLocationConstraintEu.Values() {
    if string(region) == self.Conf.Aws.Region { return region, nil }
  }
  return invalid, fmt.Errorf("region '%s' does not match any location constraint",
                             self.Conf.Aws.Region)
}

func GetAccountId(ctx context.Context, aws_conf types.AwsConf) (string, error) {
  var err error
  var res_name arn.ARN
  var ident_out *sts.GetCallerIdentityOutput

  client := sts.NewFromConfig(*aws_conf.C)
  ident_in := &sts.GetCallerIdentityInput{}
  ident_out, err = client.GetCallerIdentity(ctx, ident_in)
  if err != nil { return "", err }

  res_name, err = arn.Parse(*(ident_out.Arn))
  if err != nil { return "", err }
  return res_name.AccountID, nil
}

