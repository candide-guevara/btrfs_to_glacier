package aws_s3_common

import (
  "bytes"
  "context"
  "fmt"
  "io"
  "sort"

  "btrfs_to_glacier/util"

  "github.com/aws/aws-sdk-go-v2/aws"
  "github.com/aws/aws-sdk-go-v2/service/s3"
  s3mgr "github.com/aws/aws-sdk-go-v2/feature/s3/manager"
  s3_types "github.com/aws/aws-sdk-go-v2/service/s3/types"

  "github.com/google/uuid"
  "google.golang.org/protobuf/proto"
)


type MockS3Client struct {
  Err              error
  RestoreObjectErr error
  DeleteObjsErr    error
  AccountId string
  Data map[string][]byte
  RestoreStx map[string]string
  Class map[string]s3_types.StorageClass
  Buckets map[string]bool
  HeadAlwaysEmpty bool
  HeadAlwaysAccessDenied bool
  FirstListObjEmpty      bool
  LastLifecycleIn *s3.PutBucketLifecycleConfigurationInput
  LastPublicAccessBlockIn *s3.PutPublicAccessBlockInput
  LastPutBucketVersioning *s3.PutBucketVersioningInput
}

func (self *MockS3Client) GetData(key string) ([]byte, bool) {
  data,found := self.Data[key];
  return data,found
}

func (self *MockS3Client) SetData(key string, data []byte, class s3_types.StorageClass, ongoing bool) {
  self.Data[key] = make([]byte, len(data))
  copy(self.Data[key], data)
  //self.Data[key] =  data
  self.Class[key] = class
  if class != s3_types.StorageClassStandard {
    self.RestoreStx[key] = fmt.Sprintf(`ongoing-request="%v"`, ongoing)
  }
}

func (self *MockS3Client) DelData(key string) {
  delete(self.Data, key)
  delete(self.Class, key)
  delete(self.RestoreStx, key)
}

func (self *MockS3Client) GetProto(key string, msg proto.Message) error {
  data,found := self.Data[key];
  if !found { return fmt.Errorf("not_found") }
  err := util.UnmarshalCompressedPb(bytes.NewReader(data), msg)
  return err
}

func (self *MockS3Client) PutProto(
    key string, msg proto.Message, class s3_types.StorageClass, ongoing bool) error {
  blob := new(bytes.Buffer)
  err := util.MarshalCompressedPb(blob, msg)
  if err != nil { return err }
  self.Data[key] = make([]byte, blob.Len())
  copy(self.Data[key], blob.Bytes())
  //self.Data[key] =  blob.Bytes()
  self.Class[key] = class
  if class != s3_types.StorageClassStandard {
    self.RestoreStx[key] = fmt.Sprintf(`ongoing-request="%v"`, ongoing)
  }
  return nil
}

func (self *MockS3Client) CreateBucket(
    ctx context.Context, in *s3.CreateBucketInput, opts ...func(*s3.Options)) (*s3.CreateBucketOutput, error) {
  if _,found := self.Buckets[*in.Bucket]; found {
    return &s3.CreateBucketOutput{}, fmt.Errorf("already created bucket %s", util.AsJson(in))
  }
  self.Buckets[*in.Bucket] = true
  return &s3.CreateBucketOutput{}, self.Err
}

func (self *MockS3Client) DeleteObjects(
    ctx context.Context, in *s3.DeleteObjectsInput, opts...func(*s3.Options)) (*s3.DeleteObjectsOutput, error) {
  out := &s3.DeleteObjectsOutput{}
  for _,obj_id := range in.Delete.Objects {
    delete(self.Data, *obj_id.Key)
    delete(self.RestoreStx, *obj_id.Key)
    delete(self.Class, *obj_id.Key)
  }
  if self.DeleteObjsErr != nil {
    str := self.DeleteObjsErr.Error()
    aws_err := s3_types.Error{ Code:&str, Key:&str, }
    out.Errors = []s3_types.Error{ aws_err }
  }
  return out, self.Err
}

func (self *MockS3Client) GetObject(
    ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
  key := *(in.Key)
  if _,found := self.Data[key]; !found {
    return nil, new(s3_types.NoSuchKey)
  }
  out := &s3.GetObjectOutput{
    Body: io.NopCloser(bytes.NewReader(self.Data[key])),
    ContentLength: int64(len(self.Data[key])),
  }
  return out, self.Err
}

func (self *MockS3Client) ListObjectsV2(
    ctx context.Context, in *s3.ListObjectsV2Input, opts ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
  if in.Prefix != nil || in.StartAfter != nil { util.Fatalf("not_implemented") }
  var page_count int32
  out := &s3.ListObjectsV2Output{
    ContinuationToken: in.ContinuationToken,
    Contents:make([]s3_types.Object, 0, len(self.Data)),
  }

  if self.FirstListObjEmpty {
    self.FirstListObjEmpty = false
    out.NextContinuationToken = aws.String("1")
    return out, self.Err
  }

  // iteration order is not stable: https://go.dev/blog/maps
  keys := make([]string, 0, len(self.Data))
  for key,_ := range self.Data { keys = append(keys, key) }
  sort.Strings(keys)

  for _,key:= range keys {
    if in.ContinuationToken != nil && key <= *in.ContinuationToken { continue }
    data := self.Data[key]
    item := s3_types.Object{ Key:aws.String(key), Size:int64(len(data)), }
    out.Contents = append(out.Contents, item)
    page_count += 1
    if page_count >= in.MaxKeys { out.NextContinuationToken = aws.String(key); break }
  }
  out.KeyCount = page_count
  return out, self.Err
}

func (self *MockS3Client) HeadBucket(
    ctx context.Context, in *s3.HeadBucketInput, opts ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
  _,found := self.Buckets[*(in.Bucket)]
  if self.HeadAlwaysEmpty || !found {
    return nil, new(s3_types.NoSuchBucket)
  }
  bad_owner := in.ExpectedBucketOwner != nil && *(in.ExpectedBucketOwner) != self.AccountId
  if self.HeadAlwaysAccessDenied || bad_owner {
    // Error model is too complex to mock
    // https://aws.github.io/aws-sdk-go-v2/docs/handling-errors/#api-error-responses
    return nil, StrToApiErr("AccessDenied")
  }
  return &s3.HeadBucketOutput{}, self.Err
}

func (self *MockS3Client) HeadObject(
    ctx context.Context, in *s3.HeadObjectInput, opts ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
  key := *(in.Key)
  if _,found := self.Data[key]; !found {
    return nil, new(s3_types.NoSuchKey)
  }
  out := &s3.HeadObjectOutput{ StorageClass: self.Class[key], }
  if restore,found := self.RestoreStx[key]; found { out.Restore = &restore }
  return out, self.Err
}

func (self *MockS3Client) PutBucketLifecycleConfiguration(
    ctx context.Context, in *s3.PutBucketLifecycleConfigurationInput, opts ...func(*s3.Options)) (*s3.PutBucketLifecycleConfigurationOutput, error) {
  if _,found := self.Buckets[*in.Bucket]; !found {
    return &s3.PutBucketLifecycleConfigurationOutput{}, fmt.Errorf("unknown bucket %v", util.AsJson(in))
  }
  self.LastLifecycleIn = in
  rs := &s3.PutBucketLifecycleConfigurationOutput{}
  return rs, self.Err
}

func (self *MockS3Client) PutPublicAccessBlock(
    ctx context.Context, in *s3.PutPublicAccessBlockInput, opts ...func(*s3.Options)) (*s3.PutPublicAccessBlockOutput, error) {
  if _,found := self.Buckets[*in.Bucket]; !found {
    return &s3.PutPublicAccessBlockOutput{}, fmt.Errorf("unknown bucket %v", util.AsJson(in))
  }
  self.LastPublicAccessBlockIn = in
  return &s3.PutPublicAccessBlockOutput{}, self.Err
}

func (self *MockS3Client) RestoreObject(
  ctx context.Context, in *s3.RestoreObjectInput, opts ...func(*s3.Options)) (*s3.RestoreObjectOutput, error) {
  key := *(in.Key)
  if _,found := self.Data[key]; !found {
    return nil, new(s3_types.NoSuchKey)
  }
  return &s3.RestoreObjectOutput{}, self.RestoreObjectErr
}

func (self *MockS3Client) Upload(
    ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3mgr.Uploader)) (*s3mgr.UploadOutput, error) {
  if in.Bucket == nil || len(*in.Bucket) < 1 { return nil, fmt.Errorf("malormed request") }
  if in.Key == nil || len(*in.Key) < 1 { return nil, fmt.Errorf("malormed request") }
  if self.Err == nil {
    buf, err := io.ReadAll(in.Body)
    if err != nil { return nil, err }
    if _,found := self.Data[*in.Key]; found { return nil, fmt.Errorf("overwritting key") }
    self.Data[*in.Key] = buf
    return &s3mgr.UploadOutput{}, self.Err
  }
  return nil, self.Err
}

func (self *MockS3Client) PutObject(
    ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
  if self.Err == nil {
    buf, err := io.ReadAll(in.Body)
    if err != nil { return nil, err }
    self.Data[*in.Key] = buf
    put_out := &s3.PutObjectOutput{
      VersionId: aws.String(uuid.NewString()),
    }
    return put_out, self.Err
  }
  return nil, self.Err
}

func (self *MockS3Client) PutBucketVersioning(
  ctx context.Context, in *s3.PutBucketVersioningInput, opts ...func(*s3.Options)) (*s3.PutBucketVersioningOutput, error) {
  if _,found := self.Buckets[*in.Bucket]; !found {
    return &s3.PutBucketVersioningOutput{}, fmt.Errorf("unknown bucket %v", util.AsJson(in))
  }
  self.LastPutBucketVersioning = in
  return &s3.PutBucketVersioningOutput{}, self.Err
}

