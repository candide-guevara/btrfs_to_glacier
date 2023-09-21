package util

import (
  "bytes"
  "compress/gzip"
  "context"
  "crypto/md5"
  "errors"
  "fmt"
  "io"
  "io/fs"
  "os"
  "os/exec"
  fpmod "path/filepath"
  "reflect"
  "strings"
  "sync"
  "time"
  "unicode"
  "unicode/utf8"

  "btrfs_to_glacier/types"
  pb "btrfs_to_glacier/messages"

  "google.golang.org/protobuf/proto"
  "golang.org/x/sys/unix"
)

type WriteEndImpl struct {
  io.WriteCloser
  parent *PipeImpl
}

type WriteEndFile struct {
  *os.File
  parent *PipeImpl
}

type WriteEndBuffer struct { *bytes.Buffer }

// Writing will block until the context or timeout expires
type WriteEndBlock struct {
  ctx context.Context
  timeout time.Duration
}

func (self *WriteEndImpl) SetErr(err error) {
  if err == nil { return }
  self.parent.mutex.Lock()
  defer self.parent.mutex.Unlock()
  self.parent.err = err
}

func (self *WriteEndImpl) CloseWithError(err error) error {
  self.SetErr(err)
  return CloseWithError(self.WriteCloser, err)
}

func (self *WriteEndFile) SetErr(err error) {
  if err == nil { return }
  self.parent.mutex.Lock()
  defer self.parent.mutex.Unlock()
  self.parent.err = err
}

func (self *WriteEndFile) CloseWithError(err error) error {
  self.SetErr(err)
  return CloseWithError(self.File, err)
}

func (self *WriteEndBuffer) SetErr(err error) {}
func (self *WriteEndBuffer) CloseWithError(err error) error { return nil }
func (self *WriteEndBuffer) Close() error { return nil }
func NewBufferWriteEnd() *WriteEndBuffer {
  return &WriteEndBuffer{ Buffer:new(bytes.Buffer), }
}

func (self *WriteEndBlock) SetErr(err error) {}
func (self *WriteEndBlock) CloseWithError(err error) error { return nil }
func (self *WriteEndBlock) Close() error { return nil }
func (self *WriteEndBlock) Write(p []byte) (n int, err error) {
  select {
    case <-self.ctx.Done():
      if self.ctx.Err() == nil { Fatalf("WriteEndBlock self.ctx.Err() should have error") }
      return 0, self.ctx.Err()
    case <-time.After(self.timeout):
      Fatalf("WriteEndBlock timedout: %v", self.timeout)
  }
  return 0, fmt.Errorf("WriteEndBlock wtf")
}
func NewWriteEndBlock(ctx context.Context, timeout time.Duration) *WriteEndBlock {
  return &WriteEndBlock{ ctx:ctx, timeout:timeout, }
}

type ReadEndImpl struct {
  io.ReadCloser
  parent *PipeImpl
}
type ReadEndFile struct {
  *os.File
  parent *PipeImpl
}
type ReadEndLimitedImpl struct {
  *io.LimitedReader
  inner types.ReadEndIf
  propagate_close bool
}
type ReadEndNoErrWrapper struct { io.ReadCloser }
func (self *ReadEndImpl) GetErr() error {
  self.parent.mutex.Lock()
  defer self.parent.mutex.Unlock()
  return self.parent.err
}
func (self *ReadEndFile) GetErr() error {
  self.parent.mutex.Lock()
  defer self.parent.mutex.Unlock()
  return self.parent.err
}
func (self *ReadEndNoErrWrapper) GetErr() error { return nil }
func WrapPlainReaderCloser(inner io.ReadCloser) types.ReadEndIf {
  return &ReadEndNoErrWrapper{ ReadCloser: inner, }
}
func ReadEndFromBytes(data []byte) types.ReadEndIf {
  return &ReadEndNoErrWrapper{ ReadCloser: io.NopCloser(bytes.NewBuffer(data)), }
}
func (self *ReadEndLimitedImpl) GetErr() error { return self.inner.GetErr() }
func (self *ReadEndLimitedImpl) Close()  error {
  if self.propagate_close { return self.inner.Close() }
  return nil
}
func NewLimitedReadEnd(inner types.ReadEndIf, limit uint64) *ReadEndLimitedImpl {
  limited := &io.LimitedReader{ R:inner, N:int64(limit), }
  return &ReadEndLimitedImpl{ LimitedReader:limited, inner:inner, propagate_close:false, }
}
func NewPropagatingLimitedReadEnd(inner types.ReadEndIf, limit uint64) *ReadEndLimitedImpl {
  limited := &io.LimitedReader{ R:inner, N:int64(limit), }
  return &ReadEndLimitedImpl{ LimitedReader:limited, inner:inner, propagate_close:true, }
}


type PipeImpl struct {
  read_end  types.ReadEndIf
  write_end types.WriteEndIf
  mutex     sync.Mutex
  err       error
}

func NewInMemPipe(ctx context.Context) *PipeImpl {
  read_end, write_end := io.Pipe()
  pipe := &PipeImpl{
    mutex: sync.Mutex{},
    err: nil,
  }
  pipe.read_end =  &ReadEndImpl { ReadCloser:read_end, parent:pipe, }
  pipe.write_end = &WriteEndImpl{ WriteCloser:write_end, parent:pipe, }
  go func() {
    select {
      case <-ctx.Done():
        //Warnf("NewInMemPipe ctx closing")
        read_end.Close()
        write_end.Close()
    }
  }()
  return pipe
}

func NewFileBasedPipe(ctx context.Context) *PipeImpl {
  read_end, write_end, err := os.Pipe()
  if err != nil { Fatalf("failed os.Pipe %v", err) }
  pipe := &PipeImpl{
    mutex: sync.Mutex{},
    err: nil,
  }
  pipe.read_end =  &ReadEndFile { File:read_end, parent:pipe, }
  pipe.write_end = &WriteEndFile{ File:write_end, parent:pipe, }
  // Looking at posix pipes, it is not clear whether closing like this is bullet proof
  // see https://man7.org/linux/man-pages/man2/close.2.html
  go func() {
    select {
      case <-ctx.Done():
        //Infof("NewFileBasedPipe ctx closing")
        read_end.Close()
        write_end.Close()
    }
  }()
  return pipe
}

func (self *PipeImpl) ReadEnd()  types.ReadEndIf  { return self.read_end }
func (self *PipeImpl) WriteEnd() types.WriteEndIf { return self.write_end }


// Synchronous, waits for the command to finish
// Takes ownership of `input` and will close it once done.
func StartCmdWithPipedInput(ctx context.Context, input types.ReadEndIf, args []string) error {
  var err error
  buf_err := new(bytes.Buffer)
  buf_out := new(bytes.Buffer)
  defer input.Close()

  command := exec.CommandContext(ctx, args[0], args[1:]...)
  command.Stdin = input
  command.Stdout = buf_out
  command.Stderr = buf_err

  err = command.Start()
  if err != nil {
    return fmt.Errorf("%v: %v", args, err)
  }
  Infof("%v started as pid %d", args, command.Process.Pid)

  err = command.Wait()
  if err != nil && ctx.Err() == nil {
    return fmt.Errorf("%v failed: %v\nstderr: %s", args, err, buf_err.Bytes())
  }
  Infof("%v done, output:\n%s", args, buf_out)
  return input.GetErr()
}

func StartCmdAndWait(ctx context.Context, args []string) error {
  return StartCmdWithPipedInput(ctx, ReadEndFromBytes(nil), args)
}

func StartCmdWithPipedOutput(ctx context.Context, args []string) (types.ReadEndIf, error) {
  var err error
  pipe := NewFileBasedPipe(ctx)
  defer func() { OnlyCloseWriteEndWhenError(pipe, err) }()

  buf_err := new(bytes.Buffer)
  command := exec.CommandContext(ctx, args[0], args[1:]...)
  command.Stdout = pipe.WriteEnd()
  command.Stderr = buf_err

  err = command.Start()
  if err != nil {
    return nil, fmt.Errorf("%v: %v", args, err)
  }
  Infof("%v started as pid %d", args, command.Process.Pid)

  go func() {
    var err error
    defer func() { CloseWriteEndWithError(pipe, err) }()
    err = command.Wait()
    if err != nil && ctx.Err() == nil {
      err = fmt.Errorf("%v failed: %v\nstderr: %s", args, err, buf_err.Bytes())
    }
  }()
  return pipe.ReadEnd(), pipe.ReadEnd().GetErr()
}

func CloseWriteEndWithError(pipe types.Pipe, err error) {
  obj := pipe.WriteEnd()
  CloseWithError(obj, err)
}

func CloseWithError(obj io.Closer, err error) error {
  if err != nil {
    defer Warnf("CloseWithError: %v", err)
    if adv_obj,ok := obj.(types.CloseWithErrIf); ok {
      return adv_obj.CloseWithError(err)
    }
  }
  return obj.Close()
}

func OnlyCloseWriteEndWhenError(pipe types.Pipe, err error) {
  if err == nil { return }
  CloseWriteEndWithError(pipe, err)
}

func OnlyCloseWhenError(obj io.Closer, err error) {
  if err == nil { return }
  CloseWithError(obj, err)
}

func Coalesce(errors ...error) error {
  for _,e := range errors { if e != nil { return e } }
  return nil
}

// Closes the channel if `err != nil`.
// If `channel` is of type `channel error` then attempts to send the error before closing.
func OnlyCloseChanWhenError(channel interface{}, err error) {
  if err == nil { return }
  rv := reflect.ValueOf(channel)
  if rk := rv.Kind(); rk != reflect.Chan {
    Fatalf("expecting type: 'chan ...'  instead got: %s", rk.String())
  }
  is_chan_err := rv.Type().Elem() == reflect.TypeOf((*error)(nil)).Elem()
  is_send_dir := rv.Type().ChanDir() != reflect.RecvDir
  if is_chan_err && is_send_dir {
    if ok := rv.TrySend(reflect.ValueOf(err)); !ok { Fatalf("failed to send before closing: %v", err) }
  }
  rv.Close()
}

func WrapInChan(err error) (<-chan error) {
  done := make(chan error, 1)
  done <- err
  close(done)
  return done
}

func PbErrorf(format string, pbs ...proto.Message) error {
  return errors.New(PbPrintf(format, pbs...))
}

// Should NOT copy `str` because it may contain sensible pw that will stick until GC.
func IsOnlyAsciiString(str []byte, allow_ctrl bool) error {
  if !utf8.Valid(str) { return fmt.Errorf("String is not valid unicode") }
  for idx,b := range str {
    codept := rune(b)
    // only ascii non control are allowed
    if codept > unicode.MaxASCII || (!allow_ctrl && unicode.IsControl(codept)) {
      return fmt.Errorf("String is has invalid characters at %d: '0x%x'", idx, codept)
    }
  }
  return nil
}

// Removes problematic characters for shell arguments.
func SanitizeShellInput(in []byte) string {
  sanitized := bytes.Map(func(b rune) rune {
    if b > unicode.MaxASCII || unicode.IsControl(b) { return -1 }
    if strings.ContainsRune(";&$`(){}<>", b) { return -1 }
    return b
  }, in)
  return string(sanitized)
}

func IsDir(path string) bool {
  f_info, err := os.Lstat(path)
  if err != nil { return false }
  return f_info.IsDir()
}

func IsSymLink(path string) bool {
  f_info, err := os.Lstat(path)
  if err != nil { return false }
  return f_info.Mode() & fs.ModeSymlink != 0
}

// os.IsNotExists does not do sh*t
func IsNotExist(err error) bool {
  return os.IsNotExist(err) || errors.Is(err, unix.ENOENT)
}

func Exists(path string) bool {
  _, err := os.Lstat(path)
  return !IsNotExist(err)
}

func UnmarshalGzProto(path string, msg proto.Message) error {
  f, err := os.Open(path)
  if err != nil { return err }
  defer f.Close()

  reader, err := gzip.NewReader(f)
  if err != nil { return err }
  defer reader.Close()

  data, err := io.ReadAll(reader)
  if err != nil { return err }
  err = proto.Unmarshal(data, msg)
  return err
}

func MarshalGzProto(path string, msg proto.Message) error {
  f, err := os.Create(path)
  if err != nil { return err }
  defer f.Close()

  data, err := proto.Marshal(msg)
  if err != nil { return err }

  writer := gzip.NewWriter(f)
  _,err = writer.Write(data)
  if err != nil { writer.Close(); return err }
  return writer.Close()
}

func RemoveAll(path string) error {
  tmpdir := os.TempDir()
  if !fpmod.HasPrefix(path, tmpdir) {
    return fmt.Errorf("HasPrefix('%s', '%s')", path, tmpdir)
  }
  return os.RemoveAll(path)
}

// We have to call the shell, golang does not have an API for `cp -r`
func RecursiveCopy(ctx context.Context, dst string, srcs []string) error {
  tmpdir := os.TempDir()
  var cmd_paths []string
  cmd_paths = append(cmd_paths, srcs...)
  cmd_paths = append(cmd_paths, dst)
  for _,p := range cmd_paths {
    if !fpmod.HasPrefix(p, tmpdir) {
      return fmt.Errorf("!HasPrefix('%s', '%s')", p, tmpdir)
    }
  }
  cmd := []string{ "cp", "--one-file-system", "--recursive", "--no-dereference", "--no-clobber" }
  cmd = append(cmd, cmd_paths...)
  return StartCmdAndWait(ctx, cmd)
}

func HashFromSv(sv *pb.SubVolume, chain string) string {
  buf := new(bytes.Buffer)
  buf.WriteString(chain)
  buf.WriteString(sv.Uuid)
  // Do not add parent since it changes as we append clones to the sequence
  //buf.WriteString(sv.ParentUuid)
  for _,c := range sv.Data.Chunks { buf.WriteString(c.Uuid) }
  return fmt.Sprintf("%x", md5.Sum(buf.Bytes()))
}

