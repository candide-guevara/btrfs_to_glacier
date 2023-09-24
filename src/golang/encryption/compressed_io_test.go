package encryption

import (
  "bytes"
  "context"
  "io"
  "testing"

  "btrfs_to_glacier/types/mocks"
  "btrfs_to_glacier/util"
  "btrfs_to_glacier/types"
)

func TestZlibSink_BadData(t *testing.T) {
  ctx,cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  buf := new(bytes.Buffer)
  expect_msg := []byte("this is some plain text data")

  zlib_w := NewDecompressingSink_Zlib(ctx, buf)
  // The first write races with the initialization of the zlib reader,
  // so the errors has not time to propagate.
  zlib_w.Write(expect_msg)
  count, err := zlib_w.Write(expect_msg)
  if err == nil { t.Errorf("io.Write: count=%d, %v", count, err) }
  err = zlib_w.Close()
  // No error on close
  if err != nil { t.Errorf("zlib.Close: count=%d, %v", count, err) }
}

func TestZlibSmallMsg_Direct(t *testing.T) {
  ctx,cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  buf := new(bytes.Buffer)
  expect_msg := []byte("this is some plain text data")
  read_pipe := mocks.NewPreloadedPipe(expect_msg).ReadEnd()

  zlib_r := NewCompressingSource_Zlib(read_pipe)
  zlib_w := NewDecompressingSink_Zlib(ctx, buf)
  count, err := io.Copy(zlib_w, zlib_r)
  if err != nil { t.Errorf("io.Copy: count=%d, %v", count, err) }
  err = zlib_w.Close()
  if err != nil { t.Errorf("zlib.Close: count=%d, %v", count, err) }

  util.EqualsOrFailTest(t, "Bad length", buf.Len(), len(expect_msg))
  util.EqualsOrFailTest(t, "Bad content", buf.Bytes(), expect_msg)
}

func TestZlibSmallMsg_ViaBuffer(t *testing.T) {
  ctx,cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  buf := new(bytes.Buffer)
  tmp := new(bytes.Buffer)
  expect_msg := []byte("this is some plain text data")
  read_pipe := mocks.NewPreloadedPipe(expect_msg).ReadEnd()

  zlib_r := NewCompressingSource_Zlib(read_pipe)
  zlib_w := NewDecompressingSink_Zlib(ctx, buf)
  count, err := io.Copy(tmp, zlib_r)
  if err != nil { t.Errorf("io.Copy1: count=%d, %v", count, err) }
  count, err = io.Copy(zlib_w, tmp)
  if err != nil { t.Errorf("io.Copy2: count=%d, %v", count, err) }
  err = zlib_w.Close()
  if err != nil { t.Errorf("zlib.Close: count=%d, %v", count, err) }
}

func TestZlibSmallMsg_ManyWrites(t *testing.T) {
  const kWriteCount = 10
  ctx,cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  buf := new(bytes.Buffer)
  fragment := []byte("this is some plain text data")
  expect_msg := bytes.Repeat(fragment, kWriteCount)
  reader, writer := io.Pipe()

  done_w := make(chan error)
  go func() {
    for i:=0; i<kWriteCount; i+=1 {
      count, err := writer.Write(fragment)
      if err != nil { t.Errorf("Write: count=%d, %v", count, err) }
    }
    err := writer.Close()
    if err != nil { t.Errorf("Close: %v", err) }
    close(done_w)
  }()

  zlib_r := NewCompressingSource_Zlib(reader)
  zlib_w := NewDecompressingSink_Zlib(ctx, buf)
  count, err := io.Copy(zlib_w, zlib_r)
  if err != nil { t.Errorf("io.Copy: count=%d, %v", count, err) }
  err = zlib_w.Close()
  if err != nil { t.Errorf("zlib.Close: count=%d, %v", count, err) }

  util.EqualsOrFailTest(t, "Bad length", buf.Len(), len(expect_msg))
  util.EqualsOrFailTest(t, "Bad content", buf.Bytes(), expect_msg)
  util.WaitForClosure(t, ctx, done_w)
}

func TestZlibLargeMsg(t *testing.T) {
  ctx,cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  buf := new(bytes.Buffer)
  alphabet := []byte("repeat this short message forever and ever.")
  expect_msg := bytes.Repeat(alphabet, 1024)
  read_pipe := mocks.NewBigPreloadedPipe(ctx, expect_msg).ReadEnd()

  zlib_r := NewCompressingSource_Zlib(read_pipe)
  zlib_w := NewDecompressingSink_Zlib(ctx, buf)
  count, err := io.Copy(zlib_w, zlib_r)
  if err != nil { t.Errorf("io.Copy: count=%d, %v", count, err) }
  err = zlib_w.Close()
  if err != nil { t.Errorf("zlib.Close: count=%d, %v", count, err) }

  if bytes.Compare(buf.Bytes(), expect_msg) != 0 {
    t.Errorf("Bad encryption: %d / %d", buf.Len(), len(expect_msg))
  }
}

func testZlibLargeMsg_ViaPipe_Helper(
    ctx context.Context, t *testing.T, pipe_r io.ReadCloser, pipe_w io.WriteCloser) {
  buf := new(bytes.Buffer)
  alphabet := []byte("repeat this short message forever and ever.")
  expect_msg := bytes.Repeat(alphabet, 4096)
  read_pipe := mocks.NewBigPreloadedPipe(ctx, expect_msg).ReadEnd()

  zlib_r := NewCompressingSource_Zlib(read_pipe)
  zlib_w := NewDecompressingSink_Zlib(ctx, buf)
  done_r := make(chan error)
  done_w := make(chan error)

  go func() {
    count, err := io.Copy(pipe_w, zlib_r)
    if err != nil { t.Errorf("io.Copy: count=%d, %v", count, err) }
    err = pipe_w.Close()
    if err != nil { t.Errorf("pipe_w.Close: count=%d, %v", count, err) }
    close(done_r)
  }()
  go func() {
    count, err := io.Copy(zlib_w, pipe_r)
    if err != nil { t.Errorf("io.Copy: count=%d, %v", count, err) }
    err = zlib_w.Close()
    if err != nil { t.Errorf("zlib.Close: count=%d, %v", count, err) }
    close(done_w)
  }()

  util.WaitForClosure(t, ctx, done_r)
  util.WaitForClosure(t, ctx, done_w)
  util.EqualsOrFailTest(t, "Bad length", buf.Len(), len(expect_msg))
}

func TestZlibLargeMsg_ViaPipe(t *testing.T) {
  ctx,cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  pipes := []types.Pipe{
    util.NewFileBasedPipe(ctx),
    util.NewInMemPipe(ctx),
  }
  for _,pipe := range pipes {
    testZlibLargeMsg_ViaPipe_Helper(ctx, t, pipe.ReadEnd(), pipe.WriteEnd())
  }
}

func testZlibSinkCloseRace_Helper(
    ctx context.Context, t *testing.T, pipe_r io.ReadCloser, pipe_w io.WriteCloser) {
  buf := new(bytes.Buffer)
  expect_msg := []byte("this is some plain text data")
  read_pipe := mocks.NewPreloadedPipe(expect_msg).ReadEnd()

  done := make(chan error)
  go func() {
    count, err := io.Copy(buf, pipe_r)
    if err != nil { t.Errorf("io.Copy: count=%d, %v", count, err) }
    close(done)
  }()

  zlib_r := NewCompressingSource_Zlib(read_pipe)
  zlib_w := NewDecompressingSink_Zlib(ctx, pipe_w)
  count, err := io.Copy(zlib_w, zlib_r)
  if err != nil { t.Errorf("io.Copy: count=%d, %v", count, err) }

  err = zlib_w.Close()
  if err != nil { t.Errorf("zlib_w.Close: count=%d, %v", count, err) }
  util.Warnf("second")
  err = pipe_w.Close()
  if err != nil { t.Errorf("pipe_w.Close: count=%d, %v", count, err) }

  util.WaitForClosure(t, ctx, done)
  util.EqualsOrFailTest(t, "Bad length", buf.Len(), len(expect_msg))
}

func TestZlibSinkCloseRace(t *testing.T) {
  ctx,cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  pipes := []types.Pipe{
    util.NewFileBasedPipe(ctx),
    util.NewInMemPipe(ctx),
  }
  for _,pipe := range pipes {
    testZlibSinkCloseRace_Helper(ctx, t, pipe.ReadEnd(), pipe.WriteEnd())
  }
}

