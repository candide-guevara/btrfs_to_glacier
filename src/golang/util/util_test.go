package util

import (
  "bytes"
  "context"
  "io"
  "math/rand"
  "testing"
  "time"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
)

func runCmdGetOutputOrDie(
    ctx context.Context, t *testing.T, args []string) (<-chan []byte, types.ReadEndIf) {
  read_end, err := StartCmdWithPipedOutput(ctx, args)
  if err != nil {
    t.Fatalf("%v failed: %v", args, err)
  }

  done := make(chan []byte, 1)
  go func() {
    defer read_end.Close()
    data, _ := io.ReadAll(read_end)
    done <- data
  }()

  return done, read_end
}

func testInMemPipeCtxCancel_Helper(t *testing.T, pipe types.Pipe, pipe_f func([]byte)) {
  done := make(chan bool, 1)
  go func() {
    defer close(done)
    buf := make([]byte, 1024*1024) //big enough to fill a file pipe
    pipe_f(buf)
  }()
  select {
    case <-done: return
    case <-time.After(LargeTimeout):
      t.Fatalf("context timeout was not taken into account")
  }
}

func TestInMemPipeCtxCancel_WhileWriting(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
  defer cancel()
  pipe := NewInMemPipe(ctx)
  pipe_f := func(buf []byte) { pipe.WriteEnd().Write(buf) }
  testInMemPipeCtxCancel_Helper(t, pipe, pipe_f)
}

func TestFileBasedPipeCtxCancel_WhileWriting(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
  defer cancel()
  pipe := NewFileBasedPipe(ctx)
  pipe_f := func(buf []byte) { pipe.WriteEnd().Write(buf) }
  testInMemPipeCtxCancel_Helper(t, pipe, pipe_f)
}

func TestInMemPipeCtxCancel_WhileReading(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
  defer cancel()
  pipe := NewInMemPipe(ctx)
  pipe_f := func(buf []byte) { pipe.ReadEnd().Read(buf) }
  testInMemPipeCtxCancel_Helper(t, pipe, pipe_f)
}

func TestFileBasedPipeCtxCancel_WhileReading(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
  defer cancel()
  pipe := NewFileBasedPipe(ctx)
  pipe_f := func(buf []byte) { pipe.ReadEnd().Read(buf) }
  testInMemPipeCtxCancel_Helper(t, pipe, pipe_f)
}

func TestFileBasedPipeHasGoodImpl(t *testing.T) {
  pipe := NewFileBasedPipe(context.TODO())
  defer pipe.WriteEnd().Close()
  defer pipe.ReadEnd().Close()
  if _,ok := pipe.ReadEnd().(types.HasFileDescriptorIf); !ok { t.Error("bad impl for read end") }
  if _,ok := pipe.WriteEnd().(types.HasFileDescriptorIf); !ok { t.Error("bad impl for write end") }
  if _,ok := pipe.WriteEnd().(io.ReaderFrom); !ok { t.Error("bad impl for write end") }
  //if _,ok := pipe.ReadEnd().(io.WriterTo); !ok { t.Error("bad impl for read end") }
}

func randomPipeImpl(t *testing.T, ctx context.Context) types.Pipe {
  if rand.Int() % 2 == 0 {
    t.Logf("NewInMemPipe")
    return NewInMemPipe(ctx)
  }
  t.Logf("NewFileBasedPipe")
  return NewFileBasedPipe(ctx)
}
func TestPipePropagateClosure_Fuzzer(t *testing.T) {
  if RaceDetectorOn { return }
  seed := time.Now().UnixNano()
  rand.Seed(seed)
  pipe_cnt := 1 + rand.Intn(7)
  chan_cnt := pipe_cnt + 1
  done := make(chan int)
  ctx,cancel := context.WithTimeout(context.Background(), TestTimeout)
  defer cancel()
  expect_count := make([]int, chan_cnt)
  pipes := make([]types.Pipe, pipe_cnt)
  var pipe_last types.Pipe = randomPipeImpl(t, ctx)
  message := GenerateRandomTextData(1024 + rand.Intn(3*4096))
  t.Logf("seed=%d, pipe_cnt=%d, len(message)=%d", seed, pipe_cnt, len(message))

  go func(pipe types.Pipe) {
    defer pipe.WriteEnd().Close()
    pipe.WriteEnd().Write(message)
    done <- 0
  }(pipe_last)

  copy_f := func(idx int, write io.WriteCloser, read io.ReadCloser) {
    defer write.Close()
    defer read.Close()
    io.Copy(write, read)
    done <- idx
  }
  for i,_ := range pipes {
    pipes[i] = randomPipeImpl(t, ctx)
    go copy_f(i+1, pipes[i].WriteEnd(), pipe_last.ReadEnd())
    pipe_last = pipes[i]
    expect_count[i+1] = i+1
  }

  var data []byte
  go func(pipe types.Pipe) {
    defer pipe.ReadEnd().Close()
    defer close(done)
    data,_ = io.ReadAll(pipe.ReadEnd())
  }(pipe_last)

  count := []int{}
  for i := range done { count = append(count, i) }
  EqualsOrFailTest(t, "count", count, expect_count)
  EqualsOrFailTest(t, "message bytes", data, message)
}

func TestLimitReadExhaustedThenCloseBehavior(t *testing.T) {
  const message = "coucou_salut"
  const limit_len = len(message) - 2
  close_test_f := func(scope string, writer io.WriteCloser, reader io.ReadCloser) {
    ctx,cancel := context.WithTimeout(context.Background(), TestTimeout)
    defer cancel()
    read_done := make(chan error)
    write_done := make(chan error)
    go func() {
      defer close(write_done)
      var err error
      for err == nil {
        _, err = writer.Write([]byte(message))
      }
    }()
    go func() {
      defer close(read_done)
      defer reader.Close()
      buffer := make([]byte, 2*len(message))
      cnt,err := reader.Read(buffer)
      // BE CAREFUL IT IS A TRAP !
      // Even if we exhaust the limited reader capacity on a single read, it will not return io.EOF
      // Documented in https://pkg.go.dev/io#Reader
      if err != nil || cnt != limit_len {
        t.Fatalf("Read failed prematurely: scope:%s, count:%d, err:%v", scope, cnt, err)
      }
      cnt,err = reader.Read(buffer)
      if err != io.EOF || cnt != 0 {
        t.Fatalf("Cannot read after the limit: %s", scope)
      }
    }()
    for done_cnt:=0; done_cnt != 2; {
      select {
        case <-read_done:  done_cnt+=1 ; read_done = nil
        case <-write_done: done_cnt+=1 ; write_done = nil
        case <-ctx.Done():
          t.Fatalf("Context expired while running test '%s'", scope)
      }
    }
  }

  pipe_3 := NewInMemPipe(context.Background())
  close_test_f("pipe_3", pipe_3.WriteEnd(),
               NewPropagatingLimitedReadEnd(pipe_3.ReadEnd(), uint64(limit_len)))
  pipe_4 := NewFileBasedPipe(context.Background())
  close_test_f("pipe_4", pipe_4.WriteEnd(),
               NewPropagatingLimitedReadEnd(pipe_4.ReadEnd(), uint64(limit_len)))
}

func TestReadExhaustedThenCloseBehavior(t *testing.T) {
  const message = "coucou_salut"
  close_test_f := func(scope string, writer io.WriteCloser, reader io.ReadCloser) {
    ctx,cancel := context.WithTimeout(context.Background(), TestTimeout)
    defer cancel()
    read_done := make(chan error)
    write_done := make(chan error)
    go func() {
      defer close(write_done)
      defer writer.Close()
      var err error
      for err == nil {
        _, err = writer.Write([]byte(message))
      }
    }()
    go func() {
      defer close(read_done)
      defer reader.Close()
      buffer := make([]byte, 3+len(message)) // unaligned read and writes
      for total:=0; total < (len(buffer) * 7); {
        cnt,err := reader.Read(buffer)
        if err != nil || cnt == 0 {
          t.Fatalf("Read failed prematurely: scope:%s, count:%d, err:%v, total:%d",
                   scope, cnt, err, total)
        }
        total += cnt
      }
    }()
    for done_cnt:=0; done_cnt != 2; {
      select {
        case <-read_done:  done_cnt+=1 ; read_done = nil
        case <-write_done: done_cnt+=1 ; write_done = nil
        case <-ctx.Done():
          t.Fatalf("Context expired TestReadExhaustedThenCloseBehavior '%s', read:%v, write:%v",
                   scope, read_done, write_done)
      }
    }
  }

  pipe_1 := NewInMemPipe(context.Background())
  close_test_f("pipe_1", pipe_1.WriteEnd(), pipe_1.ReadEnd())
  pipe_2 := NewFileBasedPipe(context.Background())
  close_test_f("pipe_2", pipe_2.WriteEnd(), pipe_2.ReadEnd())
}

func TestClosedReadEndBehavior(t *testing.T) {
  close_test_f := func(scope string, writer io.WriteCloser, reader io.ReadCloser) {
    ctx,cancel := context.WithTimeout(context.Background(), TestTimeout)
    defer cancel()
    done := make(chan error)
    reader.Close()
    go func() {
      count,err := writer.Write([]byte("coucou"))
      if count != 0 || err == nil {
        t.Fatalf("Expected write to closed-read-end pipe to fail: count:%d, err:%v", count, err)
      }
    }()
    go func() {
      defer close(done)
      cnt,err := reader.Read(make([]byte,64))
      if err == nil || err == io.EOF || cnt > 0 {
        t.Fatalf("%s.ReadEnd().Read should fail on a closed read end", scope)
      }
    }()
    WaitForClosure(t, ctx, done)
  }

  pipe_1 := NewInMemPipe(context.Background())
  close_test_f("pipe_1", pipe_1.WriteEnd(), pipe_1.ReadEnd())
  pipe_2 := NewFileBasedPipe(context.Background())
  close_test_f("pipe_2", pipe_2.WriteEnd(), pipe_2.ReadEnd())
  pipe_3 := NewInMemPipe(context.Background())
  close_test_f("pipe_3", pipe_3.WriteEnd(), NewPropagatingLimitedReadEnd(pipe_3.ReadEnd(), 1))
  pipe_4 := NewFileBasedPipe(context.Background())
  close_test_f("pipe_4", pipe_4.WriteEnd(), NewPropagatingLimitedReadEnd(pipe_4.ReadEnd(), 1))
}

func TestNonPropagatingLimitedReadEnd(t *testing.T) {
  const message = "coucou_salut"
  const limit_len = len(message) - 2

  ctx,cancel := context.WithTimeout(context.Background(), TestTimeout)
  defer cancel()

  pipe := NewInMemPipe(context.Background())
  limit_reader := NewLimitedReadEnd(pipe.ReadEnd(), uint64(limit_len))

  done := make(chan bool)
  defer close(done)
  go func() {
    select {
      case <-done: return
      case <-ctx.Done():
        t.Fatalf("timedout while testing")
    }
  }()

  go func() {
    count,err := pipe.WriteEnd().Write([]byte(message))
    if count != len(message) || err != nil {
      t.Errorf("Expected to write the whole message: count:%d, err:%v", count, err)
    }
  }()

  buffer := make([]byte, 2*len(message))
  count, err := limit_reader.Read(buffer)
  if count != limit_len || err != nil {
    t.Errorf("limit_reader.Read(buffer): count:%d, err:%v", count, err)
  }
  if err = limit_reader.Close(); err != nil { t.Errorf("limit_reader.Close(): %v", err) }
  count, err = pipe.ReadEnd().Read(buffer)
  if count != (len(message) - limit_len) || err != nil {
    t.Errorf("pipe.ReadEnd().Read(buffer): count:%d, err:%v", count, err)
  }
  done <- true // we are done but wait for coroutine to finish.
}

func TestStartCmdWithPipedOutput_Echo(t *testing.T) {
  args := []string{ "echo", "-n", "salut" }
  ctx, cancel := context.WithTimeout(context.Background(), 2*TestTimeout)
  defer cancel()

  done, read_end := runCmdGetOutputOrDie(ctx, t, args)

  select {
    case data := <-done:
      if string(data) != "salut" { t.Errorf("%v got: '%s'", args, data) }
      if read_end.GetErr() != nil { t.Errorf("Error in output: %v", read_end.GetErr()) }
    case <- ctx.Done():
      t.Fatalf("%v timedout", args)
  }
}

func TestStartCmdWithPipedOutput_ErrPropagation(t *testing.T) {
  args := []string{ "false" }
  ctx, cancel := context.WithTimeout(context.Background(), 2*TestTimeout)
  defer cancel()

  done, read_end := runCmdGetOutputOrDie(ctx, t, args)

  select {
    case <-done:
      if read_end.GetErr() == nil { t.Errorf("StartCmdWithPipedOutput did not propagate errors") }
    case <- ctx.Done():
      t.Fatalf("%v timedout", args)
  }
}

func TestStartCmdWithPipedOutput_Timeout(t *testing.T) {
  args := []string{ "sleep", "60" }
  ctx, cancel := context.WithCancel(context.Background())
  defer cancel()

  done, _ := runCmdGetOutputOrDie(ctx, t, args)
  cancel()

  select {
    case <-done:
    case <-time.After(TestTimeout):
      t.Fatalf("%v did NOT timeout", args)
  }
}

func TestMarshalCompressedPb(t *testing.T) {
  sv := DummySubVolume("some_uuid")
  buf := new(bytes.Buffer)
  err := MarshalCompressedPb(buf, sv)
  if err != nil { t.Fatalf("MarshalCompressedPb(): %v", err) }
  sv_unmarshalled := &pb.SubVolume{}
  err = UnmarshalCompressedPb(buf, sv_unmarshalled)
  if err != nil { t.Fatalf("UnmarshalCompressedPb(): %v", err) }
  EqualsOrFailTest(t, "Bad sv", sv_unmarshalled, sv)
}

