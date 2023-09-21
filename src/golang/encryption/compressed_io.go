package encryption

import (
  "compress/gzip"
  "context"
  "io"

  "btrfs_to_glacier/util"
)

// Uncompressed data will be read from `source`.
// Compressed data will be read from the returned `reader`.
// `source` will not be closed by this method.
func NewCompressingSource_Gzip(source io.Reader) io.ReadCloser {
  reader, writer := io.Pipe()
  gzip_w := gzip.NewWriter(writer)
  go func() {
    var fls_err, cmp_err error
    count, cpy_err := io.Copy(gzip_w, source)
    // Do not write anything else in case there was a copy error
    if cpy_err == nil {
      // BE CAREFUL IT IS A TRAP !
      // `gzip.Writer.Close()` does not flush.
      fls_err = gzip_w.Flush()
      cmp_err = gzip_w.Close()
    }
    pip_err := writer.CloseWithError(util.Coalesce(cpy_err, fls_err, cmp_err))
    all_err := util.Coalesce(cpy_err, fls_err, cmp_err, pip_err)
    if all_err != nil { util.Warnf("NewCompressingSource_Gzip: count=%d, %v", count, all_err) }
  }()
  return reader
}

func NewCompressingSource(source io.Reader) io.ReadCloser {
  return io.NopCloser(source)
  //return NewCompressingSource_Gzip(source)
}

type syncCloser struct {
  io.WriteCloser
  ctx context.Context
  done chan bool
}

func(self syncCloser) Close() error {
  err := self.WriteCloser.Close()
  //util.Warnf("syncCloser.Close: %v", err)
  if err != nil { return err }
  select {
    case <-self.done:
    case <-self.ctx.Done(): return self.ctx.Err()
  }
  return nil
}

// Compressed data must be written to the returned `writer`.
// `sink` will be written with the uncompressed data.
// `sink` will not be closed by this method.
// IMPORTANT: the returned writer will block until all data has gone to `sink` when closing.
// Does not return errors upon creation on purpose. It is easier for error handling in callign code.
func NewDecompressingSink_Gzip(ctx context.Context, sink io.Writer) io.WriteCloser {
  done := make(chan bool)
  reader, writer := io.Pipe()

  go func() {
    var cpy_err, cmp_err error
    var count int64
    gzip_r, new_err := gzip.NewReader(reader)
    // When copy has finished we know `writer` was closed or there was an error.
    // It should be safe to close the readers.
    if new_err == nil {
      count, cpy_err = io.Copy(sink, gzip_r)
      cmp_err = gzip_r.Close()
    }
    pip_err := reader.CloseWithError(util.Coalesce(new_err, cpy_err, cmp_err))
    all_err := util.Coalesce(new_err, cpy_err, cmp_err, pip_err)
    if all_err != nil { util.Warnf("NewDecompressingSink_Gzip: count=%d, %v", count, all_err) }
    util.Warnf("first")
    close(done)
  }()
  return syncCloser{writer, ctx, done}
}

type nopCloser struct { io.Writer }
func (self nopCloser) Close() error { return nil }

func NewDecompressingSink(ctx context.Context, sink io.Writer) io.WriteCloser {
  return nopCloser{sink}
  //return NewDecompressingSink_Gzip(ctx, sink)
}

