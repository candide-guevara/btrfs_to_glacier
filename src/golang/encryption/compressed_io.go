package encryption

import (
  "compress/gzip"
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
    count, cpy_err := io.Copy(gzip_w, source)
    // BE CAREFUL IT IS A TRAP !
    // `gzip.Writer.Close()` does not flush.
    fls_err := gzip_w.Flush()
    cmp_err := gzip_w.Close()
    pip_err := writer.CloseWithError(util.Coalesce(cpy_err, fls_err, cmp_err))
    all_err := util.Coalesce(cpy_err, fls_err, cmp_err, pip_err)
    if all_err != nil { util.Warnf("NewCompressingSource: count=%d, %v", count, all_err) }
  }()
  return reader
}

func NewCompressingSource(source io.Reader) io.ReadCloser {
  return io.NopCloser(source)
}

// Compressed data must be written to the returned `writer`.
// `sink` will be written with the uncompressed data.
// `sink` will not be closed by this method.
// Does not return errors upon creation on purpose. It is easier for error handling in callign code.
func NewDecompressingSink_Gzip(sink io.Writer) io.WriteCloser {
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
    if all_err != nil { util.Warnf("NewDecompressingSink: count=%d, %v", count, all_err) }
  }()
  return writer
}

type nopCloser struct { io.Writer }
func (self nopCloser) Close() error { return nil }
func NewDecompressingSink(sink io.Writer) io.WriteCloser {
  return nopCloser{sink}
}

