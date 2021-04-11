package util

import "context"
import "encoding/base64"
import "encoding/json"
import "math/rand"
import "strings"
import "testing"
import "btrfs_to_glacier/types"

func CompareAsStrings(t *testing.T, val interface{}, expected interface{}) {
  var val_str, expected_str []byte
  var val_err, expected_err error
  val_str, val_err = json.MarshalIndent(val, "", "  ")
  expected_str, expected_err = json.MarshalIndent(expected, "", "  ")
  if val_err != nil || expected_err != nil { panic("cannot marshal to json string") }
  if strings.Compare(string(val_str), string(expected_str)) != 0 {
    t.Errorf("\n%s\n !=\n%s", val_str, expected_str)
  }
}

func GenerateRandomTextData(size int) []byte {
  buffer := make([]byte, size)
  buffer_txt := make([]byte, base64.StdEncoding.EncodedLen(size))
  _, err := rand.Read(buffer)
  if err != nil { Fatalf("rand failed: %v", err) }
  base64.StdEncoding.Encode(buffer_txt, buffer)
  return buffer_txt[:size]
}

func ProduceRandomTextIntoPipe(ctx context.Context, chunk int, iterations int) types.PipeReadEnd {
  var err error
  pipe := NewFileBasedPipe()
  defer CloseIfProblemo(pipe, &err)

  go func() {
    defer pipe.WriteEnd().Close()
    for i:=0; ctx.Err() == nil && i < iterations; i+=1 {
      data := GenerateRandomTextData(chunk)
      _, err := pipe.WriteEnd().Write(data)
      if err != nil {
        pipe.WriteEnd().PutErr(err)
        return
      }
    }
  }()
  return pipe.ReadEnd()
}

