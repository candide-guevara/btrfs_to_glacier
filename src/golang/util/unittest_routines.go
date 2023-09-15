package util

import (
  "context"
  "encoding/base64"
  "encoding/json"
  "fmt"
  "math/rand"
  "strings"
  "testing"
  "time"

  "btrfs_to_glacier/types"
)

func AsJson(val interface{}) string {
  switch s := val.(type) { case string: return s }
  str, err := json.MarshalIndent(val, "", "  ")
  if err != nil { Fatalf("cannot marshal to json string: %v", err) }
  return string(str)
}

func asJsonStrings(val interface{}, expected interface{}) (string, string) {
  return AsJson(val), AsJson(expected)
}

func fmtAssertMsg(err_msg string, got string, expected string) string {
  const max_len = 1024
  got_limited := got
  expect_limited := expected
  if len(got_limited) > max_len { got_limited = got[:max_len] }
  if len(expect_limited) > max_len { expect_limited = expected[:max_len] }
  return fmt.Sprintf("%s:\ngot: %s\n !=\nexp: %s\n",
                     err_msg, got_limited, expect_limited)
}

func DiffLines(val interface{}, expected interface{}) string {
  val_str, expected_str := asJsonStrings(val, expected)
  expected_lines := strings.Split(expected_str, "\n")
  for i,l := range strings.Split(val_str, "\n") {
    if i >= len(expected_lines) { return fmt.Sprintf("value is to long, line:%d", i) }
    if strings.Compare(l, expected_lines[i]) != 0 {
      return fmt.Sprintf("line:%d: '%s' != '%s'", i, l, expected_lines[i])
    }
  }
  return ""
}

func EqualsOrDie(err_msg string, val interface{}, expected interface{}) {
  val_str, expected_str := asJsonStrings(val, expected)
  if strings.Compare(val_str, expected_str) != 0 {
    Fatalf(fmtAssertMsg(err_msg, val_str, expected_str))
  }
}

func EqualsOrDieTest(t *testing.T, err_msg string, val interface{}, expected interface{}) {
  val_str, expected_str := asJsonStrings(val, expected)
  comp_res := strings.Compare(val_str, expected_str)
  if comp_res != 0 {
    t.Fatal(fmtAssertMsg(err_msg, val_str, expected_str))
  }
}

// Returns 0 if equal
func EqualsOrFailTest(t *testing.T, err_msg string, val interface{}, expected interface{}) int {
  val_str, expected_str := asJsonStrings(val, expected)
  comp_res := strings.Compare(val_str, expected_str)
  if comp_res != 0 {
    t.Error(fmtAssertMsg(err_msg, val_str, expected_str))
    return comp_res
  }
  return 0
}

func GenerateRandomTextData(size int) []byte {
  buffer := make([]byte, size)
  buffer_txt := make([]byte, base64.StdEncoding.EncodedLen(size))
  _, err := rand.Read(buffer)
  if err != nil { Fatalf("rand failed: %v", err) }
  base64.StdEncoding.Encode(buffer_txt, buffer)
  return buffer_txt[:size]
}

func GenerateRandomTextDataFrom(gen *rand.Rand, size int) []byte {
  buffer := make([]byte, size)
  buffer_txt := make([]byte, base64.StdEncoding.EncodedLen(size))
  _, err := gen.Read(buffer)
  if err != nil { Fatalf("rand failed: %v", err) }
  base64.StdEncoding.Encode(buffer_txt, buffer)
  return buffer_txt[:size]
}

func ProduceRandomTextIntoPipe(ctx context.Context, chunk int, iterations int) types.ReadEndIf {
  pipe := NewInMemPipe(ctx)

  go func() {
    defer pipe.WriteEnd().Close()
    for i:=0; ctx.Err() == nil && (i < iterations || iterations < 1); i+=1 {
      data := GenerateRandomTextData(chunk)
      _, err := pipe.WriteEnd().Write(data)
      if err != nil { return }
    }
  }()
  return pipe.ReadEnd()
}

func WaitDurationForNoError(t *testing.T, duration time.Duration, done <-chan error) {
  if done == nil { t.Error("channel is nil"); return }
  select {
    case err,ok := <-done:
      if !ok { Infof("channel closed") }
      if err != nil { t.Errorf("Error in channel: %v", err) }
    case <-time.After(duration):
      t.Errorf("WaitForNoError timeout."); return
  }
}

func WaitForClosure(t *testing.T, ctx context.Context, done <-chan error) error {
  if done == nil { t.Error("channel is nil"); return nil }
  if ctx.Err() != nil { t.Errorf("context expired before select"); return nil }
  for { select {
    case err,ok := <-done:
      if !ok { Infof("channel closed") }
      return err
    case <-ctx.Done(): t.Errorf("WaitForClosure timeout."); return nil
  }}
  return nil
}

func WaitForClosureOrDie(ctx context.Context, done <-chan error) error {
  if done == nil { Fatalf("channel is nil") }
  if ctx.Err() != nil { Fatalf("context expired before select") }
  for { select {
    case err,ok := <-done:
      if !ok { Infof("channel closed") }
      return err
    case <-ctx.Done(): Fatalf("WaitForClosure timeout.")
  }}
  return nil
}

func WaitDurationForClosure(t *testing.T, duration time.Duration, done <-chan error) error {
  if done == nil { t.Error("channel is nil"); return nil }
  for { select {
    case err,ok := <-done:
      if !ok { Infof("channel closed") }
      return err
    case <-time.After(duration):
      t.Errorf("WaitForClosure timeout."); return nil
  }}
  return nil
}

func WaitForNoError(t *testing.T, ctx context.Context, done <-chan error) {
  err := WaitForClosure(t, ctx, done)
  if err != nil { t.Errorf("Error in channel: %v", err) }
}

func WaitForNoErrorOrDie(ctx context.Context, done <-chan error) {
  err := WaitForClosureOrDie(ctx, done)
  if err != nil { Fatalf("Error in channel: %v", err) }
}

