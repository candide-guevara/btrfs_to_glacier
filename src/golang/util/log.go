package util

import (
  "encoding/json"
  "fmt"
  "log"
  "runtime"

  "google.golang.org/protobuf/proto"
  "google.golang.org/protobuf/encoding/prototext"
)

func AsJson(val interface{}) string {
  switch s := val.(type) { case string: return s }
  str, err := json.MarshalIndent(val, "", "  ")
  if err != nil { Fatalf("cannot marshal to json string: %v", err) }
  return string(str)
}

// Like Sprintf but for all protobuf.
// Nicer than simply using '%v'
func PbPrintf(format string, pbs ...proto.Message) string {
  pb_strs := make([]interface{}, 0, len(pbs))
  for _, p := range pbs {
    str := prototext.Format(p)
    pb_strs = append(pb_strs, str)
  }
  return fmt.Sprintf(format, pb_strs...)
}

func Fatalf(format string, v ...interface{}) {
  log.Printf("[FATAL] " + format, v...)
  buf := make([]byte, 4096)
  cnt := runtime.Stack(buf, /*all=*/false)
  log.Fatalf("Stack:\n%s", buf[:cnt])
}

func Infof(format string, v ...interface{}) {
  log.Printf(format, v...)
}
func PbInfof(format string, v ...proto.Message) {
  Infof(PbPrintf(format, v...))
}

func Debugf(format string, v ...interface{}) {
  log.Printf(format, v...)
}
func PbDebugf(format string, v ...proto.Message) {
  Debugf(PbPrintf(format, v...))
}

func Warnf(format string, v ...interface{}) {
  log.Printf("[WARN] " + format, v...)
}

