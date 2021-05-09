package util

import (
  "fmt"
  "log"

  "google.golang.org/protobuf/proto"
  "google.golang.org/protobuf/encoding/prototext"
)

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
  log.Fatalf(format, v...)
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

