// +build !race
// +build !delve

package util

import "time"

// https://stackoverflow.com/questions/44944959/how-can-i-check-if-the-race-detector-is-enabled-at-runtime
const TestTimeout  = 12 *  time.Millisecond
const SmallTimeout = 2 *   time.Millisecond
const MedTimeout   = 5 *   time.Millisecond
const LargeTimeout = 19 *  time.Millisecond
const HugeTimeout =  190 * time.Millisecond
const RaceDetectorOn = false


