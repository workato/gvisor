// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipv4

import (
	"encoding/binary"
	"errors"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Pretty much everything in this file should be private other than the
// ProcessIPOptions function. It is expected that some functions will be
// exported as we need them.
/*
      Example options layout. Adapted from RFC 791

   |                      destination address                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Opt. Code = w | Opt.  Len.= 3 | option value  | Opt. Code = x |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Opt. Len. = 4 |           option value        | Opt. Code = 1 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Opt. Code = y | Opt. Len. = 3 |  option value | Opt. Code = z |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Opt. Len = 2  | Opt. Code = 0 |  Unspecified  | Unspecified   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                              data                             |

   Options types:
      End of Option List
        +--------+
        |00000000| Type=0
        +--------+

      No Operation
        +--------+
        |00000001| Type=1
        +--------+

      Security
        +--------+--------+---//---+---//---+---//---+---//---+
        |10000010|00001011|SSS  SSS|CCC  CCC|HHH  HHH|  TCC   |
        +--------+--------+---//---+---//---+---//---+---//---+
          Type=130 Length=11

      Loose Source and Record Route
        +--------+--------+--------+---------//--------+
        |10000011| length | pointer|     route data    | Type=131
        +--------+--------+--------+---------//--------+

      Strict Source and Record Route
        +--------+--------+--------+---------//--------+
        |10001001| length | pointer|     route data    | Type=137
        +--------+--------+--------+---------//--------+

      Record Route
        +--------+--------+--------+---------//--------+
        |00000111| length | pointer|     route data    | Type=7
        +--------+--------+--------+---------//--------+

      Stream Identifier
        +--------+--------+--------+--------+
        |10001000|00000010|    Stream ID    | Type=136 Length=4
        +--------+--------+--------+--------+

      Router Alert
        +--------+--------+--------+--------+
        |10010100|00000100|  2 octet value  | Type=140 Length=4
        +--------+--------+--------+--------+

      Internet Timestamp
        +--------+--------+--------+--------+
        |01000100| length | pointer|oflw|flg| Type=68
        +--------+--------+--------+--------+
        |         internet address          |
        +--------+--------+--------+--------+
        |             timestamp             |
        +--------+--------+--------+--------+
        |                 .                 |
                          .


  Option code 0: End of options. Anything following is ignored.
  Option code 1: NOP/spacer. Can go anywhere and appear multiple times.
  Only codes 0 and 1 have no length field.
  Options may be on any byte boundary, however the complete options area ends
  on a multiple of 4 bytes as specified by the IP header length field.
*/

const (
	// ipv4EndOfOptionListType is the option type for the End Of Option List
	// option.
	ipv4EndOfOptionListType = 0

	// ipv4EOptionNopType is the No-Operation option. May appear between other
	// options and may appear multiple times
	ipv4OptionNopType = 1

	// Options we don't fully implement yet
	ipv4OptionRRType                     = 7
	ipv4OptionSecurityType               = 130
	ipv4OptionLooseSourceRecordRouteType = 131
	ipv4OptionExtendedSecurityType       = 133
	ipv4OptionCommercialSecurityType     = 134
	ipv4OptionStreamIDType               = 136
	ipv4OptionStrictSourceRouteType      = 137
	ipv4OptionRouterAlertType            = 148

	ipv4OptionStreamIDLength = 4
	ipv4OptionSecurityLength = 11

	// ipv4OptTimestamp is the option type for the Timestamp option.
	ipv4OptionTimestampType = 68

	// With 20 bytes used up of the maximum of 60, only 40 bytes may be used for
	// options.
	ipv4OptionMaxLength = header.IPv4MaximumHeaderSize - header.IPv4MinimumSize
)

// Potential errors when parsing IP options.
var (
	ErrIPv4OptZeroLength   = errors.New("zero length")
	ErrIPv4OptInvalid      = errors.New("invalid option")
	ErrIPv4OptMalformed    = errors.New("malformed option")
	ErrIPv4OptionTruncated = errors.New("option truncated")
)

// This is the set of functions to be implemented
// by all IP options.
type option interface {
	typ() uint8
	length() int
}

// OptionGeneric represents an IPv4 Option  of unknown type stored
// in a byte array. Should be an implementation of IPv4Option interface.
type optionGeneric []byte

// Type returns the type for IPv4 Timestamp Option. (68)
func (b optionGeneric) Type() uint8 {
	return uint8(b[0])
}

// Length returns the total length of the option including type and
// length fields.
func (b optionGeneric) Length() int {
	return len(b)
}

// Options is a buffer that holds all the raw IP options.
type Options []byte

// optionIterator represents an iterator pointing to a specific IP option
// at any point of time.
type optionIterator struct {
	opts Options
	// While parsing options we need to keep track of where we are as the
	// resulting ICMP packet is supposed to have a pointer to the byte within
	// the IP packet where the error was detected.
	errCursor     int
	nextErrCursor int
}

// Function iter sets up and returns an iterator of options.
//
// If check is true, iter will do an integrity check on the options by iterating
// over it and returning an error if detected.
func (b Options) iter(check bool) (optionIterator, error) {
	it := optionIterator{opts: b, nextErrCursor: header.IPv4MinimumSize}

	if check {
		for it2 := it; true; {
			if _, done, err := it2.next(); err != nil || done {
				return it, err
			}
		}
	}

	return it, nil
}

// function next returns the next IP option in the buffer/list of IP options.
// - done is true if parsing all the options is complete.
// - error is non-nil if an error condition was encountered.
func (i *optionIterator) next() (optionGeneric, bool, error) {
	if len(i.opts) == 0 {
		return nil, true, nil
	}

	htype := i.opts[0]
	i.errCursor = i.nextErrCursor

	if htype == ipv4EndOfOptionListType {
		return nil, true, nil
	}

	if htype == ipv4OptionNopType {
		i.opts = i.opts[1:]
		i.nextErrCursor = i.errCursor + 1
		return nil, false, nil
	}

	if len(i.opts) < 2 { // i.e. 1
		return nil, true, ErrIPv4OptMalformed
	}

	optLen := int(i.opts[1])

	if optLen == 0 { // why is this special?
		i.errCursor++
		return nil, true, ErrIPv4OptZeroLength
	}

	if optLen < 2 { // i.e. 1.
		i.errCursor++
		return nil, true, ErrIPv4OptMalformed
	}

	if optLen > len(i.opts) {
		i.errCursor++
		return nil, true, ErrIPv4OptionTruncated
	}

	optionBody := i.opts[:optLen]
	i.nextErrCursor = i.errCursor + optLen
	i.opts = i.opts[optLen:]

	// We will check the length of some option types that we know.
	switch htype {
	case ipv4OptionTimestampType:
		if optLen < 4 {
			i.errCursor++
			return nil, true, ErrIPv4OptMalformed
		}
	case ipv4OptionSecurityType:
		if optLen != ipv4OptionSecurityLength {
			i.errCursor++
			return nil, true, ErrIPv4OptMalformed
		}
	case ipv4OptionStreamIDType:
		if optLen != ipv4OptionStreamIDLength {
			i.errCursor++
			return nil, true, ErrIPv4OptMalformed
		}
	}
	return optionGeneric(optionBody), false, nil
}

/*
        IP Timestamp option - RFC 791
        +--------+--------+--------+--------+
        |01000100| length | pointer|oflw|flg|
        +--------+--------+--------+--------+
        |         internet address          |
        +--------+--------+--------+--------+
        |             timestamp             |
        +--------+--------+--------+--------+
        |                ...                |

  N.B. pointer is 1 based and points to next FREE entry.
  Internet address will be not appear in mode 0.
  Maximum allowed value of length is 40 (decimal).
  Maximum allowed value of pointer is length + 1 (full).
*/

// Specifically Timestamp option related constants
const (
	// ipv4OptTimestampHdrLength is the length of the timestamp option header
	ipv4OptTimestampHdrLength = 4

	// ipv4OptTimestampSize is the size of an IP timestamp.
	ipv4OptTimestampSize = 4

	// ipv4OptTimestampWithAddrSize is the size of an IP timestamp + Address.
	ipv4OptTimestampWithAddrSize = header.IPv4AddressSize + ipv4OptTimestampSize

	// ipv4OptTimestampOnlyMinSize is the minimum length of a Timestamp option
	// containing only timestamps.
	ipv4OptTimestampOnlyMinSize = ipv4OptTimestampHdrLength + ipv4OptTimestampSize

	// ipv4OptTimestampWithIPMinSize is the minimum length of a Timestamp option
	// containing both IP address and timestamp.
	ipv4OptTimestampWithIPMinSize = ipv4OptTimestampOnlyMinSize + header.IPv4AddressSize

	// ipv4OptTimestampMaxSize is limited by space for options
	ipv4OptTimestampMaxSize = ipv4OptionMaxLength

	// ipv4OptTimestampOnlyFlag is a flag indicating that only timestamp is present.
	ipv4OptTimestampOnlyFlag = 0

	// ipv4OptTimestampWithIPFlag is a flag indicating that both timestamps and
	// IP are present.
	ipv4OptTimestampWithIPFlag = 1

	// ipv4OptTimestampWithPredefinedIPFlag is a flag indicating that predefined
	// IP is present.
	ipv4OptTimestampWithPredefinedIPFlag = 3
)

const (
	// IP Timestamp option fields.
	ipv4OptTimestampStart        = 0
	ipv4OptTimestampLength       = 1
	ipv4OptTimestampPointer      = 2
	ipv4OptTimestampOFLWAndFLG   = 3
	ipv4OptTimestampData         = 4
	ipv4OptTimestampOverflowMask = 0xf0
	ipv4OptTimestampFlagsMask    = 0x0f
)

var (
	// ErrIPv4TimestampOptInvalidLength indicates a timestamp option had an
	// inconsitency to do with its length.
	ErrIPv4TimestampOptInvalidLength = errors.New("invalid length")

	// ErrIPv4TimestampOptInvalidPointer is used when the pointer in a timestamp
	// does not point within the option.
	ErrIPv4TimestampOptInvalidPointer = errors.New("invalid pointer")

	// ErrIPv4TimestampOptOverflow is used when the number of overflowed
	// timestamps exceeds 15.
	ErrIPv4TimestampOptOverflow = errors.New("timestamp overflow")

	// ErrIPv4TimestampOptInvalidFlags is used when the flags of a timestamp
	// option do not result in a valid combination.
	ErrIPv4TimestampOptInvalidFlags = errors.New("invalid flags")
)

// IPv4OptTimestampEntry represents an IPv4 Timestamp Option entry stored in a
// byte array. It may be 4 or 8 bytes long depending on the flags.
type optTimestampEntry []byte

// Timestamps are defined in RFC791 as milliseconds since midnight UTC.
// In Go we can get nSecs since then using UnixNano() (an int64)
// and get rid of parts > 1 day while converting to milliseconds.

const millisecondsPerDay = 24 * 3600 * 1000

type milliSecTime uint32

// timestampTime provides the current time in a form suitable for IPv4 Timestamps
func timestampTime() milliSecTime {
	return milliSecTime((time.Now().UnixNano() / 1000000) % (millisecondsPerDay))
}

// Functionn address returns the IP address field in the IP Timestamp Entry (if there)
// Only call on the entries that have an address.
func (b optTimestampEntry) address() tcpip.Address {
	return tcpip.Address(b[:header.IPv4AddressSize])
}

// setIPAddress sets the IP address field in the IP Timestamp Entry (if there)
// Only call on the entries that have an address.
func (b optTimestampEntry) setIPAddress(addr tcpip.Address) {
	copy(b[:header.IPv4AddressSize], addr)
}

func (b optTimestampEntry) Timestamp() uint32 {
	if len(b) == ipv4OptTimestampSize {
		return binary.BigEndian.Uint32(b[:ipv4OptTimestampSize])
	}
	return binary.BigEndian.Uint32(b[header.IPv4AddressSize:])
}

func (b optTimestampEntry) setTimestamp() {
	if len(b) == ipv4OptTimestampSize {
		binary.BigEndian.PutUint32(b[0:], uint32(timestampTime()))
	} else { // must be 8 bytes
		binary.BigEndian.PutUint32(b[header.IPv4AddressSize:], uint32(timestampTime()))
	}
}

// optTimestamp represents an IPv4 Timestamp Option stored
// in a byte array. It is an instance of the option interface.
type optTimestamp []byte

// Type returns the type for IPv4 Timestamp Option. (68)
func (b optTimestamp) tsType() uint8 {
	return ipv4OptionTimestampType
}

// Length returns the total length of the option including type and
// length fields given the complete option in the array b.
func (b optTimestamp) length() int {
	return len(b)
}

// Function pointer returns the pointer field in the IP Timestamp option.
func (b optTimestamp) pointer() uint8 {
	return b[ipv4OptTimestampPointer]
}

// incPointer increments the pointer field by the given size.
func (b optTimestamp) incPointer(size uint8) uint8 {
	b[ipv4OptTimestampPointer] += size
	return b[ipv4OptTimestampPointer]
}

// Flags returns the flags field in the IP Timestamp option.
func (b optTimestamp) Flags() uint8 {
	return b[ipv4OptTimestampOFLWAndFLG] & ipv4OptTimestampFlagsMask
}

// Overflow returns the overflow field in the IP Timestamp option.
func (b optTimestamp) Overflow() uint8 {
	return (b[ipv4OptTimestampOFLWAndFLG] & ipv4OptTimestampOverflowMask) >> 4
}

// incOverflow increments the overflow field in the IP Timestamp option.
// If it returns 0 it overflowed.
func (b optTimestamp) incOverflow() uint8 {
	b[ipv4OptTimestampOFLWAndFLG] += byte(1 << 4)
	return (b[ipv4OptTimestampOFLWAndFLG] & ipv4OptTimestampOverflowMask) >> 4
}

// handleTimestamp will sanity check an IP Timestamp option.
func handleTimestamp(tsOpt optTimestamp, localAddress tcpip.Address) (int, error) {
	var entrySize int
	flags := tsOpt.Flags()
	optlen := tsOpt.length()

	switch flags {
	case ipv4OptTimestampOnlyFlag:
		entrySize = ipv4OptTimestampSize
	case ipv4OptTimestampWithIPFlag, ipv4OptTimestampWithPredefinedIPFlag:
		entrySize = ipv4OptTimestampWithAddrSize
	default:
		return 3, ErrIPv4TimestampOptInvalidFlags
	}

	if optlen > ipv4OptTimestampMaxSize {
		return 1, ErrIPv4TimestampOptInvalidLength
	}
	// Must have room for at least one entry.
	optlen -= ipv4OptTimestampHdrLength
	if optlen < entrySize {
		return 1, ErrIPv4TimestampOptInvalidLength
	}
	// load 'pointer' to be a 0 based offset from the base of the timestamp
	// data section. In packet it is a 1 based offset from the start of the
	// timestamp header. e.g. for a 1 stamp sized data area:
	// 1 2 3 4 | 5 6 7 8 | 9    <--- in packet
	// _ _ _ _ | 0 1 2 3 | 4    <--- 'pointer'
	//
	start := int(tsOpt.pointer())
	pointer := int(start - (ipv4OptTimestampHdrLength + 1))
	if pointer == optlen {
		// The data area is full...
		if tsOpt.incOverflow() == 0 {
			// and so is the overflow count.
			// RFC 791 says we should discard the packet.
			return 3, ErrIPv4TimestampOptOverflow
		}
		return 0, nil
	}
	if pointer < 0 || (pointer > optlen-entrySize) {
		return 2, ErrIPv4TimestampOptInvalidPointer
	}
	//  this one is not in the RFC but...
	if pointer%entrySize != 0 {
		return 2, ErrIPv4TimestampOptInvalidPointer
	}

	target := optTimestampEntry(tsOpt[start-1 : start+entrySize-1])
	switch flags {
	case ipv4OptTimestampOnlyFlag:
		target.setTimestamp()
		tsOpt.incPointer(uint8(entrySize))
	case ipv4OptTimestampWithIPFlag:
		target.setIPAddress(localAddress)
		target.setTimestamp()
		tsOpt.incPointer(uint8(entrySize))
	case ipv4OptTimestampWithPredefinedIPFlag:
		if target.address() == localAddress {
			target.setTimestamp()
			tsOpt.incPointer(uint8(entrySize))
		}
	}
	return 0, nil
}

// ProcessIPOptions will parse all the available IP options from an IPv4 packet.
// This is called upon reception before forwarding (or echoing)
// In order to correctly process some options we need some information about
// the interface on which the packet will be sent next, specifically whether it
// has a given address or what it's main address is. This information is
// accessed via the supplied route, which is expected to reflect the next hop
// or in the case of ICMP echo requests at their desination, the return path.
// This code assumes that the options buffer is mutable and that changes made
// in that buffer will be reflected in the options of the outgoing packet.
//
// Returns
// - an error (or nil)
// - information as to where the error was encountered.
//
func ProcessIPOptions(r *stack.Route, opts Options) (int, error) {
	optIter, err := opts.iter(false)
	if err != nil {
		return 0, err
	}

	var scoreBoard [256]bool
	var optType int

	for {
		option, done, err := optIter.next()
		if done || err != nil {
			return optIter.errCursor, err
		}
		if option == nil { // NOP/spacer option
			continue
		}

		optType = int(option.Type())
		// check for repeating options (multiple NOPs are OK)
		if scoreBoard[optType] {
			return optIter.errCursor, ErrIPv4OptInvalid
		}
		scoreBoard[optType] = true
		switch optType {
		case ipv4OptionTimestampType:
			r.Stats().IP.OptionTSReceived.Increment()
			topt := optTimestamp(option)
			offset, ret := handleTimestamp(topt, r.LocalAddress)
			if ret != nil {
				return optIter.errCursor + offset, ret
			}
			// Most of the types below are for router and we can ignore them until
			// we start adding router support.
		case ipv4OptionRRType:
			r.Stats().IP.OptionRRReceived.Increment()
		case ipv4OptionSecurityType:
			r.Stats().IP.OptionSecurityReceived.Increment()
		case ipv4OptionLooseSourceRecordRouteType:
			r.Stats().IP.OptionLSRReceived.Increment()
		case ipv4OptionExtendedSecurityType:
			r.Stats().IP.OptionExtSecReceived.Increment()
		case ipv4OptionCommercialSecurityType:
			r.Stats().IP.OptionComSecReceived.Increment()
		case ipv4OptionStreamIDType:
			r.Stats().IP.OptionStreamIDReceived.Increment()
		case ipv4OptionStrictSourceRouteType:
			r.Stats().IP.OptionSSRReceived.Increment()
		case ipv4OptionRouterAlertType:
			r.Stats().IP.OptionRouterAlertReceived.Increment()
		default:
			r.Stats().IP.OptionUnknownReceived.Increment()
			// This is a completely unknown type to us.
			return optIter.errCursor, ErrIPv4OptInvalid
		}
	}
}
