// Copyright 2018 The gVisor Authors.
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

// Package fragmentation contains the implementation of IP fragmentation.
// It is based on RFC 791 and RFC 815 and RFC 8200.
package fragmentation

import (
	"errors"
	"fmt"
	"log"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// DefaultReassembleTimeout is based on the linux stack: net.ipv4.ipfrag_time.
	DefaultReassembleTimeout = 30 * time.Second

	// HighFragThreshold is the threshold at which we start trimming old
	// fragmented packets. Linux uses a default value of 4 MB. See
	// net.ipv4.ipfrag_high_thresh for more information.
	HighFragThreshold = 4 << 20 // 4MB

	// LowFragThreshold is the threshold we reach to when we start dropping
	// older fragmented packets. It's important that we keep enough room for newer
	// packets to be re-assembled. Hence, this needs to be lower than
	// HighFragThreshold enough. Linux uses a default value of 3 MB. See
	// net.ipv4.ipfrag_low_thresh for more information.
	LowFragThreshold = 3 << 20 // 3MB

	// minBlockSize is the minimum block size for fragments.
	minBlockSize = 1
)

var (
	// ErrInvalidArgs indicates to the caller that that an invalid argument was
	// provided.
	ErrInvalidArgs = errors.New("invalid args")
)

// FragmentID is the identifier for a fragment.
type FragmentID struct {
	// Source is the source address of the fragment.
	Source tcpip.Address

	// Destination is the destination address of the fragment.
	Destination tcpip.Address

	// ID is the identification value of the fragment.
	//
	// This is a uint32 because IPv6 uses a 32-bit identification value.
	ID uint32

	// The protocol for the packet.
	Protocol uint8
}

// Fragmentation is the main structure that other modules
// of the stack should use to implement IP Fragmentation.
type Fragmentation struct {
	mu           sync.Mutex
	highLimit    int
	lowLimit     int
	reassemblers map[FragmentID]*reassembler
	rList        reassemblerList
	size         int
	timeout      time.Duration
	blockSize    uint16
}

// NewFragmentation creates a new Fragmentation.
//
// blockSize specifies the fragment block size, in bytes.
//
// highMemoryLimit specifies the limit on the memory consumed
// by the fragments stored by Fragmentation (overhead of internal data-structures
// is not accounted). Fragments are dropped when the limit is reached.
//
// lowMemoryLimit specifies the limit on which we will reach by dropping
// fragments after reaching highMemoryLimit.
//
// reassemblingTimeout specifies the maximum time allowed to reassemble a packet.
// Fragments are lazily evicted only when a new a packet with an
// already existing fragmentation-id arrives after the timeout.
func NewFragmentation(blockSize uint16, highMemoryLimit, lowMemoryLimit int, reassemblingTimeout time.Duration) *Fragmentation {
	if lowMemoryLimit >= highMemoryLimit {
		lowMemoryLimit = highMemoryLimit
	}

	if lowMemoryLimit < 0 {
		lowMemoryLimit = 0
	}

	if blockSize < minBlockSize {
		blockSize = minBlockSize
	}

	return &Fragmentation{
		reassemblers: make(map[FragmentID]*reassembler),
		highLimit:    highMemoryLimit,
		lowLimit:     lowMemoryLimit,
		timeout:      reassemblingTimeout,
		blockSize:    blockSize,
	}
}

// Process processes an incoming fragment belonging to an ID and returns a
// complete packet and its protocol number when all the packets belonging to
// that ID have been received.
//
// [first, last] is the range of the fragment bytes.
//
// first must be a multiple of the block size f is configured with. The size
// of the fragment data must be a multiple of the block size, unless there are
// no fragments following this fragment (more set to false).
//
// proto is the protocol number marked in the fragment being processed. It has
// to be given here outside of the FragmentID struct because IPv6 should not use
// the protocol to identify a fragment.
func (f *Fragmentation) Process(
	id FragmentID, first, last uint16, more bool, proto uint8, vv buffer.VectorisedView) (
	buffer.VectorisedView, uint8, bool, error) {
	if first > last {
		return buffer.VectorisedView{}, 0, false, fmt.Errorf("first=%d is greater than last=%d: %w", first, last, ErrInvalidArgs)
	}

	if first%f.blockSize != 0 {
		return buffer.VectorisedView{}, 0, false, fmt.Errorf("first=%d is not a multiple of block size=%d: %w", first, f.blockSize, ErrInvalidArgs)
	}

	fragmentSize := last - first + 1
	if more && fragmentSize%f.blockSize != 0 {
		return buffer.VectorisedView{}, 0, false, fmt.Errorf("fragment size=%d bytes is not a multiple of block size=%d on non-final fragment: %w", fragmentSize, f.blockSize, ErrInvalidArgs)
	}

	if l := vv.Size(); l < int(fragmentSize) {
		return buffer.VectorisedView{}, 0, false, fmt.Errorf("got fragment size=%d bytes less than the expected fragment size=%d bytes (first=%d last=%d): %w", l, fragmentSize, first, last, ErrInvalidArgs)
	}
	vv.CapLength(int(fragmentSize))

	f.mu.Lock()
	r, ok := f.reassemblers[id]
	if ok && r.tooOld(f.timeout) {
		// This is very likely to be an id-collision or someone performing a slow-rate attack.
		f.release(r)
		ok = false
	}
	if !ok {
		r = newReassembler(id)
		f.reassemblers[id] = r
		f.rList.PushFront(r)
	}
	f.mu.Unlock()

	res, firstFragmentProto, done, consumed, err := r.process(first, last, more, proto, vv)
	if err != nil {
		// We probably got an invalid sequence of fragments. Just
		// discard the reassembler and move on.
		f.mu.Lock()
		f.release(r)
		f.mu.Unlock()
		return buffer.VectorisedView{}, 0, false, fmt.Errorf("fragmentation processing error: %w", err)
	}
	f.mu.Lock()
	f.size += consumed
	if done {
		f.release(r)
	}
	// Evict reassemblers if we are consuming more memory than highLimit until
	// we reach lowLimit.
	if f.size > f.highLimit {
		for f.size > f.lowLimit {
			tail := f.rList.Back()
			if tail == nil {
				break
			}
			f.release(tail)
		}
	}
	f.mu.Unlock()
	return res, firstFragmentProto, done, nil
}

func (f *Fragmentation) release(r *reassembler) {
	// Before releasing a fragment we need to check if r is already marked as done.
	// Otherwise, we would delete it twice.
	if r.checkDoneOrMark() {
		return
	}

	delete(f.reassemblers, r.id)
	f.rList.Remove(r)
	f.size -= r.size
	if f.size < 0 {
		log.Printf("memory counter < 0 (%d), this is an accounting bug that requires investigation", f.size)
		f.size = 0
	}
}

type packetFragmenter struct {
	netHdr            buffer.View
	transHdr          buffer.View
	data              buffer.VectorisedView
	baseReserve       int
	innerMTU          int
	fragmentCount     uint32
	currentFragment   uint32
	offset            uint16
	transHdrFitsFirst bool
}

// newPacketFragmenter prepares the struct needed for packet fragmentation.
//
// pkt is the packet to be fragmented.
//
// mtu includes the network header(s) currently in the packet.
//
// extraHdrLen can be set to reserve extra space for the headers and this will
// also lower the inner MTU.
func newPacketFragmenter(pkt *stack.PacketBuffer, mtu uint32, extraHdrLen int) packetFragmenter {
	// Each fragment will *at least* reserve the bytes available to the Link Layer
	// (which are currently the only unused header bytes) and the bytes dedicated
	// to the Network header.
	baseReserve := pkt.AvailableHeaderBytes() + pkt.NetworkHeader().View().Size() + extraHdrLen
	innerMTU := int(mtu) - pkt.NetworkHeader().View().Size() - extraHdrLen

	// Round the MTU down to align to 8 bytes.
	innerMTU &^= 7

	// As per RFC 8200 Section 4.5, some IPv6 extension headers should not be
	// repeated in each fragment. However we do not currently support any header
	// of that kind yet, so the following computation is valid for both IPv4 and
	// IPv6.
	fragmentablePartLength := pkt.TransportHeader().View().Size() + pkt.Data.Size()

	return packetFragmenter{
		netHdr:            pkt.NetworkHeader().View(),
		transHdr:          pkt.TransportHeader().View(),
		data:              pkt.Data,
		baseReserve:       baseReserve,
		innerMTU:          innerMTU,
		fragmentCount:     uint32((fragmentablePartLength + innerMTU - 1) / innerMTU),
		transHdrFitsFirst: pkt.TransportHeader().View().Size() <= innerMTU,
	}
}

// IPv4PacketFragmenter is the structure that should be used to perform IPv4
// fragmentation on outbound packets.
type IPv4PacketFragmenter struct {
	packetFragmenter
}

// NewIPv4PacketFragmenter initializes an IPv4PacketFragmenter structure.
func NewIPv4PacketFragmenter(pkt *stack.PacketBuffer, mtu uint32) IPv4PacketFragmenter {
	return IPv4PacketFragmenter{newPacketFragmenter(pkt, mtu, 0)}
}

// IPv6PacketFragmenter is the structure that should be used to perform IPv6
// fragmentation on outbound packets.
type IPv6PacketFragmenter struct {
	packetFragmenter

	// transProto is needed for IPv6 fragmentation when there are extension
	// headers to avoid parsing them.
	transProto tcpip.TransportProtocolNumber

	// Fragment identification number.
	id uint32
}

// NewIPv6PacketFragmenter initializes an IPv6PacketFragmenter structure.
func NewIPv6PacketFragmenter(pkt *stack.PacketBuffer, mtu uint32, transProto tcpip.TransportProtocolNumber, id uint32) IPv6PacketFragmenter {
	return IPv6PacketFragmenter{
		packetFragmenter: newPacketFragmenter(pkt, mtu, header.IPv6FragmentHeaderSize),
		transProto:       transProto,
		id:               id,
	}
}

// buildNextFragment initialize a packet with the payload of the next fragment,
// and returns it along with the number of bytes copied and a boolean indicating
// if there is more data left or not.
// Note that the returned packet will not have its network header/link header
// populated, but the space for them will be reserved.
func (pf *packetFragmenter) buildNextFragment(proto tcpip.NetworkProtocolNumber) (*stack.PacketBuffer, uint16, bool) {
	if pf.currentFragment >= pf.fragmentCount {
		return nil, 0, false
	}

	reserve := pf.baseReserve

	// Where possible, the first fragment that is sent has the same
	// number of bytes reserved for header as the input packet. The link-layer
	// endpoint may depend on this for looking at, eg, L4 headers.
	if pf.currentFragment == 0 && pf.transHdrFitsFirst {
		reserve += pf.transHdr.Size()
	}

	fragPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: reserve,
	})
	fragPkt.NetworkProtocolNumber = proto

	// Copy data for the fragment.
	avail := pf.innerMTU

	if n := len(pf.transHdr); n > 0 {
		if n > avail {
			n = avail
		}
		if pf.currentFragment == 0 && pf.transHdrFitsFirst {
			copy(fragPkt.TransportHeader().Push(n), pf.transHdr)
		} else {
			fragPkt.Data.AppendView(pf.transHdr[:n:n])
		}
		pf.transHdr = pf.transHdr[n:]
		avail -= n
	}

	if avail > 0 {
		n := pf.data.Size()
		if n > avail {
			n = avail
		}
		pf.data.ReadToVV(&fragPkt.Data, n)
		avail -= n
	}

	copied := uint16(pf.innerMTU - avail)

	pf.currentFragment++
	pf.offset += copied

	return fragPkt, copied, pf.currentFragment != pf.fragmentCount
}

// BuildNextFragment creates a packet with the headers and data of the next
// fragment to be sent. Once there are no more fragments to be made, it will
// return nil.
func (pf *IPv4PacketFragmenter) BuildNextFragment() *stack.PacketBuffer {
	fragPkt, copied, more := pf.buildNextFragment(header.IPv4ProtocolNumber)

	if fragPkt != nil {
		originalIPHdr := header.IPv4(pf.netHdr)
		nextFragIPHdr := header.IPv4(fragPkt.NetworkHeader().Push(len(originalIPHdr)))
		copy(nextFragIPHdr, originalIPHdr)

		flags := originalIPHdr.Flags()
		if more {
			flags |= header.IPv4FlagMoreFragments
		}
		nextFragIPHdr.SetFlagsFragmentOffset(flags, pf.offset-copied)
		nextFragIPHdr.SetTotalLength(uint16(nextFragIPHdr.HeaderLength()) + copied)
		nextFragIPHdr.SetChecksum(0)
		nextFragIPHdr.SetChecksum(^nextFragIPHdr.CalculateChecksum())
	}

	return fragPkt
}

// BuildNextFragment creates a packet with the headers and data of the next
// fragment to be sent. Once there are no more fragments to be made, it will
// return nil.
func (pf *IPv6PacketFragmenter) BuildNextFragment() *stack.PacketBuffer {
	fragPkt, copied, more := pf.buildNextFragment(header.IPv6ProtocolNumber)

	if fragPkt != nil {
		ipHeadersLen := pf.netHdr.Size() + header.IPv6FragmentHeaderSize
		originalIPHdr := header.IPv6(pf.netHdr)
		nextFragIPHdr := header.IPv6(fragPkt.NetworkHeader().Push(ipHeadersLen))

		// Copy the IPv6 header and any extension headers already populated.
		copy(nextFragIPHdr, originalIPHdr)
		nextFragIPHdr.SetNextHeader(header.IPv6FragmentHeader)
		nextFragIPHdr.SetPayloadLength(uint16(copied) + (uint16(ipHeadersLen - header.IPv6MinimumSize)))

		// Populate the newly added Fragment header.
		fragHdr := header.IPv6Fragment(nextFragIPHdr[pf.netHdr.Size():])
		fragHdr.Encode(&header.IPv6FragmentFields{
			M:              more,
			FragmentOffset: uint16((pf.offset - copied) / 8),
			Identification: pf.id,
			NextHeader:     uint8(pf.transProto),
		})
	}

	return fragPkt
}
