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

// Package testutil defines types and functions used to test Network Layer
// functionality such as IP fragmentation. An ErrorChannel should be created
// using NewErrorChannel and packets can be written to it using WritePacket.
// Packets are stored in a channel and they can then be examined.
package testutil

import (
	"fmt"
	"math/rand"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// ErrorChannel is an endpoint for testing used to capture packets in a channel
// and to mock errors.
type ErrorChannel struct {
	*channel.Endpoint

	// Ch is a channel which will receive packets as they are written via
	// WritePacket.
	Ch chan *stack.PacketBuffer

	packetCollectorErrors []*tcpip.Error
}

// NewErrorChannel creates a new ErrorChannel endpoint.
//
// packetCollectorErrors can be used to set error values and each call to
// WritePacket will remove the first one from the slice and return it until
// the slice is empty - at that point it will return nil every time.
func NewErrorChannel(size int, mtu uint32, linkAddr tcpip.LinkAddress, packetCollectorErrors []*tcpip.Error) *ErrorChannel {
	return &ErrorChannel{
		Endpoint:              channel.New(0, mtu, linkAddr),
		Ch:                    make(chan *stack.PacketBuffer, size),
		packetCollectorErrors: packetCollectorErrors,
	}
}

// Drain removes all outbound packets from the channel and counts them.
func (e *ErrorChannel) Drain() int {
	close(e.Ch)

	c := 0
	for range e.Ch {
		c++
	}

	return c
}

// WritePacket stores outbound packets into the channel.
func (e *ErrorChannel) WritePacket(_ *stack.Route, gso *stack.GSO, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) *tcpip.Error {
	select {
	case e.Ch <- pkt:
	default:
	}

	if len(e.packetCollectorErrors) > 0 {
		nextError := e.packetCollectorErrors[0]
		e.packetCollectorErrors = e.packetCollectorErrors[1:]
		return nextError
	}

	return nil
}

// MakeRandPkt generates a randomized packet. transportHeaderLength indicates
// how many random bytes will be copied in the Transport Header.
// extraHeaderReserveLength indicates how much extra space will be reserved for
// the other headers. The payload is made from Views of the sizes listed in
// viewSizes.
func MakeRandPkt(transportHeaderLength int, extraHeaderReserveLength int, viewSizes []int, proto tcpip.NetworkProtocolNumber) *stack.PacketBuffer {
	var views buffer.VectorisedView

	for _, s := range viewSizes {
		newView := buffer.NewView(s)
		if _, err := rand.Read(newView); err != nil {
			panic(fmt.Sprintf("rand.Read: %s", err))
		}
		views.AppendView(newView)
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: transportHeaderLength + extraHeaderReserveLength,
		Data:               views,
	})
	pkt.NetworkProtocolNumber = proto
	if _, err := rand.Read(pkt.TransportHeader().Push(transportHeaderLength)); err != nil {
		panic(fmt.Sprintf("rand.Read: %s", err))
	}
	return pkt
}
