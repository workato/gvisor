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

// Package testutil defines types and functions used to test Network Layer
// functionalities such as IP fragmentation. An `ErrorChannel` should be created
// using NewErrorChannel and packets can be written to it using `WritePacket`.
// Packets are stored in a Go channel and they can then be examinated.
package testutil

import (
	"fmt"
	"math/rand"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// ErrorChannel is composed by a Link Layer endpoint but packets wrote to it are
// captured by a Go channel `Ch`. packetCollectorsErrors can be set to test that
// error conditions occur as expected.
type ErrorChannel struct {
	*channel.Endpoint
	Ch                    chan *stack.PacketBuffer
	packetCollectorErrors []*tcpip.Error
}

// NewErrorChannel creates a new ErrorChannel endpoint. Each call to WritePacket
// will return successive errors from packetCollectorErrors until the list is
// empty and then return nil each time.
func NewErrorChannel(size int, mtu uint32, linkAddr tcpip.LinkAddress, packetCollectorErrors []*tcpip.Error) *ErrorChannel {
	return &ErrorChannel{
		Endpoint:              channel.New(size, mtu, linkAddr),
		Ch:                    make(chan *stack.PacketBuffer, size),
		packetCollectorErrors: packetCollectorErrors,
	}
}

// Drain removes all outbound packets from the channel and counts them.
func (e *ErrorChannel) Drain() int {
	c := 0
	for {
		select {
		case <-e.Ch:
			c++
		default:
			return c
		}
	}
}

// WritePacket stores outbound packets into the channel.
func (e *ErrorChannel) WritePacket(r *stack.Route, gso *stack.GSO, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) *tcpip.Error {
	select {
	case e.Ch <- pkt:
	default:
	}

	nextError := (*tcpip.Error)(nil)
	if len(e.packetCollectorErrors) > 0 {
		nextError = e.packetCollectorErrors[0]
		e.packetCollectorErrors = e.packetCollectorErrors[1:]
	}
	return nextError
}

// MakeRandPkt generates a randomized packet. transHdrLength indicates how many
// random bytes will be copied in the Transport Header. extraHdrReserve
// indicates how much extra space will be reserved for the other headers. The
// payload is made from many Views of the sizes listed in viewSizes.
func MakeRandPkt(transHdrLen int, extraHdrReserve int, viewSizes []int, proto tcpip.NetworkProtocolNumber) *stack.PacketBuffer {
	var views []buffer.View
	totalLength := 0
	for _, s := range viewSizes {
		newView := buffer.NewView(s)
		rand.Read(newView)
		views = append(views, newView)
		totalLength += s
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: transHdrLen + extraHdrReserve,
		Data:               buffer.NewVectorisedView(totalLength, views),
	})
	pkt.NetworkProtocolNumber = proto
	if _, err := rand.Read(pkt.TransportHeader().Push(transHdrLen)); err != nil {
		panic(fmt.Sprintf("rand.Read: %s", err))
	}
	return pkt
}
