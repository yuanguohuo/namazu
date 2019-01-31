// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ethernet

import (
	"fmt"
	"sync"

	netfilter "github.com/AkihiroSuda/go-netfilter-queue"
	log "github.com/cihub/seelog"
	"github.com/google/gopacket/layers"
	"github.com/osrg/namazu/nmz/inspector/ethernet/tcpwatcher"
	"github.com/osrg/namazu/nmz/inspector/transceiver"
	"github.com/osrg/namazu/nmz/signal"
)

// TODO: support user-written MapPacketToEventFunc
type NFQInspector struct {
	OrchestratorURL  string
	EntityID         string
	NFQNumberStart   uint16
	NFQNumberEnd     uint16
	EnableTCPWatcher bool
	trans            transceiver.Transceiver
	tcpWatcher       *tcpwatcher.TCPWatcher
}

func (this *NFQInspector) Serve() error {
	log.Debugf("Initializing Ethernet Inspector %#v", this)
	var err error

	if this.EnableTCPWatcher {
		this.tcpWatcher = tcpwatcher.New()
	}

	this.trans, err = transceiver.NewTransceiver(this.OrchestratorURL, this.EntityID)
	if err != nil {
		return err
	}
	this.trans.Start()

	numQ := int(this.NFQNumberEnd - this.NFQNumberStart + 1)
	queues := make([]*netfilter.NFQueue, 0, numQ)

	for i := this.NFQNumberStart; i <= this.NFQNumberEnd; i++ {
		nfq, err := netfilter.NewNFQueue(i, 1024*1024, netfilter.NF_DEFAULT_PACKET_SIZE)
		if err != nil {
			fmt.Printf("error occurred when create NF queue. error:%s\n", err.Error())
			return err
		}
		queues = append(queues, nfq)
	}

	defer func() {
		for _, nfq := range queues {
			nfq.Close()
		}
	}()

	var wg sync.WaitGroup
	for _, nfq := range queues {
		nfpChan := nfq.GetPackets()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				nfp := <-nfpChan
				ip, tcp := this.decodeNFPacket(nfp)
				// note: tcpwatcher is not thread-safe
				//       so, we enable it only if numQ == 1, in which case there is no concurrency;
				if numQ == 1 && this.EnableTCPWatcher && this.tcpWatcher.IsTCPRetrans(ip, tcp) {
					nfp.SetVerdict(netfilter.NF_DROP)
					continue
				}
				go func() {
					// can we use queue so as to improve determinism?
					if err := this.onPacket(nfp, ip, tcp); err != nil {
						log.Error(err)
					}
				}()
			}
		}()
	}
	wg.Wait()

	// NOTREACHED
	return nil
}

func (this *NFQInspector) decodeNFPacket(nfp netfilter.NFPacket) (ip *layers.IPv4, tcp *layers.TCP) {
	if layer := nfp.Packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ip, _ = layer.(*layers.IPv4)
	}
	if layer := nfp.Packet.Layer(layers.LayerTypeTCP); layer != nil {
		tcp, _ = layer.(*layers.TCP)
	}
	return
}

func packetBytes(nfp netfilter.NFPacket) []byte {
	dummyEth := []byte("\xff\xff\xff\xff\xff\xff" +
		"\x00\x00\x00\x00\x00\x00" +
		"\x08\x00")
	payload := nfp.Packet.Data()
	return append(dummyEth[:], payload[:]...)
}

func (this *NFQInspector) onPacket(nfp netfilter.NFPacket,
	ip *layers.IPv4, tcp *layers.TCP) error {
	srcEntityID, dstEntityID := makeEntityIDs(nil, ip, tcp)
	bytes := packetBytes(nfp)
	event, err := signal.NewPacketEvent(this.EntityID,
		srcEntityID, dstEntityID,
		map[string]interface{}{
			"bytes": bytes,
		})
	if err != nil {
		return err
	}
	actionCh, err := this.trans.SendEvent(event)
	if err != nil {
		return err
	}
	action := <-actionCh
	switch action.(type) {
	case *signal.EventAcceptanceAction:
		nfp.SetVerdict(netfilter.NF_ACCEPT)
	case *signal.PacketFaultAction:
		nfp.SetVerdict(netfilter.NF_DROP)
	default:
		return fmt.Errorf("unknown action %s", action)
	}
	return nil
}
