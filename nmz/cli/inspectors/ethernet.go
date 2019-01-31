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

// +build !static

package inspectors

import (
	"flag"
	"strconv"
	"strings"

	log "github.com/cihub/seelog"
	"github.com/mitchellh/cli"

	inspector "github.com/osrg/namazu/nmz/inspector/ethernet"
)

type etherFlags struct {
	commonFlags
	HookSwitchZMQAddr string
	NFQNumber         int
	NFQBalance        string
}

var (
	etherFlagset = flag.NewFlagSet("ethernet", flag.ExitOnError)
	_etherFlags  = etherFlags{}
)

func init() {
	initCommon(etherFlagset, &_etherFlags.commonFlags, "_namazu_ethernet_inspector")
	etherFlagset.StringVar(&_etherFlags.HookSwitchZMQAddr, "hookswitch",
		"ipc:///tmp/namazu-hookswitch-zmq", "HookSwitch ZeroMQ addr")
	etherFlagset.IntVar(&_etherFlags.NFQNumber, "nfq-number",
		-1, "netfilter_queue number")
	etherFlagset.StringVar(&_etherFlags.NFQBalance, "nfq-balance",
		"", "netfilter_queue number range, in format start:end (both inclusive)")
}

type etherCmd struct {
}

func EtherCommandFactory() (cli.Command, error) {
	return etherCmd{}, nil
}

func (cmd etherCmd) Help() string {
	return "Please run `nmz --help inspectors` instead"
}

func (cmd etherCmd) Synopsis() string {
	return "Start Ethernet inspector"
}

func (cmd etherCmd) Run(args []string) int {
	if err := etherFlagset.Parse(args); err != nil {
		log.Critical(err)
		return 1
	}

	useHookSwitch := _etherFlags.NFQNumber < 0 && _etherFlags.NFQBalance == ""

	if useHookSwitch && _etherFlags.HookSwitchZMQAddr == "" {
		log.Critical("hookswitch is invalid")
		return 1
	}

	var start int = -1
	var end int = -1

	if !useHookSwitch {
		if _etherFlags.NFQNumber >= 0 { // use NFQ Number
			if _etherFlags.NFQNumber > 0xFFFF {
				log.Critical("nfq-number is invalid")
				return 1
			}
			start = _etherFlags.NFQNumber
			end = _etherFlags.NFQNumber
		} else { // use NFQ balance
			pair := strings.Split(_etherFlags.NFQBalance, ":")

			if len(pair) != 2 {
				log.Criticalf("nfq-balance %s is invalid, it must be in 'start:end' format", _etherFlags.NFQBalance)
				return 1
			}

			var err error
			start, err = strconv.Atoi(pair[0])
			if err != nil {
				log.Criticalf("nfq-balance %s:%s is invalid, cannot parse %s to int. error:%s", pair[0], pair[1], pair[0], err.Error())
				return 1
			}
			end, err = strconv.Atoi(pair[1])
			if err != nil {
				log.Criticalf("nfq-balance %s:%s is invalid, cannot parse %s to int. error:%s", pair[0], pair[1], pair[1], err.Error())
				return 1
			}

			if start < 0 || start > 0xFFFF || end < 0 || end > 0xFFFF {
				log.Criticalf("nfq-balance %s:%s is invalid, both of them should be in [0,65535]", pair[0], pair[1])
				return 1
			}

			if start > end {
				log.Criticalf("nfq-balance %s:%s is invalid, the former should be less than or equal to the latter", pair[0], pair[1])
				return 1
			}
		}
	}

	autopilot, err := conditionalStartAutopilotOrchestrator(_etherFlags.commonFlags)
	if err != nil {
		log.Critical(err)
		return 1
	}
	log.Infof("Autopilot-mode: %t", autopilot)

	var etherInspector inspector.EthernetInspector
	if useHookSwitch {
		log.Infof("Using hookswitch %s", _etherFlags.HookSwitchZMQAddr)
		etherInspector = &inspector.HookSwitchInspector{
			OrchestratorURL:   _etherFlags.OrchestratorURL,
			EntityID:          _etherFlags.EntityID,
			HookSwitchZMQAddr: _etherFlags.HookSwitchZMQAddr,
			EnableTCPWatcher:  true,
		}
	} else {
		log.Infof("Using NFQ %d", _etherFlags.NFQNumber)
		etherInspector = &inspector.NFQInspector{
			OrchestratorURL:  _etherFlags.OrchestratorURL,
			EntityID:         _etherFlags.EntityID,
			NFQNumberStart:   uint16(start),
			NFQNumberEnd:     uint16(end),
			EnableTCPWatcher: true,
		}
	}

	if err := etherInspector.Serve(); err != nil {
		panic(log.Critical(err))
	}

	// NOTREACHED
	return 0
}
