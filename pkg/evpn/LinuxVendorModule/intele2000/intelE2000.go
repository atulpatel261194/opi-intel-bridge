// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022-2023 Intel Corporation, or its subsidiaries.
// Copyright (C) 2023 Nordix Foundation.

// Package intele2000 handles intel e2000 vendor specific tasks
package intele2000

import (
	"context"
	"fmt"

	"log"
	"math"
	"net"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/opiproject/opi-evpn-bridge/pkg/config"
	"github.com/opiproject/opi-evpn-bridge/pkg/infradb"
	"github.com/opiproject/opi-evpn-bridge/pkg/infradb/common"
	"github.com/opiproject/opi-evpn-bridge/pkg/infradb/subscriberframework/eventbus"
	"github.com/opiproject/opi-evpn-bridge/pkg/utils"
	"github.com/vishvananda/netlink"
)

// portMux variable of type string
var portMux string

// vrfMux variable of type string
var vrfMux string

// ModulelvmHandler empty interface
type ModulelvmHandler struct{}

// lvmComp empty interface
const lvmComp string = "lvm"

// run runs the command
func run(cmd []string, flag bool) (string, int) {
	var out []byte
	var err error
	out, err = exec.Command(cmd[0], cmd[1:]...).CombinedOutput() //nolint:gosec
	if err != nil {
		if flag {
			panic(fmt.Sprintf("LVM: Command %s': exit code %s;", out, err.Error()))
		}
		log.Printf("LVM: Command %s': exit code %s;\n", out, err)
		return "Error", -1
	}
	output := string(out)
	return output, 0
}

// HandleEvent handles the events
func (h *ModulelvmHandler) HandleEvent(eventType string, objectData *eventbus.ObjectData) {
	switch eventType {
	case "vrf":
		log.Printf("LVM recevied %s %s\n", eventType, objectData.Name)
		handlevrf(objectData)
	case "bridge-port":
		log.Printf("LVM recevied %s %s\n", eventType, objectData.Name)
		handlebp(objectData)
	case "tun-rep":
		log.Printf("LVM recevied %s %s\n", eventType, objectData.Name)
		handleTunRep(objectData)
	default:
		log.Printf("error: Unknown event type %s\n", eventType)
	}
}

func handleTunRep(objectData *eventbus.ObjectData) {
	var comp common.Component
	tr, err := infradb.GetTunRep(objectData.Name)
	if err != nil {
		log.Printf("LVM: GetTunRep error: %s %s\n", err, objectData.Name)
		comp.Name = lvmComp
		comp.CompStatus = common.ComponentStatusError
		if comp.Timer == 0 {
			comp.Timer = 2 * time.Second
		} else {
			comp.Timer *= 2
		}
		err := infradb.UpdateTunRepStatus(objectData.Name, objectData.ResourceVersion, objectData.NotificationID, nil, comp)
		if err != nil {
			log.Printf("error in updating tr status: %s\n", err)
		}
		return
	}
	if objectData.ResourceVersion != tr.ResourceVersion {
		log.Printf("LVM: Mismatch in resoruce version %+v\n and tr resource version %+v\n", objectData.ResourceVersion, tr.ResourceVersion)
		comp.Name = lvmComp
		comp.CompStatus = common.ComponentStatusError
		if comp.Timer == 0 {
			comp.Timer = 2 * time.Second
		} else {
			comp.Timer *= 2
		}
		err := infradb.UpdateTunRepStatus(objectData.Name, objectData.ResourceVersion, objectData.NotificationID, nil, comp)
		if err != nil {
			log.Printf("error in updating tr status: %s\n", err)
		}
		return
	}
	if len(tr.Status.Components) != 0 {
		for i := 0; i < len(tr.Status.Components); i++ {
			if tr.Status.Components[i].Name == lvmComp {
				comp = tr.Status.Components[i]
			}
		}
	}
	if tr.Status.TunRepOperStatus != infradb.TunRepOperStatusToBeDeleted {
		var status bool
		comp.Name = lvmComp
		if len(tr.OldVersions) > 0 {
			status = UpdateTunRep(tr)
		} else {
			status = setUpTunRep(tr)
		}
		if status {
			comp.Details = ""
			comp.CompStatus = common.ComponentStatusSuccess
			comp.Timer = 0
		} else {
			if comp.Timer == 0 {
				comp.Timer = 2 * time.Second
			} else {
				comp.Timer *= 2
			}
			comp.CompStatus = common.ComponentStatusError
		}
		log.Printf("LVM: %+v \n", comp)
		err := infradb.UpdateTunRepStatus(objectData.Name, objectData.ResourceVersion, objectData.NotificationID, nil, comp)
		if err != nil {
			log.Printf("error in updating tr status: %s\n", err)
		}
	} else {
		status := tearDownTunRep(tr)
		comp.Name = lvmComp
		if status {
			comp.CompStatus = common.ComponentStatusSuccess
			comp.Timer = 0
		} else {
			comp.CompStatus = common.ComponentStatusError
			if comp.Timer == 0 {
				comp.Timer = 2 * time.Second
			} else {
				comp.Timer *= 2
			}
		}
		log.Printf("LVM: %+v\n", comp)
		err := infradb.UpdateTunRepStatus(objectData.Name, objectData.ResourceVersion, objectData.NotificationID, nil, comp)
		if err != nil {
			log.Printf("error in updating tr status: %s\n", err)
		}
	}
}

// handlebp  handles the bridge port functionality
//
//gocognit:ignore
func handlebp(objectData *eventbus.ObjectData) {
	var comp common.Component
	bp, err := infradb.GetBP(objectData.Name)
	if err != nil {
		log.Printf("LVM : GetBP error: %s\n", err)
		comp.Name = lvmComp
		comp.CompStatus = common.ComponentStatusError
		if comp.Timer == 0 {
			comp.Timer = 2 * time.Second
		} else {
			comp.Timer *= 2
		}
		err := infradb.UpdateBPStatus(objectData.Name, objectData.ResourceVersion, objectData.NotificationID, nil, comp)
		if err != nil {
			log.Printf("error in updating bp status: %s\n", err)
		}
		return
	}
	if objectData.ResourceVersion != bp.ResourceVersion {
		log.Printf("LVM: Mismatch in resoruce version %+v\n and bp resource version %+v\n", objectData.ResourceVersion, bp.ResourceVersion)
		comp.Name = lvmComp
		comp.CompStatus = common.ComponentStatusError
		if comp.Timer == 0 {
			comp.Timer = 2 * time.Second
		} else {
			comp.Timer *= 2
		}
		err := infradb.UpdateBPStatus(objectData.Name, objectData.ResourceVersion, objectData.NotificationID, nil, comp)
		if err != nil {
			log.Printf("error in updating bp status: %s\n", err)
		}
		return
	}
	if len(bp.Status.Components) != 0 {
		for i := 0; i < len(bp.Status.Components); i++ {
			if bp.Status.Components[i].Name == lvmComp {
				comp = bp.Status.Components[i]
			}
		}
	}
	if bp.Status.BPOperStatus != infradb.BridgePortOperStatusToBeDeleted {
		status := setUpBp(bp)
		comp.Name = lvmComp
		if status {
			comp.Details = ""
			comp.CompStatus = common.ComponentStatusSuccess
			comp.Timer = 0
		} else {
			if comp.Timer == 0 {
				comp.Timer = 2 * time.Second
			} else {
				comp.Timer *= 2
			}
			comp.CompStatus = common.ComponentStatusError
		}
		log.Printf("LVM: %+v \n", comp)
		err := infradb.UpdateBPStatus(objectData.Name, objectData.ResourceVersion, objectData.NotificationID, bp.Metadata, comp)
		if err != nil {
			log.Printf("error updaing bp status %s\n", err)
		}
	} else {
		status := tearDownBp(bp)
		comp.Name = lvmComp
		if status {
			comp.CompStatus = common.ComponentStatusSuccess
			comp.Timer = 0
		} else {
			if comp.Timer == 0 {
				comp.Timer = 2 * time.Second
			} else {
				comp.Timer *= 2
			}
			comp.CompStatus = common.ComponentStatusError
		}
		log.Printf("LVM: %+v \n", comp)
		err := infradb.UpdateBPStatus(objectData.Name, objectData.ResourceVersion, objectData.NotificationID, nil, comp)
		if err != nil {
			log.Printf("error updaing bp status %s\n", err)
		}
	}
}

// MactoVport converts mac address to vport
func MactoVport(mac *net.HardwareAddr) int {
	byte0 := int((*mac)[0])
	byte1 := int((*mac)[1])
	return (byte0 << 8) + byte1
}

// setUpBp sets up a bridge port
func setUpBp(bp *infradb.BridgePort) bool {
	MacAddress := fmt.Sprintf("%+v", *bp.Spec.MacAddress)
	vportID := MactoVport(bp.Spec.MacAddress)
	link := fmt.Sprintf("vport-%+v", vportID)
	vport := fmt.Sprintf("%+v", vportID)
	bp.Metadata.VPort = vport
	muxIntf, err := nlink.LinkByName(ctx, portMux)
	if err != nil {
		log.Printf("Failed to get link information for %s, error is %v\n", portMux, err)
		return false
	}
	vlanLink := &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: link, ParentIndex: muxIntf.Attrs().Index}, VlanId: vportID, VlanProtocol: netlink.VLAN_PROTOCOL_8021AD}
	if err = nlink.LinkAdd(ctx, vlanLink); err != nil {
		log.Printf("Failed to add VLAN sub-interface %s: %v\n", link, err)
		return false
	}
	log.Printf("LVM: Executed ip link add link %s name %s type vlan protocol 802.1ad id %s\n", portMux, link, vport)
	brIntf, err := nlink.LinkByName(ctx, brTenant)
	if err != nil {
		log.Printf("Failed to get link information for %s: %v\n", brTenant, err)
		return false
	}
	if err = nlink.LinkSetMaster(ctx, vlanLink, brIntf); err != nil {
		log.Printf("Failed to set master for %s: %v\n", brIntf, err)
		return false
	}
	if err = nlink.LinkSetUp(ctx, vlanLink); err != nil {
		log.Printf("Failed to set up link for %v: %s\n", vlanLink, err)
		return false
	}
	if err = nlink.LinkSetMTU(ctx, vlanLink, ipMtu); err != nil {
		log.Printf("Failed to set MTU for %v: %s\n", vlanLink, err)
		return false
	}
	log.Printf("LVM: Executed ip link set %s master %s up mtu %d \n", link, brTenant, ipMtu)
	for _, vlan := range bp.Spec.LogicalBridges {
		BrObj, err := infradb.GetLB(vlan)
		if err != nil {
			log.Printf("LVM: unable to find key %s and error is %v", vlan, err)
			return false
		}
		if BrObj.Spec.VlanID > math.MaxUint16 {
			log.Printf("LVM : VlanID %v value passed in Logical Bridge create is greater than 16 bit value\n", BrObj.Spec.VlanID)
			return false
		}
		//TODO: Update opi-api to change vlanid to uint16 in LogiclaBridge
		vid := uint16(BrObj.Spec.VlanID)
		if err = nlink.BridgeVlanAdd(ctx, vlanLink, vid, false, false, false, false); err != nil {
			log.Printf("Failed to add VLAN %d to bridge interface %s: %v\n", vportID, link, err)
			return false
		}
		log.Printf("LVM: Executed bridge vlan add dev %s vid %d \n", link, vid)
	}
	if err = nlink.BridgeFdbAdd(ctx, link, MacAddress); err != nil {
		log.Printf("LVM: Error in executing command %s %s with error %s\n", "bridge fdb add", link, err)
		return false
	}
	log.Printf("LVM: Executed bridge fdb add %s dev %s master static extern_learn\n", MacAddress, link)
	return true
}

// tearDownBp tears down the bridge port
func tearDownBp(bp *infradb.BridgePort) bool {
	vportID := MactoVport(bp.Spec.MacAddress)
	link := fmt.Sprintf("vport-%+v", vportID)
	Intf, err := nlink.LinkByName(ctx, link)
	if err != nil {
		log.Printf("Failed to get link %v: %s\n", link, err)
		return true
	}
	if err = nlink.LinkDel(ctx, Intf); err != nil {
		log.Printf("Failed to delete link %v: %s\n", link, err)
		return false
	}
	log.Printf(" LVM: Executed ip link delete %v\n", link)
	return true
}

// handlevrf handles the vrf functionality
//
//gocognit:ignore
func handlevrf(objectData *eventbus.ObjectData) {
	var comp common.Component
	vrf, err := infradb.GetVrf(objectData.Name)
	if err != nil {
		log.Printf("LVM : GetVrf error: %s\n", err)
		comp.Name = lvmComp
		comp.CompStatus = common.ComponentStatusError
		if comp.Timer == 0 { // wait timer is 2 powerof natural numbers ex : 1,2,3...
			comp.Timer = 2 * time.Second
		} else {
			comp.Timer *= 2
		}
		err := infradb.UpdateVrfStatus(objectData.Name, objectData.ResourceVersion, objectData.NotificationID, nil, comp)
		if err != nil {
			log.Printf("error updaing vrf status %s\n", err)
		}
		return
	}
	if objectData.ResourceVersion != vrf.ResourceVersion {
		log.Printf("LVM: Mismatch in resoruce version %+v\n and vrf resource version %+v\n", objectData.ResourceVersion, vrf.ResourceVersion)
		comp.Name = lvmComp
		comp.CompStatus = common.ComponentStatusError
		if comp.Timer == 0 { // wait timer is 2 powerof natural numbers ex : 1,2,3...
			comp.Timer = 2 * time.Second
		} else {
			comp.Timer *= 2
		}
		err := infradb.UpdateVrfStatus(objectData.Name, objectData.ResourceVersion, objectData.NotificationID, nil, comp)
		if err != nil {
			log.Printf("error updaing vrf status %s\n", err)
		}
		return
	}
	if len(vrf.Status.Components) != 0 {
		for i := 0; i < len(vrf.Status.Components); i++ {
			if vrf.Status.Components[i].Name == lvmComp {
				comp = vrf.Status.Components[i]
			}
		}
	}
	if vrf.Status.VrfOperStatus != infradb.VrfOperStatusToBeDeleted {
		statusUpdate := setUpVrf(vrf)
		comp.Name = lvmComp
		if statusUpdate {
			comp.Details = ""
			comp.CompStatus = common.ComponentStatusSuccess
			comp.Timer = 0
		} else {
			if comp.Timer == 0 {
				comp.Timer = 2 * time.Second
			} else {
				comp.Timer *= 2
			}
			comp.CompStatus = common.ComponentStatusError
		}
		err := infradb.UpdateVrfStatus(objectData.Name, objectData.ResourceVersion, objectData.NotificationID, nil, comp)
		if err != nil {
			log.Printf("error updaing vrf status %s\n", err)
		}
	} else {
		comp.Name = lvmComp
		if tearDownVrf(vrf) {
			comp.CompStatus = common.ComponentStatusSuccess
		} else {
			if comp.Timer == 0 {
				comp.Timer = 2 * time.Second
			} else {
				comp.Timer *= 2
			}
			comp.CompStatus = common.ComponentStatusError
		}
		err := infradb.UpdateVrfStatus(objectData.Name, objectData.ResourceVersion, objectData.NotificationID, nil, comp)
		if err != nil {
			log.Printf("error updaing vrf status %s\n", err)
		}
	}
}

// disableRpFilter disables the RP filter
func disableRpFilter(iface string) error {
	// Work-around for the observation that sometimes the sysctl -w command did not take effect.
	rpFilterDisabled := false
	var maxTry = 5
	for i := 0; i < maxTry; i++ {
		rpDisable := fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", iface)
		output, errCode := run([]string{"sysctl", "-w", rpDisable}, false)
		if errCode != 0 && i == maxTry-1 {
			log.Printf("Error setting rp_filter: %s\n", output)
			return fmt.Errorf("%s", output)
		}
		time.Sleep(200 * time.Millisecond)
		rpDisable = fmt.Sprintf("net.ipv4.conf.%s.rp_filter", iface)
		output, errCode = run([]string{"sysctl", "-n", rpDisable}, false)
		if errCode == 0 && strings.HasPrefix(output, "0") {
			rpFilterDisabled = true
			log.Printf("RP filter disabled on interface %s\n", iface)
			break
		}
	}
	if !rpFilterDisabled {
		log.Printf("Failed to disable rp_filter on interface %s\n", iface)
	}
	return nil
}

// setUpVrf sets up a vrf
func setUpVrf(vrf *infradb.Vrf) bool {
	log.Printf("LVM configure linux function \n")
	vlanIntf := fmt.Sprintf("rep-%+v", path.Base(vrf.Name))
	if path.Base(vrf.Name) == "GRD" {
		err := disableRpFilter("rep-" + path.Base(vrf.Name))
		if err != nil {
			log.Printf("Failed to disable RP filter %v", err)
			return false
		}
		return true
	}
	muxIntf, err := nlink.LinkByName(ctx, vrfMux)
	if err != nil {
		log.Printf("Failed to get link information for %s, error is %v\n", vrfMux, err)
		return false
	}
	vlanLink := &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: vlanIntf, ParentIndex: muxIntf.Attrs().Index}, VlanId: int(*vrf.Metadata.RoutingTable[0])}
	if err = nlink.LinkAdd(ctx, vlanLink); err != nil {
		log.Printf("Failed to add VLAN sub-interface %s: %v\n", vlanIntf, err)
		return false
	}
	log.Printf(" LVM: Executed ip link add link %s name rep-%s type vlan id %s\n", vrfMux, path.Base(vrf.Name), strconv.Itoa(int(*vrf.Metadata.RoutingTable[0])))
	vrfIntf, err := nlink.LinkByName(ctx, path.Base(vrf.Name))
	if err != nil {
		log.Printf("Failed to get link information for %s: %v\n", path.Base(vrf.Name), err)
		return false
	}
	if err = nlink.LinkSetMaster(ctx, vlanLink, vrfIntf); err != nil {
		log.Printf("Failed to set master for %v: %s\n", vlanIntf, err)
		return false
	}
	if err = nlink.LinkSetUp(ctx, vlanLink); err != nil {
		log.Printf("Failed to set up link for %v: %s\n", vlanLink, err)
		return false
	}
	if err = nlink.LinkSetMTU(ctx, vlanLink, ipMtu); err != nil {
		log.Printf("Failed to set MTU for %v: %s\n", vlanLink, err)
		return false
	}
	log.Printf(" LVM: Executed ip link set rep-%s master %s up mtu %d\n", path.Base(vrf.Name), path.Base(vrf.Name), ipMtu)
	err = disableRpFilter("rep-" + path.Base(vrf.Name))
	if err != nil {
		log.Printf("Failed to disable RP filter %v", err)
		return false
	}
	return true
}

func UpdateTunRep(tun *infradb.TunRep) bool {
	// We need to handle the update events as no-op
	// because we do not want to fully delete and create
	// the linux configuration for tunnel representor
	// every time we have a bind/unbind of an SA.
	// In the future were we will support proper updates for
	// all the objects (VRFs, LBs, TunReps etc...) we will
	// revisit the subject.

	/*
		for _, tuns := range tun.OldVersions {
			tunObj, err := infradb.GetTunRep(tuns)
			if err == nil {
				if !tearDownTunRep(tunObj) {
					log.Printf("LVM: UpdateTunRep failed for object %+v\n", tunObj)
					return false
				}
			}
		}
		return setUpTunRep(tun)
	*/
	log.Println("LVM: Inside the UpdateTunRep() function")
	return true
}

func setUpTunRep(tun *infradb.TunRep) bool {
	link := path.Base(tun.Spec.IfName)

	muxIntf, err := nlink.LinkByName(ctx, tunMux)
	if err != nil {
		log.Printf("Failed to get link information for %s, error is %v\n", tunMux, err)
		return false
	}
	vlanLink := &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: link, ParentIndex: muxIntf.Attrs().Index}, VlanId: int(tun.Spec.IfID)}
	if err = nlink.LinkAdd(ctx, vlanLink); err != nil {
		log.Printf("Failed to add VLAN sub-interface %s: %v\n", link, err)
		return false
	}
	log.Printf("LVM: Executed ip link add link %s name %s type vlan protocol 802.1ad id %d\n", tunMux, link, tun.Spec.IfID)

	linkmtuErr := nlink.LinkSetMTU(ctx, vlanLink, ipMtu+50)
	if linkmtuErr != nil {
		log.Printf("LVM : Unable to set MTU to link %s \n", link)
		return false
	}

	linkArpOff := nlink.LinkSetArpOff(ctx, vlanLink)
	if linkArpOff != nil {
		log.Printf("LVM: Unable to set arp off to link %s \n", link)
		return false
	}
	var address = tun.Spec.IPNet
	var Addrs = &netlink.Addr{
		IPNet: address,
	}
	addrErr := nlink.AddrAdd(ctx, vlanLink, Addrs)
	if addrErr != nil {
		log.Printf("LVM: Unable to set the ip to tun link %s \n", link)
		return false
	}
	log.Printf("LVM: Added Address %s dev %s\n", address, link)

	if err = nlink.LinkSetUp(ctx, vlanLink); err != nil {
		log.Printf("LVM: Failed to set link in up state. Details: %+v: Error: %+v\n", vlanLink, err)
		return false
	}

	if tun.Spec.RemoteIP != nil {
		dst := tun.Spec.RemoteIPNet
		vrf, err := infradb.GetVrf(tun.Spec.Vrf)
		if err != nil {
			return false
		}
		dev, _ := nlink.LinkByName(ctx, link)
		LinkIndex := dev.Attrs().Index
		route := netlink.Route{
			Table:     int(*vrf.Metadata.RoutingTable[0]),
			Protocol:  255,
			Dst:       dst,
			LinkIndex: LinkIndex,
			Scope:     netlink.SCOPE_LINK,
		}
		//netlink.Route.LinkIndex
		routeaddErr := nlink.RouteAdd(ctx, &route)
		if routeaddErr != nil {
			log.Printf("LVM : Failed in adding Route %+v\n", routeaddErr)
			return false
		}
	}
	linksetupErr := nlink.LinkSetUp(ctx, vlanLink)
	if linksetupErr != nil {
		log.Printf("LVM : Unable to set link %s UP \n", link)
		return false
	}
	return true
}

// tearDownVrf tears down a vrf
func tearDownVrf(vrf *infradb.Vrf) bool {
	vlanIntf := fmt.Sprintf("rep-%+v", path.Base(vrf.Name))
	if path.Base(vrf.Name) == "GRD" {
		return true
	}
	Intf, err := nlink.LinkByName(ctx, vlanIntf)
	if err != nil {
		log.Printf("Failed to get link %v: %s\n", vlanIntf, err)
		return false
	}
	if err = nlink.LinkDel(ctx, Intf); err != nil {
		log.Printf("Failed to delete link %v: %s\n", vlanIntf, err)
		return false
	}
	log.Printf(" LVM: Executed ip link delete rep-%s\n", path.Base(vrf.Name))
	return true
}

func tearDownTunRep(tun *infradb.TunRep) bool {
	link, err1 := nlink.LinkByName(ctx, path.Base(tun.Spec.IfName))
	if err1 != nil {
		log.Printf("LVM : Link %s not found %+v\n", tun.Spec.IfName, err1)
		return true
	}
	delerr := nlink.LinkDel(ctx, link)
	if delerr != nil {
		log.Printf("LVM: Error in delete br %+v\n", delerr)
		return false
	}
	log.Printf("LVM :link delete  %s\n", tun.Spec.IfName)
	return true
}

var ipMtu int
var brTenant string
var ctx context.Context
var nlink utils.Netlink
var tunMux string

// Initialize function initialize config
func Initialize() {
	eb := eventbus.EBus
	for _, subscriberConfig := range config.GlobalConfig.Subscribers {
		if subscriberConfig.Name == lvmComp {
			for _, eventType := range subscriberConfig.Events {
				eb.StartSubscriber(subscriberConfig.Name, eventType, subscriberConfig.Priority, &ModulelvmHandler{})
			}
		}
	}
	portMux = config.GlobalConfig.Interfaces.PortMux
	vrfMux = config.GlobalConfig.Interfaces.VrfMux
	tunMux = config.GlobalConfig.Interfaces.TunnelMux
	ipMtu = config.GlobalConfig.LinuxFrr.IPMtu
	brTenant = "br-tenant"
	ctx = context.Background()
	nlink = utils.NewNetlinkWrapperWithArgs(config.GlobalConfig.Tracer)
}

// DeInitialize function handles stops functionality
func DeInitialize() {
	eb := eventbus.EBus
	eb.UnsubscribeModule(lvmComp)
}
