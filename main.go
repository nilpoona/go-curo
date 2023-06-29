package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"syscall"
)

type netDevice struct {
	name       string
	macAddr    [6]uint8
	socket     int
	sockAddr   syscall.SockaddrLinklayer
	etheHeader ethernetHeader
	ipDev      ipDevice
}

type radixTreeNode struct {
	depth  int
	parent *radixTreeNode
	node0  *radixTreeNode // 0を入れる左のノード
	node1  *radixTreeNode // 1を入れる右のノード
	data   ipRouteEntry
	value  int
}

func (node *radixTreeNode) radixTreeSearch(prefixIpAddr uint32) ipRouteEntry {
	current := node
	var result ipRouteEntry
	// 検索するIPアドレスと比較して1ビットずつ辿っていく
	for i := 1; i <= 32; i++ {
		if current.data != (ipRouteEntry{}) {
			result = current.data
		}
		if (prefixIpAddr>>(32-i))&0x01 == 1 { // 上からiビット目が1だったら
			if current.node1 == nil {
				return result
			}
			current = current.node1
		} else { // iビット目が0だったら
			if current.node0 == nil {
				return result
			}
			current = current.node0
		}
	}
	return result
}

var iproute radixTreeNode
var netDeviceList []*netDevice

func byteToUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

const ETHER_TYPE_IP uint16 = 0x0800
const ETHER_TYPE_ARP uint16 = 0x0806
const ETHER_TYPE_IPV6 uint16 = 0x86dd
const ETHERNET_ADDRES_LEN = 6

var ETHERNET_ADDRESS_BROADCAST = [6]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

func (netDev *netDevice) netDevicePoll(mode string) error {
	recvBuffer := make([]byte, 1500)
	n, _, err := syscall.Recvfrom(netDev.socket, recvBuffer, 0)
	if err != nil {
		if n == -1 {
			return nil
		} else {
			return fmt.Errorf("recv err, n is %d, device is %s, err is %s", n, netDev.name, err)
		}
	}

	if mode == "ch1" {
		fmt.Printf("Received %d bytes from %s: %x\n", n, netDev.name, recvBuffer[:n])
	} else {
		ethernetInput(netDev, recvBuffer[:n])
	}

	return nil
}

func byteToUint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

// イーサネットの受信処理
func ethernetInput(netdev *netDevice, packet []byte) {
	// 送られてきた通信をイーサネットのフレームとして解釈する
	netdev.etheHeader.destAddr = setMacAddr(packet[0:6])
	netdev.etheHeader.srcAddr = setMacAddr(packet[6:12])
	netdev.etheHeader.etherType = byteToUint16(packet[12:14])
	// 自分のMACアドレス宛てかブロードキャストの通信かを確認する
	if netdev.macAddr != netdev.etheHeader.destAddr && netdev.etheHeader.destAddr != ETHERNET_ADDRESS_BROADCAST {
		// 自分のMACアドレス宛てかブロードキャストでなければ return する
		return
	}
	// イーサタイプの値から上位プロトコルを特定する
	switch netdev.etheHeader.etherType {
	case ETHER_TYPE_ARP:
		arpInput(netdev, packet[14:])
	case ETHER_TYPE_IP:
		ipInput(netdev, packet[14:])
	}
}

type ethernetHeader struct {
	destAddr  [6]uint8 // destination MAC address
	srcAddr   [6]uint8 // source MAC address
	etherType uint16
}

var IgnoreInterfaces = []string{"lo", "bond0", "dummy0", "tunl0", "sit0"}

func isIgnoreInterfaces(name string) bool {
	for _, v := range IgnoreInterfaces {
		if v == name {
			return true
		}
	}
	return false
}

func setMacAddr(macAddrByte []byte) [6]uint8 {
	var macAddrUint8 [6]uint8
	for i, v := range macAddrByte {
		macAddrUint8[i] = v
	}
	return macAddrUint8
}

// htons converts a short (uint16) from host-to-network byte order.
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func runChapter1() {
	events := make([]syscall.EpollEvent, 10)
	epfd, err := syscall.EpollCreate1(0)
	if err != nil {
		log.Fatalf("epoll create err : %s", err)
	}

	interfaces, _ := net.Interfaces()
	for _, netif := range interfaces {
		if !isIgnoreInterfaces(netif.Name) {
			sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW,
				int(htons(syscall.ETH_P_ALL)))
			if err != nil {
				log.Fatalf("create socket err : %s", err)
			}
			addr := syscall.SockaddrLinklayer{
				Protocol: htons(syscall.ETH_P_ALL),
				Ifindex:  netif.Index,
			}

			err = syscall.Bind(sock, &addr)
			if err != nil {
				log.Fatalf("bind err : %s", err)
			}
			fmt.Printf("Created device %s socket %d adddress %s\n",
				netif.Name, sock, netif.HardwareAddr.String())
			err = syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, sock, &syscall.EpollEvent{
				Events: syscall.EPOLLIN,
				Fd:     int32(sock),
			})
			if err != nil {
				log.Fatalf("epoll ctrl err : %s", err)
			}
			//err = syscall.SetNonblock(sock, true)
			//if err != nil {
			// log.Fatalf("set non block is err : %s", err)
			//}
			// netDevice構造体を作成
			// net_deviceの連結リストに連結させる
			netDeviceList = append(netDeviceList, &netDevice{
				name:     netif.Name,
				macAddr:  setMacAddr(netif.HardwareAddr),
				socket:   sock,
				sockAddr: addr,
			})
		}
	}

	for {
		nfds, err := syscall.EpollWait(epfd, events, -1)
		if err != nil {
			log.Fatalf("epoll wait err : %s", err)
		}
		for i := 0; i < nfds; i++ {
			for _, netDev := range netDeviceList {
				if events[i].Fd == int32(netDev.socket) {
					err = netDev.netDevicePoll("ch1")
					if err != nil {
						log.Fatal(err)
					}
				}
			}
		}
	}
}

func runChapter2(mode string) {

	// 直接接続ではないhost2へのルーティングを登録する
	routeEntryTohost2 := ipRouteEntry{
		iptype:  network,
		nexthop: 0xc0a80002,
	}
	// 192.168.2.0/24の経路の登録
	iproute.radixTreeAdd(0xc0a80202&0xffffff00, 24, routeEntryTohost2)

	// epoll作成
	events := make([]syscall.EpollEvent, 10)
	epfd, err := syscall.EpollCreate1(0)
	if err != nil {
		log.Fatalf("epoll create err : %s", err)
	}

	// ネットワークインターフェイスの情報を取得
	interfaces, _ := net.Interfaces()
	for _, netif := range interfaces {
		// 無視するインターフェイスか確認
		if !isIgnoreInterfaces(netif.Name) {
			// socketをオープン
			sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
			if err != nil {
				log.Fatalf("create socket err : %s", err)
			}
			// socketにインターフェイスをbindする
			addr := syscall.SockaddrLinklayer{
				Protocol: htons(syscall.ETH_P_ALL),
				Ifindex:  netif.Index,
			}
			err = syscall.Bind(sock, &addr)
			if err != nil {
				log.Fatalf("bind err : %s", err)
			}
			fmt.Printf("Created device %s socket %d adddress %s\n",
				netif.Name, sock, netif.HardwareAddr.String())
			// socketをepollの監視対象として登録
			err = syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, sock, &syscall.EpollEvent{
				Events: syscall.EPOLLIN,
				Fd:     int32(sock),
			})
			// ノンブロッキングに設定←epollを使うのでしない
			//err = syscall.SetNonblock(sock, true)
			//if err != nil {
			//	log.Fatalf("set non block is err : %s", err)
			//}
			netaddrs, err := netif.Addrs()
			if err != nil {
				log.Fatalf("get ip addr from nic interface is err : %s", err)
			}

			netdev := netDevice{
				name:     netif.Name,
				macAddr:  setMacAddr(netif.HardwareAddr),
				socket:   sock,
				sockAddr: addr,
				ipDev:    getIPdevice(netaddrs),
			}

			// 直接接続ネットワークの経路をルートテーブルのエントリに設定
			routeEntry := ipRouteEntry{
				iptype: connected,
				netdev: &netdev,
			}
			prefixLen := subnetToPrefixLen(netdev.ipDev.netmask)
			iproute.radixTreeAdd(netdev.ipDev.address&netdev.ipDev.netmask, prefixLen, routeEntry)
			fmt.Printf("Set directly connected route %s/%d via %s\n",
				printIPAddr(netdev.ipDev.address&netdev.ipDev.netmask), prefixLen, netdev.name)

			// netDevice構造体を作成
			// net_deviceの連結リストに連結させる
			netDeviceList = append(netDeviceList, &netdev)
		}
	}

	fmt.Printf("mode is %s start router...\n", mode)

	for {
		// epoll_waitでパケットの受信を待つ
		nfds, err := syscall.EpollWait(epfd, events, -1)
		if err != nil {
			log.Fatalf("epoll wait err : %s", err)
		}
		for i := 0; i < nfds; i++ {
			// デバイスから通信を受信
			for _, netdev := range netDeviceList {
				// イベントがあったソケットとマッチしたらパケットを読み込む処理を実行
				if events[i].Fd == int32(netdev.socket) {
					err := netdev.netDevicePoll(mode)
					if err != nil {
						log.Fatal(err)
					}
				}
			}
		}
	}
}

func main() {
	var mode string
	flag.StringVar(&mode, "mode", "ch1", "set run router mode")
	flag.Parse()
	if mode == "ch1" {
		runChapter1()
	} else {
		runChapter2(mode)
	}
}
