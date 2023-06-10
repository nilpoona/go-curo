package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"syscall"
)

const (
	ICMP_TYPE_ECHO_REPLY              uint8 = 0
	ICMP_TYPE_DESTINATION_UNREACHABLE uint8 = 3
	ICMP_TYPE_ECHO_REQUEST            uint8 = 8
	ICMP_TYPE_TIME_EXCEEDED           uint8 = 11
)

type icmpHeader struct {
	icmpType uint8
	icmpCode uint8
	checksum uint16
}

type icmpEcho struct {
	identify  uint16
	sequence  uint16
	timestamp []uint8
	data      []uint8
}

type icmpDestinationUnreachable struct {
	unused uint32
	data   []uint8
}

type icmpTimeExceeded struct {
	unused uint32
	data   []uint8
}

type icmpMessage struct {
	icmpHeader                 icmpHeader
	icmpEcho                   icmpEcho
	icmpDestinationUnreachable icmpDestinationUnreachable
	icmpTimeExceeded           icmpTimeExceeded
}

const IP_ADDRESS_LEN = 4
const IP_ADDRESS_LIMITED_BROADCAST uint32 = 0xffffffff
const IP_PROTOCOL_NUM_ICMP uint8 = 0x01
const IP_PROTOCOL_NUM_TCP uint8 = 0x06
const IP_PROTOCOL_NUM_UDP uint8 = 0x11

type ipDevice struct {
	address   uint32 // デバイスのIPアドレス
	netmask   uint32 // サブネットマスク
	broadcast uint32 // ブロードキャストアドレス
}

type ipHeader struct {
	version        uint8  // バージョン
	headerLen      uint8  // ヘッダ長
	tos            uint8  // Type of Service
	totalLen       uint16 // Totalのパケット長
	identify       uint16 // 識別番号
	fragOffset     uint16 // フラグ
	ttl            uint8  // Time To Live
	protocol       uint8  // 上位のプロトコル番号
	headerChecksum uint16 // ヘッダのチェックサム
	srcAddr        uint32 // 送信元IPアドレス
	destAddr       uint32 // 送信先IPアドレス
}

type ipRouteType uint8

const (
	connected ipRouteType = iota
	network
)

type ipRouteEntry struct {
	iptype  ipRouteType
	netdev  *netDevice
	nexthop uint32
}

func (ipheader ipHeader) ToPacket(calc bool) (ipHeaderByte []byte) {
	var b bytes.Buffer

	b.Write([]byte{ipheader.version<<4 + ipheader.headerLen})
	b.Write([]byte{ipheader.tos})
	b.Write(uint16ToByte(ipheader.totalLen))
	b.Write(uint16ToByte(ipheader.identify))
	b.Write(uint16ToByte(ipheader.fragOffset))
	b.Write([]byte{ipheader.ttl})
	b.Write([]byte{ipheader.protocol})
	b.Write(uint16ToByte(ipheader.headerChecksum))
	b.Write(uint32ToByte(ipheader.srcAddr))
	b.Write(uint32ToByte(ipheader.destAddr))

	// checksumを計算する
	if calc {
		ipHeaderByte = b.Bytes()
		checksum := calcChecksum(ipHeaderByte)
		// checksumをセット
		ipHeaderByte[10] = checksum[0]
		ipHeaderByte[11] = checksum[1]
	} else {
		ipHeaderByte = b.Bytes()
	}

	return ipHeaderByte
}

func getIPdevice(addrs []net.Addr) (ipdev ipDevice) {
	for _, addr := range addrs {
		// ipv6ではなくipv4アドレスをリターン
		ipaddrstr := addr.String()
		if !strings.Contains(ipaddrstr, ":") && strings.Contains(ipaddrstr, ".") {
			ip, ipnet, _ := net.ParseCIDR(ipaddrstr)
			ipdev.address = byteToUint32(ip.To4())
			ipdev.netmask = byteToUint32(ipnet.Mask)
			// ブロードキャストアドレスの計算はIPアドレスとサブネットマスクのbit反転の2進数「OR（論理和）」演算
			ipdev.broadcast = ipdev.address | (^ipdev.netmask)
		}
	}
	return ipdev
}

func printIPAddr(ip uint32) string {
	ipbyte := uint32ToByte(ip)
	return fmt.Sprintf("%d.%d.%d.%d", ipbyte[0], ipbyte[1], ipbyte[2], ipbyte[3])
}

// サブネットマスクとプレフィックス長の変換
// 0xffffff00を24にする
func subnetToPrefixLen(netmask uint32) uint32 {
	var prefixlen uint32
	for prefixlen = 0; prefixlen < 32; prefixlen++ {
		if !(netmask>>(31-prefixlen)&0b01 == 1) {
			break
		}
	}
	return prefixlen
}

/*
IPパケットの受信処理
https://github.com/kametan0730/interface_2022_11/blob/master/chapter2/ip.cpp#L51
*/
func ipInput(inputdev *netDevice, packet []byte) {
	// IPアドレスのついていないインターフェースからの受信は無視
	if inputdev.ipDev.address == 0 {
		return
	}
	// IPヘッダ長より短かったらドロップ
	if len(packet) < 20 {
		fmt.Printf("Received IP packet too short from %s\n", inputdev.name)
		return
	}
	// 受信したIPパケットをipHeader構造体にセットする
	ipheader := ipHeader{
		version:        packet[0] >> 4,
		headerLen:      packet[0] << 5 >> 5,
		tos:            packet[1],
		totalLen:       byteToUint16(packet[2:4]),
		identify:       byteToUint16(packet[4:6]),
		fragOffset:     byteToUint16(packet[6:8]),
		ttl:            packet[8],
		protocol:       packet[9],
		headerChecksum: byteToUint16(packet[10:12]),
		srcAddr:        byteToUint32(packet[12:16]),
		destAddr:       byteToUint32(packet[16:20]),
	}

	fmt.Printf("ipInput Received IP in %s, packet type %d from %s to %s\n", inputdev.name, ipheader.protocol,
		printIPAddr(ipheader.srcAddr), printIPAddr(ipheader.destAddr))

	// 受信したMACアドレスがARPテーブルになければ追加しておく
	macaddr, _ := searchArpTableEntry(ipheader.srcAddr)
	if macaddr == [6]uint8{} {
		addArpTableEntry(inputdev, ipheader.srcAddr, inputdev.etheHeader.srcAddr)
	}

	// IPバージョンが4でなければドロップ
	// Todo: IPv6の実装
	if ipheader.version != 4 {
		if ipheader.version == 6 {
			fmt.Println("packet is IPv6")
		} else {
			fmt.Println("Incorrect IP version")
		}
		return
	}

	// IPヘッダオプションがついていたらドロップ = ヘッダ長が20byte以上だったら
	if 20 < (ipheader.headerLen * 4) {
		fmt.Println("IP header option is not supported")
		return
	}

	// 宛先アドレスがブロードキャストアドレスか受信したNICインターフェイスのIPアドレスの場合
	if ipheader.destAddr == IP_ADDRESS_LIMITED_BROADCAST || inputdev.ipDev.address == ipheader.destAddr {
		// 自分宛の通信として処理
		ipInputToOurs(inputdev, &ipheader, packet[20:])
		return
	}

	// 宛先IPアドレスをルータが持ってるか調べる
	// つまり宛先IPが他のNICインターフェイスについてるIPアドレスだったら自分宛てのものとして処理する
	for _, dev := range netDeviceList {
		// 宛先IPアドレスがルータの持っているIPアドレス or ディレクティッド・ブロードキャストアドレスの時の処理
		if dev.ipDev.address == ipheader.destAddr || dev.ipDev.broadcast == ipheader.destAddr {
			// 自分宛の通信として処理
			ipInputToOurs(inputdev, &ipheader, packet[20:])
			return
		}
	}
}

/*
自分宛のIPパケットの処理
https://github.com/kametan0730/interface_2022_11/blob/master/chapter2/ip.cpp#L26
*/
func ipInputToOurs(inputdev *netDevice, ipheader *ipHeader, packet []byte) {
	// 上位プロトコルの処理に移行
	switch ipheader.protocol {
	case IP_PROTOCOL_NUM_ICMP:
		fmt.Println("ICMP received!")
		icmpInput(inputdev, ipheader.srcAddr, ipheader.destAddr, packet)
	case IP_PROTOCOL_NUM_UDP:
		fmt.Printf("udp received : %x\n", packet)
		//return
	case IP_PROTOCOL_NUM_TCP:
		return
	default:
		fmt.Printf("Unhandled ip protocol number : %d\n", ipheader.protocol)
		return
	}
}

func icmpInput(inputdev *netDevice, sourceAddr, destAddr uint32, icmpPacket []byte) {
	// ICMPメッセージ長より短かったら
	if len(icmpPacket) < 4 {
		fmt.Println("Received ICMP Packet is too short")
	}
	// ICMPのパケットとして解釈する
	icmpmsg := icmpMessage{
		icmpHeader: icmpHeader{
			icmpType: icmpPacket[0],
			icmpCode: icmpPacket[1],
			checksum: byteToUint16(icmpPacket[2:4]),
		},
		icmpEcho: icmpEcho{
			identify:  byteToUint16(icmpPacket[4:6]),
			sequence:  byteToUint16(icmpPacket[6:8]),
			timestamp: icmpPacket[8:16],
			data:      icmpPacket[16:],
		},
	}
	// fmt.Printf("ICMP Packet is %+v\n", icmpmsg)

	switch icmpmsg.icmpHeader.icmpType {
	case ICMP_TYPE_ECHO_REPLY:
		fmt.Println("ICMP ECHO REPLY is received")
	case ICMP_TYPE_ECHO_REQUEST:
		fmt.Println("ICMP ECHO REQUEST is received, Create Reply Packet")
		ipPacketEncapsulateOutput(inputdev, sourceAddr, destAddr, icmpmsg.ReplyPacket(), IP_PROTOCOL_NUM_ICMP)
	}
}

func (icmpmsg icmpMessage) ReplyPacket() (icmpPacket []byte) {
	var b bytes.Buffer
	// ICMPヘッダ
	b.Write([]byte{ICMP_TYPE_ECHO_REPLY})
	b.Write([]byte{0x00})       // icmp code
	b.Write([]byte{0x00, 0x00}) // checksum
	// ICMPエコーメッセージ
	b.Write(uint16ToByte(icmpmsg.icmpEcho.identify))
	b.Write(uint16ToByte(icmpmsg.icmpEcho.sequence))
	b.Write(icmpmsg.icmpEcho.timestamp)
	b.Write(icmpmsg.icmpEcho.data)

	icmpPacket = b.Bytes()
	checksum := calcChecksum(icmpPacket)
	// 計算したチェックサムをセット
	icmpPacket[2] = checksum[0]
	icmpPacket[3] = checksum[1]

	fmt.Printf("Send ICMP Packet is %x\n", icmpPacket)

	return icmpPacket
}

func calcChecksum(packet []byte) []byte {
	// まず16ビット毎に足す
	sum := sumByteArr(packet)
	// あふれた桁を足す
	sum = (sum & 0xffff) + sum>>16
	// 論理否定を取った値をbyteにして返す
	return uint16ToByte(uint16(sum ^ 0xffff))
}

func sumByteArr(packet []byte) (sum uint) {
	for i, _ := range packet {
		if i%2 == 0 {
			sum += uint(byteToUint16(packet[i:]))
		}
	}
	return sum
}

/*
IPパケットを直接イーサネットでホストに送信
*/
func ipPacketOutputToHost(dev *netDevice, destAddr uint32, packet []byte) {
	// ARPテーブルの検索
	destMacAddr, _ := searchArpTableEntry(destAddr)
	if destMacAddr == [6]uint8{0, 0, 0, 0, 0, 0} {
		// ARPエントリが無かったら
		fmt.Printf("Trying ip output to host, but no arp record to %s\n", printIPAddr(destAddr))
		// ARPリクエストを送信
		sendArpRequest(dev, destAddr)
	} else {
		// ARPエントリがあり、MACアドレスが得られたらイーサネットでカプセル化して送信
		ethernetOutput(dev, destMacAddr, packet, ETHER_TYPE_IP)
	}
}

/*
IPパケットをNextHopに送信
*/
func ipPacketOutputToNetxhop(nextHop uint32, packet []byte) {
	// ARPテーブルの検索
	destMacAddr, dev := searchArpTableEntry(nextHop)
	if destMacAddr == [6]uint8{0, 0, 0, 0, 0, 0} {
		fmt.Printf("Trying ip output to next hop, but no arp record to %s\n", printIPAddr(nextHop))
		// ルーティングテーブルのルックアップ
		routeToNexthop := iproute.radixTreeSearch(nextHop)
		//fmt.Printf("next hop route is from %s\n", routeToNexthop.netdev.name)
		if routeToNexthop == (ipRouteEntry{}) || routeToNexthop.iptype != connected {
			// next hopへの到達性が無かったら
			fmt.Printf("Next hop %s is not reachable\n", printIPAddr(nextHop))
		} else {
			// ARPリクエストを送信
			sendArpRequest(routeToNexthop.netdev, nextHop)
		}
	} else {
		// ARPエントリがあり、MACアドレスが得られたらイーサネットでカプセル化して送信
		ethernetOutput(dev, destMacAddr, packet, ETHER_TYPE_IP)
	}
}

/*
IPパケットを送信
*/
func ipPacketOutput(outputdev *netDevice, routeTree radixTreeNode, destAddr uint32, packet []byte) {
	// 宛先IPアドレスへの経路を検索
	route := routeTree.radixTreeSearch(destAddr)
	if route == (ipRouteEntry{}) {
		// 経路が見つからなかったら
		fmt.Printf("No route to %s\n", printIPAddr(destAddr))
	}
	if route.iptype == connected {
		// 直接接続されたネットワークなら
		ipPacketOutputToHost(outputdev, destAddr, packet)
	} else if route.iptype == network {
		// 直接つながっていないネットワークなら
		ipPacketOutputToNetxhop(destAddr, packet)
	}
}

/*
IPパケットにカプセル化して送信
https://github.com/kametan0730/interface_2022_11/blob/master/chapter2/ip.cpp#L102
*/
func ipPacketEncapsulateOutput(inputdev *netDevice, destAddr, srcAddr uint32, payload []byte, protocolType uint8) {
	var ipPacket []byte

	// IPヘッダで必要なIPパケットの全長を算出する
	// IPヘッダの20byte + パケットの長さ
	totalLength := 20 + len(payload)

	// IPヘッダの各項目を設定
	ipheader := ipHeader{
		version:        4,
		headerLen:      20 / 4,
		tos:            0,
		totalLen:       uint16(totalLength),
		identify:       0xf80c,
		fragOffset:     2 << 13,
		ttl:            0x40,
		protocol:       protocolType,
		headerChecksum: 0, // checksum計算する前は0をセット
		srcAddr:        srcAddr,
		destAddr:       destAddr,
	}
	// IPヘッダをByteにする
	ipPacket = append(ipPacket, ipheader.ToPacket(true)...)
	// payloadを追加
	ipPacket = append(ipPacket, payload...)

	// ルートテーブルを検索して送信先IPのMACアドレスがなければ、
	// ARPリクエストを生成して送信して結果を受信してから、ethernetからパケットを送る
	destMacAddr, _ := searchArpTableEntry(destAddr)
	if destMacAddr != [6]uint8{0, 0, 0, 0, 0, 0} {
		// ルートテーブルに送信するIPアドレスのMACアドレスがあれば送信
		ethernetOutput(inputdev, destMacAddr, ipPacket, ETHER_TYPE_IP)
	} else {
		// ARPリクエストを出す
		sendArpRequest(inputdev, destAddr)
	}
}

func uint16ToByte(i uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return b
}

func uint32ToByte(i uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return b
}

func (ethHeader ethernetHeader) ToPacket() []byte {
	var b bytes.Buffer
	b.Write(macToByte(ethHeader.destAddr))
	b.Write(macToByte(ethHeader.srcAddr))
	b.Write(uint16ToByte(ethHeader.etherType))
	return b.Bytes()
}

// イーサネットにカプセル化して送信
func ethernetOutput(netdev *netDevice, destaddr [6]uint8, packet []byte, ethType uint16) {
	// イーサネットヘッダのパケットを作成
	ethHeaderPacket := ethernetHeader{
		destAddr:  destaddr,
		srcAddr:   netdev.macAddr,
		etherType: ethType,
	}.ToPacket()
	// イーサネットヘッダに送信するパケットをつなげる
	ethHeaderPacket = append(ethHeaderPacket, packet...)
	// ネットワークデバイスに送信する
	err := netdev.netDeviceTransmit(ethHeaderPacket)
	if err != nil {
		log.Fatalf("netDeviceTransmit is err : %v", err)
	}
}

// ネットデバイスの送信処理
func (netDev netDevice) netDeviceTransmit(data []byte) error {
	err := syscall.Sendto(netDev.socket, data, 0, &netDev.sockAddr)
	if err != nil {
		return err
	}
	return nil
}

func macToByte(macaddr [6]uint8) (b []byte) {
	for _, v := range macaddr {
		b = append(b, v)
	}
	return b
}
