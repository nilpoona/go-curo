package main

func (node *radixTreeNode) radixTreeAdd(prefixIpAddr, prefixLen uint32, entryData ipRouteEntry) {
	// ルートノードから辿る
	current := node
	// 枝を辿る
	for i := 1; i <= int(prefixLen); i++ {
		if prefixIpAddr>>(32-i)&0x01 == 1 { // 上からiビット目が1なら
			if current.node1 == nil {
				current.node1 = &radixTreeNode{
					parent: current,
					depth:  i,
					value:  0,
				}
			}
			current = current.node1
		} else { // 上からiビット目が0なら
			// 辿る先の枝がなかったら作る
			if current.node0 == nil {
				current.node0 = &radixTreeNode{
					parent: current,
					depth:  i,
					value:  0,
				}
			}
			current = current.node0
		}
	}
	// 最後にデータをセット
	current.data = entryData
}
