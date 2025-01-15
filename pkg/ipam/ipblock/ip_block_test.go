package ipblock

import (
	"fmt"
	"testing"

	"github.com/yowenter/claude-ipam/pkg/utils"
)

func TestAllocateSubnet(t *testing.T) {
	ipblockAllocator, err := NewIPBlockAllocator("172.10.0.0/16", 24, "0.0.0.0")
	if err != nil {
		panic(err)
	}
	for i := 0; i < 255; i++ {
		subn, err := ipblockAllocator.Allocate(fmt.Sprintf("node-%d", i))
		if err != nil {
			panic(err)
		}
		size, _ := subn.Mask.Size()
		fmt.Println(i, subn.IP.To4().String(), size)
	}
}

func TestAllocateSubnetReload(t *testing.T) {
	ipblockAllocator, err := NewIPBlockAllocator("172.10.0.0/16", 26, "0.0.0.0")
	if err != nil {
		panic(err)
	}
	for i := 0; i < 3; i++ {
		subn, err := ipblockAllocator.Allocate(fmt.Sprintf("node-%d", i))
		if err != nil {
			panic(err)
		}
		size, _ := subn.Mask.Size()
		f, l := utils.GetFirstAndLastIP(*subn)
		fmt.Println(subn.String(), size, f, l)
	}
	ipblockAllocator.subnetSize = 24

	for i := 0; i < 3; i++ {
		subn, err := ipblockAllocator.Allocate(fmt.Sprintf("node-2-%d", i))
		if err != nil {
			panic(err)
		}
		size, _ := subn.Mask.Size()
		f, l := utils.GetFirstAndLastIP(*subn)
		fmt.Println(subn.String(), size, f, l)
	}

	ipblockAllocator.subnetSize = 26
	for i := 0; i < 3; i++ {
		subn, err := ipblockAllocator.Allocate(fmt.Sprintf("node-3-%d", i))
		if err != nil {
			panic(err)
		}
		size, _ := subn.Mask.Size()
		f, l := utils.GetFirstAndLastIP(*subn)
		fmt.Println(subn.String(), size, f, l)
	}
	fmt.Println(ipblockAllocator.allocatedNets, ipblockAllocator.hostAllocatedNets)

}
