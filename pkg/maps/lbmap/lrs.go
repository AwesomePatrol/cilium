package lbmap

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
)

// LoadReportKey4 is the key to LoadReporting4Map.
//
// It must match 'struct lb4_lrs_key' in "bpf/lib/common.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type LoadReportKey4 struct {
	Service Service4Key `align:"svc"`
	Zone    uint8       `align:"zone"`
	Pad     pad3uint8   `align:"pad"`
}

func (k *LoadReportKey4) String() string {
	return fmt.Sprintf("%s[%d]", (&k.Service).String(), k.Zone)
}

func (k *LoadReportKey4) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *LoadReportKey4) NewValue() bpf.MapValue    { return &LoadReportValue4{} }
func (k *LoadReportKey4) Map() *bpf.Map             { return LoadReporting4Map }
func (k *LoadReportKey4) GetAddress() net.IP        { return k.Service.Address.IP() }
func (k *LoadReportKey4) GetPort() uint16           { return k.Service.Port }
func (k *LoadReportKey4) MapDelete() error          { return k.Map().Delete(k.ToNetwork()) }

func (k *LoadReportKey4) ToNetwork() *LoadReportKey4 {
	n := *k
	return &n
}

// ToHost converts LoadReportKey4 to host byte order.
func (k *LoadReportKey4) ToHost() *LoadReportKey4 {
	h := *k
	return &h
}

// LoadReportValue4 must match 'struct lb4_lrs_value' in "bpf/lib/common.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type LoadReportValue4 struct {
	Opened uint32 `align:"opened"`
	Closed uint32 `align:"closed"`
}

func (s *LoadReportValue4) String() string {
	return fmt.Sprintf("+%d -%d", s.Opened, s.Closed)
}

func (s *LoadReportValue4) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(s) }

func (s *LoadReportValue4) ToNetwork() *LoadReportValue4 {
	n := *s
	return &n
}

// ToHost converts LoadReportValue4 to host byte order.
func (s *LoadReportValue4) ToHost() *LoadReportValue4 {
	h := *s
	return &h
}
