package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
	"sort"
	"strings"
)

var F = strings.Fields("vpn proxy tor malware c2 scanner brute_force spammer compromised datacenter cdn anycast crawler bot cloud private_relay anonymizer mobile isp government")
var S = [...]float64{30, 25, 45, 95, 95, 55, 70, 65, 75, 15, 5, 0, 10, 40, 10, 15, 35, 0, 0, 0}
var L = [...]struct {
	t float64
	n string
}{{80, "critical"}, {60, "high"}, {35, "medium"}, {15, "low"}}

var le = binary.LittleEndian

type DB struct {
	V4s, V4e, V4m []uint32
	V4v           []uint16
	V6s, V6e, V6m []*big.Int
	V6v           []uint16
	Vt            [][4]uint32
	St            []string
	W             [20]float64
}

func Load(path string) *DB {
	d, _ := os.ReadFile(path)
	if le.Uint32(d) != 6 {
		panic("ver")
	}
	o := make([]int, 19)
	for i := range o {
		o[i] = int(le.Uint64(d[8+i*8:]))
	}
	cn, ln, v6n, valn, strn, off := o[0], o[1], o[2], o[3], o[4], o[5:]
	bi := make([]uint32, 65537)
	for i := range bi {
		bi[i] = le.Uint32(d[off[0]+i*4:])
	}
	N := cn + ln
	v4s, v4e, v4v := make([]uint32, N), make([]uint32, N), make([]uint16, N)
	for b, j := 0, uint32(0); b < 65536; b++ {
		for ; j < bi[b+1]; j++ {
			lo := uint32(le.Uint16(d[off[1]+int(j)*2:]))
			v4s[j] = uint32(b)<<16 | lo
			v4e[j] = v4s[j] + uint32(le.Uint16(d[off[2]+int(j)*2:]))
			v4v[j] = le.Uint16(d[off[3]+int(j)*2:])
		}
	}
	for i := 0; i < ln; i++ {
		v4s[cn+i] = le.Uint32(d[off[4]+i*4:])
		v4e[cn+i] = le.Uint32(d[off[5]+i*4:])
		v4v[cn+i] = le.Uint16(d[off[6]+i*2:])
	}
	idx := make([]int, N)
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return v4s[idx[a]] < v4s[idx[b]] })
	ts, te, tv := make([]uint32, N), make([]uint32, N), make([]uint16, N)
	for i, k := range idx {
		ts[i], te[i], tv[i] = v4s[k], v4e[k], v4v[k]
	}
	v4s, v4e, v4v = ts, te, tv
	v4m := make([]uint32, N)
	var mx uint32
	for i, e := range v4e {
		if e > mx {
			mx = e
		}
		v4m[i] = mx
	}
	r6 := func(o int) []*big.Int {
		r := make([]*big.Int, v6n)
		for i := range r {
			b := make([]byte, 16)
			binary.BigEndian.PutUint64(b[:8], le.Uint64(d[o+i*16+8:]))
			binary.BigEndian.PutUint64(b[8:], le.Uint64(d[o+i*16:]))
			r[i] = new(big.Int).SetBytes(b)
		}
		return r
	}
	v6s, v6e := r6(off[7]), r6(off[8])
	v6v := make([]uint16, v6n)
	for i := range v6v {
		v6v[i] = le.Uint16(d[off[9]+i*2:])
	}
	v6m := make([]*big.Int, v6n)
	m := new(big.Int)
	for i, e := range v6e {
		if e.Cmp(m) > 0 {
			m = e
		}
		v6m[i] = m
	}
	vt := make([][4]uint32, valn)
	for i := range vt {
		for j := 0; j < 4; j++ {
			vt[i][j] = le.Uint32(d[off[10]+(i*4+j)*4:])
		}
	}
	sd := off[12]
	st := make([]string, strn)
	for i := range st {
		so, sl := int(le.Uint32(d[off[11]+i*8:])), int(le.Uint32(d[off[11]+i*8+4:]))
		st[i] = string(d[sd+so : sd+so+sl])
	}
	var w [20]float64
	if N > 0 {
		var c [20]int
		for _, vid := range v4v {
			b := vt[vid][0]
			for i := range F {
				if b&(1<<i) != 0 {
					c[i]++
				}
			}
		}
		for i := range F {
			cc := c[i]
			if cc == 0 {
				cc = 1
			}
			w[i] = S[i] * (1 + math.Log2(float64(N)/float64(cc))/24)
		}
	} else {
		w = S
	}
	return &DB{v4s, v4e, v4m, v4v, v6s, v6e, v6m, v6v, vt, st, w}
}

func r1(x float64) float64 { return math.Round(x*10) / 10 }

type M struct {
	Source   string   `json:"source"`
	Provider string   `json:"provider"`
	Range    string   `json:"range"`
	Flags    []string `json:"flags"`
	Weight   float64  `json:"weight"`
}

func ipFmt(b []byte) string { return net.IP(b).String() }

func Lookup(db *DB, ipStr string) map[string]any {
	addr := net.ParseIP(ipStr)
	matches := []M{}
	push := func(vid uint16, rng string) {
		b := db.Vt[vid][0]
		fl := []string{}
		mxw := 0.0
		for i, f := range F {
			if b&(1<<i) != 0 {
				fl = append(fl, f)
				if db.W[i] > mxw {
					mxw = db.W[i]
				}
			}
		}
		matches = append(matches, M{db.St[db.Vt[vid][2]], db.St[db.Vt[vid][1]], rng, fl, r1(mxw)})
	}
	if a4 := addr.To4(); a4 != nil {
		ip := binary.BigEndian.Uint32(a4)
		i := sort.Search(len(db.V4s), func(k int) bool { return db.V4s[k] > ip })
		for ; i > 0; i-- {
			j := i - 1
			if db.V4m[j] < ip {
				break
			}
			if db.V4e[j] >= ip {
				sb, eb := make([]byte, 4), make([]byte, 4)
				binary.BigEndian.PutUint32(sb, db.V4s[j])
				binary.BigEndian.PutUint32(eb, db.V4e[j])
				push(db.V4v[j], ipFmt(sb)+"-"+ipFmt(eb))
			}
		}
	} else {
		ip := new(big.Int).SetBytes(addr.To16())
		i := sort.Search(len(db.V6s), func(k int) bool { return db.V6s[k].Cmp(ip) > 0 })
		for ; i > 0; i-- {
			j := i - 1
			if db.V6m[j].Cmp(ip) < 0 {
				break
			}
			if db.V6e[j].Cmp(ip) >= 0 {
				sb, eb := make([]byte, 16), make([]byte, 16)
				db.V6s[j].FillBytes(sb)
				db.V6e[j].FillBytes(eb)
				push(db.V6v[j], ipFmt(sb)+"-"+ipFmt(eb))
			}
		}
	}
	sort.SliceStable(matches, func(i, j int) bool { return matches[i].Weight > matches[j].Weight })

	fi := map[string]int{}
	for i, f := range F {
		fi[f] = i
	}
	seen, src := map[string]bool{}, map[string]bool{}
	for _, m := range matches {
		for _, f := range m.Flags {
			seen[f] = true
		}
		src[m.Provider+"|"+m.Source] = true
	}
	ranked := make([]string, 0, len(seen))
	for f := range seen {
		ranked = append(ranked, f)
	}
	sort.SliceStable(ranked, func(i, j int) bool { return db.W[fi[ranked[i]]] > db.W[fi[ranked[j]]] })
	score := 0.0
	if len(ranked) > 0 {
		top, ex := db.W[fi[ranked[0]]], 0.0
		for _, f := range ranked[1:] {
			ex += db.W[fi[f]]
		}
		score = r1(math.Min(100, (top+ex*0.15)*(1+0.08*math.Log2(float64(len(src)+1)))))
	}
	verdict := "clean"
	if len(matches) > 0 {
		verdict = "minimal"
		for _, lv := range L {
			if score >= lv.t {
				verdict = lv.n
				break
			}
		}
	}
	allFlags, providers, sf, sp := []string{}, []string{}, map[string]bool{}, map[string]bool{}
	for _, m := range matches {
		for _, f := range m.Flags {
			if !sf[f] {
				sf[f] = true
				allFlags = append(allFlags, f)
			}
		}
		if m.Provider != "" && !sp[m.Provider] {
			sp[m.Provider] = true
			providers = append(providers, m.Provider)
		}
	}
	for i, p := range providers {
		if strings.EqualFold(p, "tor") {
			providers = append([]string{"Tor"}, append(append([]string{}, providers[:i]...), providers[i+1:]...)...)
			break
		}
	}
	reasons, top := ranked, ""
	if len(reasons) > 5 {
		reasons = reasons[:5]
	}
	if len(providers) > 0 {
		top = providers[0]
	}
	return map[string]any{
		"ip": ipStr, "found": len(matches) > 0, "verdict": verdict, "score": score,
		"detections": len(matches), "sources": len(src), "top_provider": top,
		"providers": providers, "flags": allFlags, "reasons": reasons, "matches": matches,
	}
}

func main() {
	ip := "8.8.8.8"
	if len(os.Args) > 1 {
		ip = os.Args[1]
	}
	b, _ := json.MarshalIndent(Lookup(Load("../intel.bin"), ip), "", "  ")
	fmt.Println(string(b))
}
