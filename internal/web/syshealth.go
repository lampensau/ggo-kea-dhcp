package web

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"ggo-kea-dhcp/internal/db"
	"ggo-kea-dhcp/internal/web/views"
)

// System-health thresholds (percent), per dimension. The header indicator shows
// the worst of CPU / memory / storage: warn at >= 80, error at >= 92.
const (
	sysHealthWarnPct = 80
	sysHealthErrPct  = 92
)

// sysHealthStore holds the latest CPU/memory/storage utilization, sampled by the
// always-on metrics sampler (every metricsSampleInterval). cgo-free: CPU from two
// reads of /proc/stat, memory from /proc/meminfo, storage from statfs on the DB
// filesystem. In-memory only - it is a live gauge, not history.
type sysHealthStore struct {
	mu        sync.RWMutex
	cpuPct    int
	memPct    int
	diskPct   int
	available bool // false until the first usable reading (CPU needs two samples)
	// prevIdle/prevTotal are the previous /proc/stat jiffy counters for the CPU
	// delta; primed is false until the first sample seeds them.
	prevIdle  uint64
	prevTotal uint64
	primed    bool
	diskPath  string // filesystem to statfs (the SQLite DB's directory)
}

func newSysHealthStore(dbPath string) *sysHealthStore {
	path := filepath.Dir(dbPath)
	if path == "" || path == "." {
		path = "/"
	}
	return &sysHealthStore{diskPath: path}
}

// sample takes one reading. CPU needs two readings to produce a busy% from the
// jiffy delta, so the first call only seeds the counters (available stays false
// until the second). Any read failure marks the store unavailable, so the header
// indicator renders nothing (graceful off-Pi or under a restricted /proc).
func (st *sysHealthStore) sample() {
	cpuIdle, cpuTotal, cpuOK := readCPUJiffies()
	memPct, memOK := readMemUsedPct()
	diskPct, diskOK := readDiskUsedPct(st.diskPath)

	st.mu.Lock()
	defer st.mu.Unlock()

	if !cpuOK || !memOK || !diskOK {
		st.available = false
		return
	}

	seeded := st.primed
	if seeded && cpuTotal > st.prevTotal {
		dTotal := cpuTotal - st.prevTotal
		dIdle := cpuIdle - st.prevIdle
		if dIdle > dTotal {
			dIdle = dTotal
		}
		st.cpuPct = clampPercent(int((dTotal - dIdle) * 100 / dTotal))
	}
	st.prevIdle, st.prevTotal, st.primed = cpuIdle, cpuTotal, true
	st.memPct = clampPercent(memPct)
	st.diskPct = clampPercent(diskPct)
	st.available = seeded
}

// read returns the latest utilization and whether it is usable yet.
func (st *sysHealthStore) read() (cpu, mem, disk int, ok bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.cpuPct, st.memPct, st.diskPct, st.available
}

// buildSysHealthView assembles the header indicator's view model. It renders only
// when ACTIVE (the CPU chip is meaningless before a profile is applied) and the
// sampler has a usable reading; otherwise Show is false and the indicator is empty.
func (s *Server) buildSysHealthView(state string) views.SysHealthView {
	if state != db.StateActive || s.sysHealth == nil {
		return views.SysHealthView{}
	}
	cpu, mem, disk, ok := s.sysHealth.read()
	if !ok {
		return views.SysHealthView{}
	}
	return views.SysHealthView{
		Show:     true,
		Severity: sysHealthSeverity(cpu, mem, disk),
		CPU:      cpu,
		Mem:      mem,
		Disk:     disk,
	}
}

// sysHealthSeverity is the worst of the three dimensions: "err" if any is at the
// error threshold, "warn" if any is at the warn threshold, else "ok".
func sysHealthSeverity(cpu, mem, disk int) string {
	worst := cpu
	for _, v := range []int{mem, disk} {
		if v > worst {
			worst = v
		}
	}
	switch {
	case worst >= sysHealthErrPct:
		return "err"
	case worst >= sysHealthWarnPct:
		return "warn"
	default:
		return "ok"
	}
}

func clampPercent(p int) int {
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return p
}

// readCPUJiffies parses the aggregate "cpu" line of /proc/stat, returning the idle
// jiffies (idle+iowait) and the total across all fields. ok is false if the line
// can't be read/parsed.
func readCPUJiffies() (idle, total uint64, ok bool) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return 0, 0, false
	}
	fields := strings.Fields(sc.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, false
	}
	for i, v := range fields[1:] {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		total += n
		// Field order: user nice system idle iowait irq softirq steal ...
		// idle is index 3, iowait index 4 (both relative to fields[1:]).
		if i == 3 || i == 4 {
			idle += n
		}
	}
	return idle, total, true
}

// readMemUsedPct parses /proc/meminfo and returns used memory as a percentage of
// total, where used = MemTotal - MemAvailable (the kernel's own headroom-aware
// figure, matching what `free`/monitoring tools report).
func readMemUsedPct() (pct int, ok bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	defer f.Close()
	var total, avail uint64
	var haveTotal, haveAvail bool
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			total, haveTotal = parseMeminfoKB(line)
		case strings.HasPrefix(line, "MemAvailable:"):
			avail, haveAvail = parseMeminfoKB(line)
		}
		if haveTotal && haveAvail {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return 0, false
	}
	if !haveTotal || !haveAvail || total == 0 {
		return 0, false
	}
	used := total - avail
	if avail > total {
		used = 0
	}
	return int(used * 100 / total), true
}

// parseMeminfoKB extracts the kB value from a "Key:   12345 kB" /proc/meminfo line.
func parseMeminfoKB(line string) (uint64, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, false
	}
	n, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// readDiskUsedPct returns used storage as a percentage of the usable space on the
// filesystem containing path, df-style: used / (used + available-to-unprivileged),
// so the reserved root blocks don't skew the figure an operator sees.
func readDiskUsedPct(path string) (pct int, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil || st.Blocks == 0 {
		return 0, false
	}
	avail := st.Bavail
	used := st.Blocks - st.Bfree
	denom := used + avail
	if denom == 0 {
		return 0, false
	}
	return int(used * 100 / denom), true
}
