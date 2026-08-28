package service

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/robfig/cron/v3"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

type MonitorService struct {
	DiskIO chan ([]disk.IOCountersStat)
	NetIO  chan ([]net.IOCountersStat)
}

// monitorMu guards monitorCancel and global.MonitorCronID and must be held for
// every mutation of either field. It upholds the state-machine invariant that,
// observed while it is held, a monitor is either fully running (both fields
// set, and set together as one generation) or fully stopped (both cleared) —
// never half of each. All start/stop paths (StartMonitor, stopMonitor and the
// MonitorStatus/MonitorInterval branches in setting.go) rely on this pairing,
// so they stay correct and race-free even when settings are toggled
// concurrently.
var (
	monitorMu     sync.Mutex
	monitorCancel context.CancelFunc
)

type IMonitorService interface {
	Run()

	saveIODataToDB(ctx context.Context, interval float64)
	saveNetDataToDB(ctx context.Context, interval float64)
}

func NewIMonitorService() IMonitorService {
	return &MonitorService{
		DiskIO: make(chan []disk.IOCountersStat, 2),
		NetIO:  make(chan []net.IOCountersStat, 2),
	}
}

func (m *MonitorService) Run() {
	var itemModel model.MonitorBase
	totalPercent, _ := cpu.Percent(3*time.Second, false)
	if len(totalPercent) == 1 {
		itemModel.Cpu = totalPercent[0]
	}
	cpuCount, _ := cpu.Counts(false)

	loadInfo, _ := load.Avg()
	itemModel.CpuLoad1 = loadInfo.Load1
	itemModel.CpuLoad5 = loadInfo.Load5
	itemModel.CpuLoad15 = loadInfo.Load15
	itemModel.LoadUsage = loadInfo.Load1 / (float64(cpuCount*2) * 0.75) * 100

	memoryInfo, _ := mem.VirtualMemory()
	itemModel.Memory = memoryInfo.UsedPercent

	if err := settingRepo.CreateMonitorBase(itemModel); err != nil {
		global.LOG.Errorf("Insert basic monitoring data failed, err: %v", err)
	}

	m.loadDiskIO()
	m.loadNetIO()

	MonitorStoreDays, err := settingRepo.Get(settingRepo.WithByKey("MonitorStoreDays"))
	if err != nil {
		return
	}
	storeDays, _ := strconv.Atoi(MonitorStoreDays.Value)
	timeForDelete := time.Now().AddDate(0, 0, -storeDays)
	_ = settingRepo.DelMonitorBase(timeForDelete)
	_ = settingRepo.DelMonitorIO(timeForDelete)
	_ = settingRepo.DelMonitorNet(timeForDelete)
}

func (m *MonitorService) loadDiskIO() {
	ioStat, _ := disk.IOCounters()
	var diskIOList []disk.IOCountersStat
	for _, io := range ioStat {
		diskIOList = append(diskIOList, io)
	}
	m.DiskIO <- diskIOList
}

func (m *MonitorService) loadNetIO() {
	netStat, _ := net.IOCounters(true)
	netStatAll, _ := net.IOCounters(false)
	var netList []net.IOCountersStat
	netList = append(netList, netStat...)
	netList = append(netList, netStatAll...)
	m.NetIO <- netList
}

func (m *MonitorService) saveIODataToDB(ctx context.Context, interval float64) {
	defer close(m.DiskIO)
	// The monitor may have been stopped between the cron publication and the
	// start of this goroutine, so the context can already be cancelled here.
	// Check before entering the loop: the select below chooses randomly among
	// ready cases, and the channel holds the first buffered sample, so without
	// this pre-check a stopped monitor could still write one round of data.
	select {
	case <-ctx.Done():
		return
	default:
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ioStat := <-m.DiskIO:
			select {
			case <-ctx.Done():
				return
			case ioStat2 := <-m.DiskIO:
				var ioList []model.MonitorIO
				for _, io2 := range ioStat2 {
					for _, io1 := range ioStat {
						if io2.Name == io1.Name {
							var itemIO model.MonitorIO
							itemIO.Name = io1.Name
							if io2.ReadBytes != 0 && io1.ReadBytes != 0 && io2.ReadBytes > io1.ReadBytes {
								itemIO.Read = uint64(float64(io2.ReadBytes-io1.ReadBytes) / interval / 60)
							}
							if io2.WriteBytes != 0 && io1.WriteBytes != 0 && io2.WriteBytes > io1.WriteBytes {
								itemIO.Write = uint64(float64(io2.WriteBytes-io1.WriteBytes) / interval / 60)
							}

							if io2.ReadCount != 0 && io1.ReadCount != 0 && io2.ReadCount > io1.ReadCount {
								itemIO.Count = uint64(float64(io2.ReadCount-io1.ReadCount) / interval / 60)
							}
							writeCount := uint64(0)
							if io2.WriteCount != 0 && io1.WriteCount != 0 && io2.WriteCount > io1.WriteCount {
								writeCount = uint64(float64(io2.WriteCount-io1.WriteCount) / interval * 60)
							}
							if writeCount > itemIO.Count {
								itemIO.Count = writeCount
							}

							if io2.ReadTime != 0 && io1.ReadTime != 0 && io2.ReadTime > io1.ReadTime {
								itemIO.Time = uint64(float64(io2.ReadTime-io1.ReadTime) / interval / 60)
							}
							writeTime := uint64(0)
							if io2.WriteTime != 0 && io1.WriteTime != 0 && io2.WriteTime > io1.WriteTime {
								writeTime = uint64(float64(io2.WriteTime-io1.WriteTime) / interval / 60)
							}
							if writeTime > itemIO.Time {
								itemIO.Time = writeTime
							}
							ioList = append(ioList, itemIO)
							break
						}
					}
				}
				if err := settingRepo.BatchCreateMonitorIO(ioList); err != nil {
					global.LOG.Errorf("Insert io monitoring data failed, err: %v", err)
				}
				m.DiskIO <- ioStat2
			}
		}
	}
}

func (m *MonitorService) saveNetDataToDB(ctx context.Context, interval float64) {
	defer close(m.NetIO)
	// Same pre-cancel check as saveIODataToDB: a context that is already done
	// at goroutine start must lead to an immediate exit, not to one final
	// sample being written for a stopped monitor.
	select {
	case <-ctx.Done():
		return
	default:
	}
	for {
		select {
		case <-ctx.Done():
			return
		case netStat := <-m.NetIO:
			select {
			case <-ctx.Done():
				return
			case netStat2 := <-m.NetIO:
				var netList []model.MonitorNetwork
				for _, net2 := range netStat2 {
					for _, net1 := range netStat {
						if net2.Name == net1.Name {
							var itemNet model.MonitorNetwork
							itemNet.Name = net1.Name

							if net2.BytesSent != 0 && net1.BytesSent != 0 && net2.BytesSent > net1.BytesSent {
								itemNet.Up = float64(net2.BytesSent-net1.BytesSent) / 1024 / interval / 60
							}
							if net2.BytesRecv != 0 && net1.BytesRecv != 0 && net2.BytesRecv > net1.BytesRecv {
								itemNet.Down = float64(net2.BytesRecv-net1.BytesRecv) / 1024 / interval / 60
							}
							netList = append(netList, itemNet)
							break
						}
					}
				}

				if err := settingRepo.BatchCreateMonitorNet(netList); err != nil {
					global.LOG.Errorf("Insert network monitoring data failed, err: %v", err)
				}
				m.NetIO <- netStat2
			}
		}
	}
}

// stopMonitor tears the running monitor down inside a single monitorMu
// critical section: it cancels the collection context and removes the cron
// job. The guarded internals make it a safe no-op when no monitor is running,
// so it may be called concurrently with StartMonitor (a disable racing an
// enable simply orders itself around the atomic publication) and with itself.
func stopMonitor() {
	monitorMu.Lock()
	defer monitorMu.Unlock()
	stopMonitorLocked()
}

// stopMonitorLocked is the monitorMu-held teardown shared by both state
// transitions: the stop path (stopMonitor) and the replace path (startMonitor)
// both clear the current generation through it before anything else is
// published. The guarded clears mean a stopped monitor stays stopped (no
// Remove(0), no nil-cancel call) and the cancel/id pair is always cleared
// together.
func stopMonitorLocked() {
	if monitorCancel != nil {
		monitorCancel()
		monitorCancel = nil
	}
	if global.MonitorCronID != 0 {
		global.Cron.Remove(cron.EntryID(global.MonitorCronID))
		global.MonitorCronID = 0
	}
}

// startMonitor atomically replaces the running monitor with a new generation:
// inside one monitorMu critical section it registers the new cron job, tears
// the previous generation down and publishes global.MonitorCronID and
// monitorCancel together. Publishing the pair under one lock is what keeps the
// state-machine invariant true — while monitorMu is held, a running monitor
// always has exactly its matching cancel and a stopped one has neither — so a
// concurrent stopMonitor can never observe half a generation and leave an
// uncancelled context whose collector goroutines keep writing to the monitor
// DB forever. AddJob runs first so a malformed spec fails without stopping the
// currently running monitor; on any other outcome the old generation is torn
// down before the new one is published.
//
// global.Cron.AddJob is called while monitorMu is held on purpose: robfig/cron
// serializes AddJob/Remove on its own mutex and never invokes a job inline
// (jobs run in their own goroutines), and the monitor job body (Run) does not
// take monitorMu, so no lock cycle is possible.
func startMonitor(service IMonitorService, interval string, cancel context.CancelFunc) error {
	monitorMu.Lock()
	defer monitorMu.Unlock()

	monitorID, err := global.Cron.AddJob(fmt.Sprintf("@every %sm", interval), service)
	if err != nil {
		return err
	}

	stopMonitorLocked()
	global.MonitorCronID = monitorID
	monitorCancel = cancel

	return nil
}

func StartMonitor(removeBefore bool, interval string) error {
	if removeBefore {
		stopMonitor()
	}
	intervalItem, err := strconv.Atoi(interval)
	if err != nil {
		return err
	}

	service := NewIMonitorService()
	ctx, cancel := context.WithCancel(context.Background())
	// startMonitor publishes the cron id and the cancel as one generation; a
	// concurrent stop that lands afterwards wins, and the goroutines started
	// below then see an already-cancelled context and exit immediately.
	if err := startMonitor(service, interval, cancel); err != nil {
		cancel()
		return err
	}

	service.Run()

	go service.saveIODataToDB(ctx, float64(intervalItem))
	go service.saveNetDataToDB(ctx, float64(intervalItem))

	return nil
}
