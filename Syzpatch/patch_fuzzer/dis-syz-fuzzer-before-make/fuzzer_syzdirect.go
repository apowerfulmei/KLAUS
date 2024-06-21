// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

type Fuzzer struct {
	name              string
	outputType        OutputType
	config            *ipc.Config
	execOpts          *ipc.ExecOpts
	procs             []*Proc
	gate              *ipc.Gate
	workQueue         *WorkQueue
	needPoll          chan struct{}
	choiceTable       *prog.ChoiceTable
	stats             [StatCount]uint64
	extStats          [ExtStatCount]uint64
	callStats         map[string]uint64
	callStatsMu       sync.Mutex
	manager           *rpctype.RPCClient
	target            *prog.Target
	triagedCandidates uint32
	timeouts          targets.Timeouts

	faultInjectionEnabled    bool
	comparisonTracingEnabled bool
	fetchRawCover            bool

	corpusMu     sync.RWMutex
	corpus       []*prog.Prog
	corpusHashes map[hash.Sig]struct{}
	// corpusPrios  []int64
	// 	sumPrios      int64
	sumPrios      int64
	distanceGroup map[uint32]uint32 // distance -> # program in this distance

	signalMu     sync.RWMutex
	corpusSignal signal.Signal // signal of inputs in corpus
	maxSignal    signal.Signal // max signal ever observed including flakes
	newSignal    signal.Signal // diff of maxSignal since last sync with master

	checkResult *rpctype.CheckArgs
	logMu       sync.Mutex

	distMu      sync.Mutex
	minDistance uint32
	maxDistance uint32
	hitLog      prog.GlobalHitLog
	startTime   time.Time
	canLog      bool
}

type FuzzerSnapshot struct {
	corpus        []*prog.Prog
	distanceGroup map[uint32]uint32
}

type Stat int

const (
	StatGenerate Stat = iota
	StatFuzz
	StatCandidate
	StatTriage
	StatMinimize
	StatSmash
	StatFISmash
	StatHint
	StatSeed
	StatCollide
	StatCount
)

var statNames = [StatCount]string{
	StatGenerate:  "exec gen",
	StatFuzz:      "exec fuzz",
	StatCandidate: "exec candidate",
	StatTriage:    "exec triage",
	StatMinimize:  "exec minimize",
	StatSmash:     "exec smash",
	StatFISmash:   "exec fail smash",
	StatHint:      "exec hints",
	StatSeed:      "exec seeds",
	StatCollide:   "exec collide",
}

type ExtStat int

const (
	ExtAllDist ExtStat = iota
	ExtProgCount
	ExtHintCompsCount
	ExtHintCompsSum
	ExtStatCount
)

var extStatNames = [ExtStatCount]string{
	ExtAllDist:        "all dist",
	ExtProgCount:      "prog count",
	ExtHintCompsCount: "hint comps count",
	ExtHintCompsSum:   "hint comps sum",
}

type OutputType int

const (
	OutputNone OutputType = iota
	OutputStdout
	OutputDmesg
	OutputFile
)

func createIPCConfig(features *host.Features, config *ipc.Config) {
	if features[host.FeatureExtraCoverage].Enabled {
		config.Flags |= ipc.FlagExtraCover
	}
	if features[host.FeatureDelayKcovMmap].Enabled {
		config.Flags |= ipc.FlagDelayKcovMmap
	}
	if features[host.FeatureNetInjection].Enabled {
		config.Flags |= ipc.FlagEnableTun
	}
	if features[host.FeatureNetDevices].Enabled {
		config.Flags |= ipc.FlagEnableNetDev
	}
	config.Flags |= ipc.FlagEnableNetReset
	config.Flags |= ipc.FlagEnableCgroups
	config.Flags |= ipc.FlagEnableCloseFds
	if features[host.FeatureDevlinkPCI].Enabled {
		config.Flags |= ipc.FlagEnableDevlinkPCI
	}
	if features[host.FeatureVhciInjection].Enabled {
		config.Flags |= ipc.FlagEnableVhciInjection
	}
	if features[host.FeatureWifiEmulation].Enabled {
		config.Flags |= ipc.FlagEnableWifi
	}
}

// nolint: funlen
func main() {
	debug.SetGCPercent(50)

	var (
		flagName     = flag.String("name", "test", "unique name for manager")
		flagOS       = flag.String("os", runtime.GOOS, "target OS")
		flagArch     = flag.String("arch", runtime.GOARCH, "target arch")
		flagManager  = flag.String("manager", "", "manager rpc address")
		flagProcs    = flag.Int("procs", 1, "number of parallel test processes")
		flagOutput   = flag.String("output", "stdout", "write programs to none/stdout/dmesg/file")
		flagTest     = flag.Bool("test", false, "enable image testing mode")      // used by syz-ci
		flagRunTest  = flag.Bool("runtest", false, "enable program testing mode") // used by pkg/runtest
		flagRawCover = flag.Bool("raw_cover", false, "fetch raw coverage")
	)
	defer tool.Init()()
	outputType := parseOutputType(*flagOutput)
	log.Logf(0, "fuzzer started")

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatalf("%v", err)
	}

	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		log.Fatalf("failed to create default ipc config: %v", err)
	}
	if *flagRawCover {
		execOpts.Flags &^= ipc.FlagDedupCover
	}
	timeouts := config.Timeouts
	sandbox := ipc.FlagsToSandbox(config.Flags)
	shutdown := make(chan struct{})
	osutil.HandleInterrupts(shutdown)
	go func() {
		// Handles graceful preemption on GCE.
		<-shutdown
		log.Logf(0, "SYZ-FUZZER: PREEMPTED")
		os.Exit(1)
	}()

	checkArgs := &checkArgs{
		target:         target,
		sandbox:        sandbox,
		ipcConfig:      config,
		ipcExecOpts:    execOpts,
		gitRevision:    prog.GitRevision,
		targetRevision: target.Revision,
	}
	if *flagTest {
		testImage(*flagManager, checkArgs)
		return
	}

	machineInfo, modules := collectMachineInfos(target)

	log.Logf(0, "dialing manager at %v", *flagManager)
	manager, err := rpctype.NewRPCClient(*flagManager, timeouts.Scale)
	if err != nil {
		log.Fatalf("failed to connect to manager: %v ", err)
	}

	log.Logf(1, "connecting to manager...")
	a := &rpctype.ConnectArgs{
		Name:        *flagName,
		MachineInfo: machineInfo,
		Modules:     modules,
	}
	r := &rpctype.ConnectRes{}
	if err := manager.Call("Manager.Connect", a, r); err != nil {
		log.Fatalf("failed to connect to manager: %v ", err)
	}
	featureFlags, err := csource.ParseFeaturesFlags("none", "none", true)
	if err != nil {
		log.Fatal(err)
	}
	if r.CoverFilterBitmap != nil {
		if err := osutil.WriteFile("syz-cover-bitmap", r.CoverFilterBitmap); err != nil {
			log.Fatalf("failed to write syz-cover-bitmap: %v", err)
		}
	}
	var includedCalls map[int]map[int]bool
	isUnit := false
	if r.CheckResult == nil {
		isUnit = true
		checkArgs.gitRevision = r.GitRevision
		checkArgs.targetRevision = r.TargetRevision
		checkArgs.enabledCalls = r.EnabledCalls
		checkArgs.allSandboxes = r.AllSandboxes
		checkArgs.featureFlags = featureFlags
		r.CheckResult, err = checkMachine(checkArgs)
		if err != nil {
			if r.CheckResult == nil {
				r.CheckResult = new(rpctype.CheckArgs)
			}
			r.CheckResult.Error = err.Error()
		}
		r.CheckResult.Name = *flagName
		if err := manager.Call("Manager.Check", r.CheckResult, &includedCalls); err != nil {
			log.Fatalf("Manager.Check call failed: %v", err)
		}
		if r.CheckResult.Error != "" {
			log.Fatalf("%v", r.CheckResult.Error)
		}
	} else {
		target.UpdateGlobs(r.CheckResult.GlobFiles)
		if err = host.Setup(target, r.CheckResult.Features, featureFlags, config.Executor); err != nil {
			log.Fatal(err)
		}
	}
	log.Logf(0, "syscalls: %v", len(r.CheckResult.EnabledCalls[sandbox]))
	for _, feat := range r.CheckResult.Features.Supported() {
		log.Logf(0, "%v: %v", feat.Name, feat.Reason)
	}
	createIPCConfig(r.CheckResult.Features, config)

	if *flagRunTest {
		runTest(target, manager, *flagName, config.Executor)
		return
	}

	needPoll := make(chan struct{}, 1)
	needPoll <- struct{}{}
	fuzzer := &Fuzzer{
		name:                     *flagName,
		outputType:               outputType,
		config:                   config,
		execOpts:                 execOpts,
		workQueue:                newWorkQueue(*flagProcs, needPoll),
		needPoll:                 needPoll,
		manager:                  manager,
		target:                   target,
		timeouts:                 timeouts,
		faultInjectionEnabled:    r.CheckResult.Features[host.FeatureFault].Enabled,
		comparisonTracingEnabled: r.CheckResult.Features[host.FeatureComparisons].Enabled,
		corpusHashes:             make(map[hash.Sig]struct{}),
		checkResult:              r.CheckResult,
		fetchRawCover:            *flagRawCover,
		minDistance:              prog.MaxDist,
		maxDistance:              0,
		hitLog:                   make(prog.GlobalHitLog),
		startTime:                time.Now().Add(-r.RunTime),
		callStats:                make(map[string]uint64),
		distanceGroup:            make(map[uint32]uint32),
	}
	gateCallback := fuzzer.useBugFrames(r, *flagProcs)
	fuzzer.gate = ipc.NewGate(2**flagProcs, gateCallback)

	for needCandidates, more := true, true; more; needCandidates = false {
		more = fuzzer.poll(needCandidates, nil)
		// This loop lead to "no output" in qemu emulation, tell manager we are not dead.
		log.Logf(0, "fetching corpus: %v, signal %v/%v (executing program)",
			len(fuzzer.corpus), len(fuzzer.corpusSignal), len(fuzzer.maxSignal))
	}
	calls := make(map[*prog.Syscall]bool)
	for _, id := range r.CheckResult.EnabledCalls[sandbox] {
		calls[target.Syscalls[id]] = true
	}
	fuzzer.choiceTable = target.BuildChoiceTable(fuzzer.corpus, calls)
	fuzzer.choiceTable.EnableGo(r.CallPairMap, r.RpcCallPairMap, fuzzer.corpus, fuzzer.startTime, r.HitIndex)
	for _, p := range fuzzer.corpus {
		p.HasTcall(fuzzer.choiceTable)
	}
	if isUnit && includedCalls == nil {
		log.Fatalf("[syzgo] should note!!!")
	}
	if includedCalls != nil {
		fuzzer.generateCandidateInputInGo(includedCalls)
	}
	if r.CoverFilterBitmap != nil {
		fuzzer.execOpts.Flags |= ipc.FlagEnableCoverageFilter
	}

	log.Logf(0, "starting %v fuzzer processes", *flagProcs)
	for pid := 0; pid < *flagProcs; pid++ {
		proc, err := newProc(fuzzer, pid)
		if err != nil {
			log.Fatalf("failed to create proc: %v", err)
		}
		fuzzer.procs = append(fuzzer.procs, proc)
		go proc.loop()
	}

	fuzzer.pollLoop()
}

func collectMachineInfos(target *prog.Target) ([]byte, []host.KernelModule) {
	machineInfo, err := host.CollectMachineInfo()
	if err != nil {
		log.Fatalf("failed to collect machine information: %v", err)
	}
	modules, err := host.CollectModulesInfo()
	if err != nil {
		log.Fatalf("failed to collect modules info: %v", err)
	}
	return machineInfo, modules
}

// Returns gateCallback for leak checking if enabled.
func (fuzzer *Fuzzer) useBugFrames(r *rpctype.ConnectRes, flagProcs int) func() {
	var gateCallback func()

	if r.CheckResult.Features[host.FeatureLeak].Enabled {
		gateCallback = func() { fuzzer.gateCallback(r.MemoryLeakFrames) }
	}

	if r.CheckResult.Features[host.FeatureKCSAN].Enabled && len(r.DataRaceFrames) != 0 {
		fuzzer.filterDataRaceFrames(r.DataRaceFrames)
	}

	return gateCallback
}

func (fuzzer *Fuzzer) gateCallback(leakFrames []string) {
	// Leak checking is very slow so we don't do it while triaging the corpus
	// (otherwise it takes infinity). When we have presumably triaged the corpus
	// (triagedCandidates == 1), we run leak checking bug ignore the result
	// to flush any previous leaks. After that (triagedCandidates == 2)
	// we do actual leak checking and report leaks.
	triagedCandidates := atomic.LoadUint32(&fuzzer.triagedCandidates)
	if triagedCandidates == 0 {
		return
	}
	args := append([]string{"leak"}, leakFrames...)
	timeout := fuzzer.timeouts.NoOutput * 9 / 10
	output, err := osutil.RunCmd(timeout, "", fuzzer.config.Executor, args...)
	if err != nil && triagedCandidates == 2 {
		// If we exit right away, dying executors will dump lots of garbage to console.
		os.Stdout.Write(output)
		fmt.Printf("BUG: leak checking failed\n")
		time.Sleep(time.Hour)
		os.Exit(1)
	}
	if triagedCandidates == 1 {
		atomic.StoreUint32(&fuzzer.triagedCandidates, 2)
	}
}

func (fuzzer *Fuzzer) filterDataRaceFrames(frames []string) {
	args := append([]string{"setup_kcsan_filterlist"}, frames...)
	timeout := time.Minute * fuzzer.timeouts.Scale
	output, err := osutil.RunCmd(timeout, "", fuzzer.config.Executor, args...)
	if err != nil {
		log.Fatalf("failed to set KCSAN filterlist: %v", err)
	}
	log.Logf(0, "%s", output)
}

func (fuzzer *Fuzzer) pollLoop() {
	var execTotal uint64
	var lastPoll time.Time
	var lastPrint time.Time
	ticker := time.NewTicker(3 * time.Second * fuzzer.timeouts.Scale).C
	for {
		poll := false
		select {
		case <-ticker:
		case <-fuzzer.needPoll:
			poll = true
		}
		if fuzzer.outputType != OutputStdout && time.Since(lastPrint) > 10*time.Second*fuzzer.timeouts.Scale {
			// Keep-alive for manager.
			log.Logf(0, "alive, executed %v", execTotal)
			lastPrint = time.Now()
		}
		if !poll {
			fuzzer.sendHitCountToManager()
		}
		if poll || time.Since(lastPoll) > 10*time.Second*fuzzer.timeouts.Scale {
			needCandidates := fuzzer.workQueue.wantCandidates()
			if poll && !needCandidates {
				continue
			}
			stats := make(map[string]uint64)
			for _, proc := range fuzzer.procs {
				stats["exec total"] += atomic.SwapUint64(&proc.env.StatExecs, 0)
				stats["executor restarts"] += atomic.SwapUint64(&proc.env.StatRestarts, 0)
			}
			for stat := Stat(0); stat < StatCount; stat++ {
				v := atomic.SwapUint64(&fuzzer.stats[stat], 0)
				stats[statNames[stat]] = v
				execTotal += v
			}
			for estat := ExtStat(0); estat < ExtStatCount; estat++ {
				v := atomic.SwapUint64(&fuzzer.extStats[estat], 0)
				stats[extStatNames[estat]] = v
			}

			fuzzer.callStatsMu.Lock()
			tmp := fuzzer.callStats
			fuzzer.callStats = make(map[string]uint64)
			fuzzer.callStatsMu.Unlock()
			for callName, callTime := range tmp {
				stats[callName] = callTime
			}
			if !fuzzer.poll(needCandidates, stats) {
				lastPoll = time.Now()
			}
		}
	}
}

func (fuzzer *Fuzzer) poll(needCandidates bool, stats map[string]uint64) bool {
	tqs, sqs, cqs := fuzzer.workQueue.getSize()
	a := &rpctype.PollArgs{
		Name:               fuzzer.name,
		NeedCandidates:     needCandidates,
		MaxSignal:          fuzzer.grabNewSignal().Serialize(),
		Stats:              stats,
		TriageQueueSize:    tqs,
		SmashQueueSize:     sqs,
		CandidateQueueSize: cqs,
	}
	r := &rpctype.PollRes{}
	if err := fuzzer.manager.Call("Manager.Poll", a, r); err != nil {
		log.Fatalf("Manager.Poll call failed: %v", err)
	}
	maxSignal := r.MaxSignal.Deserialize()
	log.Logf(1, "poll: candidates=%v inputs=%v signal=%v",
		len(r.Candidates), len(r.NewInputs), maxSignal.Len())
	fuzzer.addMaxSignal(maxSignal)
	for _, inp := range r.NewInputs {
		fuzzer.addInputFromAnotherFuzzer(inp)
	}
	for _, candidate := range r.Candidates {
		fuzzer.addCandidateInput(candidate)
	}
	if needCandidates && len(r.Candidates) == 0 && atomic.LoadUint32(&fuzzer.triagedCandidates) == 0 {
		atomic.StoreUint32(&fuzzer.triagedCandidates, 1)
	}
	return len(r.NewInputs) != 0 || len(r.Candidates) != 0 || maxSignal.Len() != 0
}

func (fuzzer *Fuzzer) sendInputToManager(inp rpctype.Input) {
	a := &rpctype.NewInputArgs{
		Name:  fuzzer.name,
		Input: inp,
	}
	if err := fuzzer.manager.Call("Manager.NewInput", a, nil); err != nil {
		log.Fatalf("Manager.NewInput call failed: %v", err)
	}
}

//当有新的program被添加到corups中时，需要根据实际情况，更新fuzzer的语料库中的最大和最小距离
func (fuzzer *Fuzzer) updateExtremeDist(dist uint32) {
	if dist != prog.InvalidDist {
		if fuzzer.minDistance > dist {
			fuzzer.minDistance = dist
		}
		if fuzzer.maxDistance < dist {
			fuzzer.maxDistance = dist
		}
		fuzzer.distanceGroup[dist] += 1
	}
}

func (fuzzer *Fuzzer) readExtremeDist() (uint32, uint32) {
	fuzzer.distMu.Lock()
	defer fuzzer.distMu.Unlock()
	return fuzzer.maxDistance, fuzzer.minDistance
}

func (fuzzer *Fuzzer) handleHitCount(progHitCounts prog.ProgHitCounts, p *prog.Prog) {
	if len(progHitCounts) == 0 {
		return
	}
	fuzzer.distMu.Lock()
	defer fuzzer.distMu.Unlock()
	var rawProg []byte
	if !fuzzer.canLog {
		fuzzer.canLog = time.Since(fuzzer.startTime) > 20*time.Minute
	}
	for hitIdx, progHitItem := range progHitCounts {
		item, ok := fuzzer.hitLog[hitIdx]
		item.Count += progHitItem.Count
		if !ok && fuzzer.canLog {
			if rawProg == nil {
				rawProg = p.Serialize()
			}
			item.Progs = append(item.Progs, string(rawProg))
			item.HitCalls = append(item.HitCalls, progHitItem.CallIds...)
		}
		fuzzer.hitLog[hitIdx] = item
	}

}

func (fuzzer *Fuzzer) sendHitCountToManager() {
	fuzzer.distMu.Lock()
	tmp := make(prog.GlobalHitLog, len(fuzzer.hitLog))
	for hitIdx, item := range fuzzer.hitLog {
		if item.Count != 0 {
			tmp[hitIdx] = item
			item.Count = 0
			item.Progs = nil
			item.HitCalls = nil
			fuzzer.hitLog[hitIdx] = item
		}
	}
	fuzzer.distMu.Unlock()
	if len(tmp) == 0 {
		return
	}
	a := &rpctype.HitCountArgs{
		HitLog: tmp,
	}
	if err := fuzzer.manager.Call("Manager.LogHitCount", a, nil); err != nil {
		log.Fatalf("Manager.NewInput call failed: %v", err)
	}
}

func (fuzzer *Fuzzer) addInputFromAnotherFuzzer(inp rpctype.Input) {
	p := fuzzer.deserializeInput(inp.Prog)
	if p == nil {
		return
	}
	p.Dist = inp.Dist
	sig := hash.Hash(inp.Prog)
	sign := inp.Signal.Deserialize()
	fuzzer.addInputToCorpus(p, sign, sig)
}

func (fuzzer *Fuzzer) addCandidateInput(candidate rpctype.Candidate) {
	p := fuzzer.deserializeInput(candidate.Prog)
	if p == nil {
		return
	}
	flags := ProgCandidate
	if candidate.Minimized {
		flags |= ProgMinimized
	}
	if candidate.Smashed {
		flags |= ProgSmashed
	}
	fuzzer.workQueue.enqueue(&WorkCandidate{
		p:     p,
		flags: flags,
	})
}

func (fuzzer *Fuzzer) generateCandidateInputInGo(includedCalls map[int]map[int]bool) {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	progs := fuzzer.target.MultiGenerateInGo(rnd, fuzzer.choiceTable, includedCalls)
	for _, p := range progs {
		fuzzer.workQueue.enqueue(&WorkCandidate{
			p:     p,
			flags: ProgCandidate,
		})
	}
}

func (fuzzer *Fuzzer) deserializeInput(inp []byte) *prog.Prog {
	p, err := fuzzer.target.Deserialize(inp, prog.NonStrict)
	if err != nil {
		log.Fatalf("failed to deserialize prog: %v\n%s", err, inp)
	}
	// We build choice table only after we received the initial corpus,
	// so we don't check the initial corpus here, we check it later in BuildChoiceTable.
	if fuzzer.choiceTable != nil {
		fuzzer.checkDisabledCalls(p)
		p.HasTcall(fuzzer.choiceTable)
	}
	if len(p.Calls) > prog.MaxCalls {
		return nil
	}
	return p
}

func (fuzzer *Fuzzer) checkDisabledCalls(p *prog.Prog) {
	for _, call := range p.Calls {
		if !fuzzer.choiceTable.Enabled(call.Meta.ID) {
			fmt.Printf("executing disabled syscall %v [%v]\n", call.Meta.Name, call.Meta.ID)
			sandbox := ipc.FlagsToSandbox(fuzzer.config.Flags)
			fmt.Printf("check result for sandbox=%v:\n", sandbox)
			for _, id := range fuzzer.checkResult.EnabledCalls[sandbox] {
				meta := fuzzer.target.Syscalls[id]
				fmt.Printf("  %v [%v]\n", meta.Name, meta.ID)
			}
			fmt.Printf("choice table:\n")
			for i, meta := range fuzzer.target.Syscalls {
				fmt.Printf("  #%v: %v [%v]: enabled=%v\n", i, meta.Name, meta.ID, fuzzer.choiceTable.Enabled(meta.ID))
			}
			panic("disabled syscall")
		}
	}
}

// 该函数是结构体FuzzerSnapshot的一个方法函数
// 作用是根据距离组中的距离和计数来选择一个程序。根据计数的比例，对距离进行加权，然后根据加权后的优先级随机选择一个程序
func (fuzzer *FuzzerSnapshot) chooseProgram(r *rand.Rand, ct *prog.ChoiceTable) *prog.Prog {
	// 存储距离组中所有种子被执行的总计数
	totalCount := uint32(0)
	// 初始化一个切片 distGroupItems，用于存储距离组中的种子的距离和该种子执行的次数
	// dist代表种子到target的距离
	// count代表该种子被选择的次数
	distGroupItems := make([]struct {
		dist  uint32
		count uint32
	}, 0)
	// 遍历距离组 fuzzer.distanceGroup
	for distance, count := range fuzzer.distanceGroup {
		// 将距离和计数存储到 distGroupItems 中
		distGroupItems = append(distGroupItems, struct {
			dist  uint32
			count uint32
		}{
			dist:  distance,
			count: count,
		})
		// 累加计数到 totalCount 中
		totalCount += count
	}
	// 对 distGroupItems 切片中的元素按照距离进行排序
	sort.Slice(distGroupItems, func(i, j int) bool { return distGroupItems[i].dist < distGroupItems[j].dist })

	//////为计算每个距离的优先级做准备，每个距离的优先级不是单纯取决于距离的大小，还跟种子的执行次数、以及整个distanceGroup相关（计算一个加权，根据该加权决定选择哪一个种子）///////////
	// 假设distanceGroup所有的种子被执行的总次数等于40，那么threeQuarterCount就等于30
	// threeQuarterCount：四分之三计数
	threeQuarterCount := (3 * totalCount / 4)
	// 初始化为最大无符号整数
	// 四分之三距离
	threeQuarterOfDistance := uint32(0xffffffff)
	// 遍历 distGroupItems 切片，找到第一个计数大于等于threeQuarterCount（总计数的四分之三）的距离，并将其赋值给 threeQuarterOfDistance
	for _, item := range distGroupItems {
		if item.count >= threeQuarterCount {
			threeQuarterOfDistance = item.dist
			break
		} else {
			threeQuarterCount -= item.count
		}
	}

	// 初始化总权重为0
	totalWeight := uint32(0)
	// 遍历距离组，计算总权重，权重由小于 threeQuarterOfDistance 的距离计算而来
	for distance := range fuzzer.distanceGroup {
		if distance < threeQuarterOfDistance {
			totalWeight += threeQuarterOfDistance - distance
		}
	}
	////////////////////////////////////////////////////////////
	// 如果 totalWeight 为 0，则随机选择语料库中的一个程序并返回
	if totalWeight == 0 {
		randIdx := r.Intn(len(fuzzer.corpus))
		return fuzzer.corpus[randIdx]
	}
	// 初始化 sumPrios 为 0
	// sumPrios 是 FuzzerSnapshot 结构体中的一个属性，表示所有程序的优先级之和
	sumPrios := uint32(0)
	// 创建一个 prioMap切片，用于存储距离和对应的优先级
	prioMap := make(map[uint32]uint32, len(fuzzer.distanceGroup))
	// 遍历距离组，计算优先级，并将优先级乘以对应的计数累加到 sumPrios 中，同时将计算的优先级（每个距离的优先级）存储到 prioMap 中
	// 这里证明优先级不是距离的线性关系，而是经过一个特征处理，即:prio := (threeQuarterOfDistance - distance) * 1000 / totalWeight
	for distance, count := range fuzzer.distanceGroup {
		if distance < threeQuarterOfDistance {
			prio := (threeQuarterOfDistance - distance) * 1000 / totalWeight
			sumPrios += prio * count
			prioMap[distance] = prio
		}
	}
	// 生成一个随机值 randVal，范围在 [0, sumPrios) 之间
	randVal := uint32(r.Int63n(int64(sumPrios)))
	// 遍历语料库中的程序，根据优先级选择一个程序并返回
	for _, p := range fuzzer.corpus {
		if p.Dist < threeQuarterOfDistance {
			currPrio := prioMap[p.Dist]
			if currPrio > randVal {
				return p
			}
			randVal -= currPrio
		}
	}
	// 如果在遍历过程中未选择到程序，则输出错误信息并终止程序运行
	log.Fatalf("select error ??????")
	return nil
}

func (fuzzer *Fuzzer) addInputToCorpus(p *prog.Prog, sign signal.Signal, sig hash.Sig) {
	fuzzer.corpusMu.Lock()
	fuzzer.updateExtremeDist(p.Dist)
	if _, ok := fuzzer.corpusHashes[sig]; !ok {
		fuzzer.corpus = append(fuzzer.corpus, p)
		fuzzer.corpusHashes[sig] = struct{}{}
		// //声明变量 prio表示优先级，并将其初始化为整数类型的 1
		// prio := int64(1)
		// //如果 sign 为空或者 p.Dist 等于 prog.InvalidDist，则将 prio 设置为 0
		// if sign.Empty() || p.Dist == prog.InvalidDist {
		// 	prio = 0
		// }
		// //如果 p.Dist 小于 3450，会根据一定的计算公式重新设置 prio 的值
		// else if p.Dist < 3450 {
		// 	prio += int64(900 * math.Exp(float64(p.Dist)*-0.003))
		// }
		// //进一步更新 prio 的值
		// 如果 sign 不为空且 p.Dist 不等于 prog.InvalidDist，则会根据另一种计算方式重新设置 prio 的值
		// if !sign.Empty() && p.Dist != prog.InvalidDist {
		// 	prio = int64(prog.MaxDist-p.Dist) * 50
		// }
		// 将计算得到的 prio 添加到 fuzzer 结构体中的 sumPrios 中，并将 sumPrios 添加到 corpusPrios 切片中
		// fuzzer.sumPrios += prio
		// fuzzer.corpusPrios = append(fuzzer.corpusPrios, fuzzer.sumPrios)
	}
	fuzzer.corpusMu.Unlock()

	if !sign.Empty() {
		fuzzer.signalMu.Lock()
		fuzzer.corpusSignal.Merge(sign)
		fuzzer.maxSignal.Merge(sign)
		fuzzer.signalMu.Unlock()
	}
}

func (fuzzer *Fuzzer) snapshot() FuzzerSnapshot {
	fuzzer.corpusMu.RLock()
	tmpGroup := make(map[uint32]uint32, len(fuzzer.distanceGroup))
	for distance, count := range fuzzer.distanceGroup {
		tmpGroup[distance] = count
	}
	fuzzer.corpusMu.RUnlock()
	return FuzzerSnapshot{fuzzer.corpus, tmpGroup}
}

func (fuzzer *Fuzzer) addMaxSignal(sign signal.Signal) {
	if sign.Len() == 0 {
		return
	}
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	fuzzer.maxSignal.Merge(sign)
}

func (fuzzer *Fuzzer) grabNewSignal() signal.Signal {
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	sign := fuzzer.newSignal
	if sign.Empty() {
		return nil
	}
	fuzzer.newSignal = nil
	return sign
}

func (fuzzer *Fuzzer) corpusSignalDiff(sign signal.Signal) signal.Signal {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	return fuzzer.corpusSignal.Diff(sign)
}

func (fuzzer *Fuzzer) checkNewSignal(p *prog.Prog, info *ipc.ProgInfo) (calls []int, extra bool) {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	for i, inf := range info.Calls {
		if fuzzer.checkNewCallSignal(p, &inf, i) {
			calls = append(calls, i)
		}
	}
	extra = fuzzer.checkNewCallSignal(p, &info.Extra, -1)
	return
}

func (fuzzer *Fuzzer) checkNewCallSignal(p *prog.Prog, info *ipc.CallInfo, call int) bool {
	diff := fuzzer.maxSignal.DiffRaw(info.Signal, signalPrio(p, info, call))
	if diff.Empty() {
		return false
	}
	fuzzer.signalMu.RUnlock()
	fuzzer.signalMu.Lock()
	fuzzer.maxSignal.Merge(diff)
	fuzzer.newSignal.Merge(diff)
	fuzzer.signalMu.Unlock()
	fuzzer.signalMu.RLock()
	return true
}

func signalPrio(p *prog.Prog, info *ipc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Errno == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

func parseOutputType(str string) OutputType {
	switch str {
	case "none":
		return OutputNone
	case "stdout":
		return OutputStdout
	case "dmesg":
		return OutputDmesg
	case "file":
		return OutputFile
	default:
		log.Fatalf("-output flag must be one of none/stdout/dmesg/file")
		return OutputNone
	}
}
