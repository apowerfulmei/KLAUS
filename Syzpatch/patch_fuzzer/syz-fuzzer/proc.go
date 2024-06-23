// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"math"
	"math/rand"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

// Proc represents a single fuzzing process (executor).
type Proc struct {
	fuzzer            *Fuzzer
	pid               int
	info              *prog.Mutateinfo
	env               *ipc.Env
	rnd               *rand.Rand
	execOpts          *ipc.ExecOpts
	execOptsCover     *ipc.ExecOpts
	execOptsComps     *ipc.ExecOpts
	execOptsNoCollide *ipc.ExecOpts
	// syzdirect
	// execOptsCollide *ipc.ExecOpts
}

func newProc(fuzzer *Fuzzer, pid int) (*Proc, error) {
	env, err := ipc.MakeEnv(fuzzer.config, pid)
	if err != nil {
		return nil, err
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12))
	waitlist := make([]map[int]int, 0)
	targetlist := make([]map[int]int, 0)
	info := &prog.Mutateinfo{
		Waitlist:   waitlist,
		Targetlist: targetlist,
	}
	execOptsNoCollide := *fuzzer.execOpts
	execOptsNoCollide.Flags &= ^ipc.FlagCollide
	execOptsCover := execOptsNoCollide
	execOptsCover.Flags |= ipc.FlagCollectCover
	execOptsComps := execOptsNoCollide
	execOptsComps.Flags |= ipc.FlagCollectComps
	proc := &Proc{
		fuzzer:            fuzzer,
		pid:               pid,
		env:               env,
		rnd:               rnd,
		info:              info, //yuhang
		execOpts:          fuzzer.execOpts,
		execOptsCover:     &execOptsCover,
		execOptsComps:     &execOptsComps,
		execOptsNoCollide: &execOptsNoCollide,
	}
	return proc, nil
}

func (proc *Proc) loop() {

	generatePeriod := 100
	if proc.fuzzer.config.Flags&ipc.FlagSignal == 0 {
		// If we don't have real coverage signal, generate programs more frequently
		// because fallback signal is weak.
		generatePeriod = 2
	}

	var execMu sync.RWMutex
	var patchMu sync.RWMutex

	// generating progs using the syscalls from the corpus
	if proc.fuzzer.spliceEnabled {
		go func() {
			// let's sleep for 10s waiting for the generation of corpus
			time.Sleep(10 * time.Second)
			var lastGen time.Time
			for {
				if time.Since(lastGen) > 10*time.Second {
					lastGen = time.Now()
					if len(proc.fuzzer.corpusSyscall) < 2 {
						log.Logf(1, "number of corpusSyscall is less than 2")
						continue
					}

					if proc.fuzzer.corpusChoiceTable == nil {
						log.Logf(1, "No choice table!\n")
						continue
					}

					// keep running for 50 iterations
					for i := 0; i < 50; i++ {
						log.Logf(3, "Generating new inputs from corpus")
						proc.fuzzer.ctMu.Lock()
						ct := proc.fuzzer.corpusChoiceTable
						p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
						log.Logf(3, "Generated:\n%s\n", p.Serialize())
						proc.fuzzer.ctMu.Unlock()
						execMu.Lock()
						proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
						execMu.Unlock()
					}
				}
			}
		}()
	}

	for i := 0; ; i++ {
		item := proc.fuzzer.workQueue.dequeue()
		if item != nil {
			switch item := item.(type) {
			case *WorkTriage:
				execMu.Lock()
				proc.triageInput(item)
				execMu.Unlock()
			case *WorkCandidate:
				execMu.Lock()
				proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
				execMu.Unlock()
			case *WorkSmash:
				execMu.Lock()
				proc.smashInput(item)
				execMu.Unlock()
			case *WorkSeed:
				log.Logf(1, "In workseed, sleeping...\n")
				proc.fuzzer.enableCorpusSyscall(item.p)
				go func(item *WorkSeed) {
					for {
						log.Logf(1, "mutating the WorkSeed\n")
						fuzzerSnapshot := proc.fuzzer.snapshot()
						log.Logf(1, "before calls\n")
						log.Logf(1, "getting relationship\n")
						cid, aid, poc := proc.fuzzer.getRelation()
						if cid != -1 && aid != -1 && poc != nil {
							log.Logf(1, "relationship ok! %d, %d, %v", cid, aid, poc)
							p, _, _, _ := proc.fuzzer.deserializeInput(poc)
							proc.info.Targetlist = make([]map[int]int, 0)
							proc.info.Waitlist = make([]map[int]int, 0)
							proc.info.Targetlist = append(proc.info.Targetlist, map[int]int{cid: aid})
							log.Logf(1, "relationship Targetlist: %v\n", proc.info.Targetlist)
							log.Logf(1, "before NewMutate\n")
							p.NewMutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, proc.info, fuzzerSnapshot.corpus, 2, 1)
							log.Logf(1, "#%v: poc mutated: %v\n\n\n", proc.pid, p)
							log.Logf(1, "#%v: poc mutated: %s\n\n\n", proc.pid, p.Serialize())
							execMu.Lock()
							proc.execute(proc.execOpts, p, ProgNormal, StatFuzz)
							execMu.Unlock()
							// FIXME: adjust the timeout here
							time.Sleep(10 * time.Second)
						} else {
							log.Logf(1, "relationship not prepared!")
							if len(item.p.Calls) == 0 {
								panic("Empty WorkSeed!")
							}
							p := item.p.Clone()
							log.Logf(1, "before NewMutate\n")
							p.Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, fuzzerSnapshot.corpus)
							log.Logf(1, "#%v: poc mutated: %v\n\n\n", proc.pid, p)
							log.Logf(1, "#%v: poc mutated: %s\n\n\n", proc.pid, p.Serialize())
							execMu.Lock()
							proc.execute(proc.execOpts, p, ProgNormal, StatFuzz)
							execMu.Unlock()
						}
					}
				}(item)
				go func(item *WorkSeed) {
					patchMu.Lock()
					mark, poc := proc.fuzzer.getRelationBuildingSig()
					patchMu.Unlock()
					for {
						patchMu.Lock()
						mark, poc = proc.fuzzer.getRelationBuildingSig()
						if mark == true {
							break
						}
						patchMu.Unlock()
					}
					for {
						log.Logf(1, "mutating the WorkSeed\n")
						fuzzerSnapshot := proc.fuzzer.snapshot()
						cid, aid, poc2 := proc.fuzzer.getRelation()
						if cid != -1 && aid != -1 && poc2 != nil {
							break
						}
						log.Logf(1, "before calls\n")
						//if len(item.p.Calls) == 0 {
						//	panic("Empty WorkSeed!")
						//}
						log.Logf(1, "before clone\n")
						//for i := 0; i < 10; i++ {
						p, _, _, _ := proc.fuzzer.deserializeInput(poc)
						log.Logf(1, "before NewMutate\n")
						log.Logf(1, "#%v: targetlist size: %d\n", proc.pid, proc.info.Targetlist)
						log.Logf(1, "#%v: waitlist size: %d\n", proc.pid, len(proc.info.Waitlist))
						//p.testMutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable,fuzzerSnapshot.corpus)
						p.NewMutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, proc.info, fuzzerSnapshot.corpus, proc.fuzzer.Ctrlnum, proc.fuzzer.Counter)
						log.Logf(1, "#%v: poc mutated: %v\n\n\n", proc.pid, p)
						log.Logf(1, "#%v: poc mutated: %s\n\n\n", proc.pid, p.Serialize())
						log.Logf(1, "NewMutate ok\n")
						log.Logf(1, "#%v: targetlist size: %d\n", proc.pid, proc.info.Targetlist)
						log.Logf(1, "#%v: waitlist size: %d\n", proc.pid, proc.info.Waitlist)
						//
						execMu.Lock()
						proc.execute_async(proc.execOpts, p, ProgNormal, StatFuzz)
						execMu.Unlock()
					}
					// FIXME: adjust the timeout here
					time.Sleep(10 * time.Second)
					//}
				}(item)

				log.Logf(1, "In workseed, sleeping...\n")
				time.Sleep(2 * time.Second)
			default:
				log.Fatalf("unknown work type: %#v", item)
			}
			continue
		}

		ct := proc.fuzzer.choiceTable
		fuzzerSnapshot := proc.fuzzer.snapshot()
		if len(fuzzerSnapshot.corpus) == 0 || i%generatePeriod == 0 {
			// Generate a new prog.
			log.Logf(1, "Generating new inputs\n")
			p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
			log.Logf(1, "#%v: generated", proc.pid)
			execMu.Lock()
			proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
			execMu.Unlock()
		} else {
			// Mutate an existing prog.
			p := fuzzerSnapshot.chooseProgram(proc.rnd, proc.fuzzer.choiceTable).Clone()
			if p==nil{
				panic("meikai this is not good\n")
			}
			log.Logf(3, "using original mutation")
			p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
			log.Logf(1, "#%v: mutated", proc.pid)
			execMu.Lock()
			proc.execute(proc.execOpts, p, ProgNormal, StatFuzz)
			execMu.Unlock()

		}
	}
}

// for triaging object input, we want to keep the new covered object signal and minimize
// the prog.
// for triaging inputs that have new coverage signal, we want to keep the coverage of object
// signal when minimizing.
func (proc *Proc) triagePatchInput(item *WorkTriage) bool {
	callInfo := item.progInfo.Calls[item.call]
	progDist := item.p.Dist
	callDist := item.info.Dist

	inputSignal := proc.fuzzer.getPatchSignal(item.p, item.progInfo, item.call)
	newSignal := proc.fuzzer.corpusPatchSignalDiff(inputSignal)
	proc.fuzzer.syncRelationBuildingSeed(item.p.Serialize())
	log.Logf(1, "\n\n\n\n******* patchsig : %v\n\n\n\n\n", newSignal)
	if newSignal.Empty() {
		return false
	}
	callName := ".extra"
	logCallName := "extra"
	if item.call != -1 {
		callName = item.p.Calls[item.call].Meta.Name
		logCallName = fmt.Sprintf("call #%v %v", item.call, callName)
	}

	log.Logf(1, "triaging Patch input for %v (new signal=%v)", logCallName, newSignal.Len())
	var inputCover cover.Cover
	const (
		signalRuns       = 3
		minimizeAttempts = 3
	)
	// Compute input coverage and non-flaky signal for minimization.
	notexecuted := 0
	for i := 0; i < signalRuns; i++ {
		info := proc.executeRaw(proc.execOptsCover, item.p, StatTriage)
		if !reexecutionSuccess(info, &callInfo, item.call) {
			// The call was not executed or failed.
			notexecuted++
			if notexecuted > signalRuns/2+1 {
				return false // if happens too often, give up
			}
			continue
		}
		thisSignal, thisCover, thisDist := getPatchSignalAndCover(item.p, info, item.call)
		newSignal = newSignal.Intersection(thisSignal)
		// Without !minimized check manager starts losing some considerable amount
		// of coverage after each restart. Mechanics of this are not completely clear.
		if newSignal.Empty() && item.flags&ProgMinimized == 0 {
			return false
		}
		inputCover.Merge(thisCover)

		if info.MinDist < progDist {
			progDist = info.MinDist
		}
		if thisDist != prog.InvalidDist && thisDist > callDist {
			callDist = thisDist
		}

	}
	if item.flags&ProgMinimized == 0 {
		item.p, item.call = prog.Minimize(item.p, item.call, false,
			func(p1 *prog.Prog, call1 int) bool {
				for i := 0; i < minimizeAttempts; i++ {
					info := proc.execute(proc.execOptsNoCollide, p1, ProgNormal, StatMinimize)
					if !reexecutionSuccess(info, &callInfo, call1) {
						// The call was not executed or failed.
						continue
					}
					thisSignal, _, _ := getPatchSignalAndCover(p1, info, call1)
					if newSignal.Intersection(thisSignal).Len() == newSignal.Len() && info.MinDist <= progDist {

						return true
					}
				}
				return false
			})
	}

	item.p.Dist = progDist
	// if progDist != prog.InvalidDist {
	// 	atomic.AddUint64(&proc.fuzzer.extStats[ExtAllDist], uint64(progDist))
	// 	atomic.AddUint64(&proc.fuzzer.extStats[ExtProgCount], 1)
	// 	if shouldUpdate && item.p.Tcall != nil {
	// 		proc.fuzzer.choiceTable.UpdateCallDistance(item.p, callDist)
	// 	}
	// }

	data := item.p.Serialize()
	sig := hash.Hash(data)

	log.Logf(1, "added new input for %v to corpus:\n%s", logCallName, data)
	//panic("aa")
	log.Logf(1, "\n\n\n\n******* patchsig2 : %v\n\n\n\n\n", inputSignal.Serialize())
	proc.fuzzer.sendInputToManager(rpctype.RPCInput{
		Call:     callName,
		Prog:     data,
		PatchSig: inputSignal.Serialize(),
		Cover:    inputCover.Serialize(),
		Dist:     progDist,
	})

	//yuhang
	//proc.fuzzer.counter
	proc.fuzzer.patchAddInputToCorpus(item.p, inputSignal, sig)

	if item.flags&ProgSmashed == 0 {
		proc.fuzzer.workQueue.enqueue(&WorkSmash{item.p, item.call})
	}
	return true
}

// 根据任务的标志来选择不同的处理逻辑。函数首先输出一个日志，记录任务类型和相关信息，然后根据任务的不同标志做出不同的处理
// WorkTriage是需要进一步判断是否有新覆盖产生的program
func (proc *Proc) triageInput(item *WorkTriage) {
	log.Logf(1, "#%v: triaging type=%x", proc.pid, item.flags)
	patchFuzzerOpt := false
	if item.flags&ProgPatchfuzzer != 0 {
		patchFuzzerOpt = true
	}
	if patchFuzzerOpt { //}
		if proc.triagePatchInput(item) == true {
			return
		}
	}
	triageObj := false
	if item.flags&ProgTriageObj != 0 {
		triageObj = true
	}
	triageTrace := false
	if item.flags&ProgTraceTag != 0 {
		triageTrace = true
	}
	callInfo := item.progInfo.Calls[item.call]

	progDist := item.p.Dist
	callDist := item.info.Dist

	var inputSignal, newSignal signal.Signal

	if triageObj {
		inputSignal = proc.fuzzer.getObjSignal(item.p, item.progInfo, item.call)
		newSignal = proc.fuzzer.corpusObjSignalDiff(inputSignal)
	} else if triageTrace {
		//change-a
		inputSignal = proc.fuzzer.getTraceSignal(item.p, item.progInfo, item.call)
		newSignal = proc.fuzzer.corpusTraceSignalDiff(inputSignal)
	} else {
		prio := signalPrio(item.p, &callInfo, item.call)
		inputSignal = signal.FromRaw(callInfo.Signal, prio)
		newSignal = proc.fuzzer.corpusSignalDiff(inputSignal)
	}

	if newSignal.Empty() {
		name := item.p.Calls[item.call].Meta.Name
		_, found := proc.fuzzer.corpusSyscall[name]
		// return if the syscall has been in the corpusSyscall
		if found || (!triageObj && !triageTrace) || inputSignal.Empty() {
			return
		}
		// keep the obj signal as new signal since this syscall is not in the corpus
		log.Logf(3, "keep this syscall %v since it is not in corpus\n", name)
		newSignal = inputSignal
	}

	callName := ".extra"
	logCallName := "extra"
	// shouldUpdate := false
	// if item.call >= 0 {
	// 	callName = item.p.Calls[item.call].Meta.Name
	// 	logCallName = fmt.Sprintf("call #%v %v", item.call, callName)
	// 	if item.p.Calls[item.call] == item.p.Tcall || item.p.Calls[item.call] == item.p.Rcall {
	// 		shouldUpdate = true
	// 	}
	// }
	if triageObj {
		callName = item.p.Calls[item.call].Meta.Name
		logCallName = fmt.Sprintf("call object interaction #%v %v", item.call, callName)
	}
	log.Logf(3, "triaging input for %v (new signal=%v)", logCallName, newSignal.Len())

	var inputCover cover.Cover
	const (
		signalRuns       = 3
		minimizeAttempts = 3
	)
	// Compute input coverage and non-flaky signal for minimization.
	notexecuted := 0
	for i := 0; i < signalRuns; i++ {
		info := proc.executeRaw(proc.execOptsCover, item.p, StatTriage)

		var thisCover []uint32
		var thisSignal signal.Signal
		var thisDist uint32
		// original execution
		if !reexecutionSuccess(info, &callInfo, item.call) {
			// The call was not executed or failed.
			notexecuted++
			if notexecuted > signalRuns/2+1 {
				return // if happens too often, give up
			}
			continue
		}
		thisSignal, thisCover, thisDist = getSignalAndCover(item.p, info, item.call)

		if triageObj {
			// item.call is always greater than 0 for triaging object cov.
			thisSignal = proc.fuzzer.getObjSignal(item.p, info, item.call)
		} else if triageTrace {
			thisSignal = proc.fuzzer.getTraceSignal(item.p, info, item.call)
		}

		newSignal = newSignal.Intersection(thisSignal)

		// Without !minimized check manager starts losing some considerable amount
		// of coverage after each restart. Mechanics of this are not completely clear.
		if newSignal.Empty() && item.flags&ProgMinimized == 0 {
			log.Logf(3, "No new signal : %v", item.flags&ProgMinimized)
			return
		}
		inputCover.Merge(thisCover)
		if info.MinDist < progDist {
			progDist = info.MinDist
		}
		if thisDist != prog.InvalidDist && thisDist > callDist {
			callDist = thisDist
		}
	}

	// minimizing prog, while minimizing, we want to keep the cover of object
	// to make sure the prog in corpus are covering the target object
	var objInputSignal, newObjSignal, traceInputSingal, newTraceSignal signal.Signal
	if !triageObj {
		// objInputSignal = proc.fuzzer.getAllObjSignal(item.p, item.progInfo)
		objInputSignal = proc.fuzzer.getObjSignal(item.p, item.progInfo, item.call)
		newObjSignal = proc.fuzzer.corpusObjSignalDiff(objInputSignal)
	} else {
		// change_a
		//objInputSignal = proc.fuzzer.getTraceSignal(item.p, item.progInfo, item.call)
		//newObjSignal = proc.fuzzer.corpusTraceSignalDiff(objInputSignal)
		objInputSignal = inputSignal
		newObjSignal = newSignal
	}

	if !triageTrace {
		traceInputSingal = proc.fuzzer.getTraceSignal(item.p, item.progInfo, item.call)
		newTraceSignal = proc.fuzzer.corpusTraceSignalDiff(traceInputSingal)
	} else {
		traceInputSingal = inputSignal
		newTraceSignal = newSignal
	}

	// return if no obj sig
	if objInputSignal.Empty() && traceInputSingal.Empty() {
		log.Logf(3, "Empty objInput and TraceInput Signal")
		return
	}

	// use the new signal and cover of the syscalls after minimzing the prog.
	if item.flags&ProgMinimized == 0 {
		item.p, item.call = prog.Minimize(item.p, item.call, false,
			func(p1 *prog.Prog, call1 int) bool {
				for i := 0; i < minimizeAttempts; i++ {
					// use executeRaw here, since we are not going to triage
					// the prog we are working on.
					info := proc.executeRaw(proc.execOptsNoCollide, p1, StatMinimize)

					if !reexecutionSuccess(info, &callInfo, call1) {
						// The call was not executed or failed.
						continue
					}
					// thisSignal, _ := getSignalAndCover(p1, info, call1)
					// if newSignal.Intersection(thisSignal).Len() == newSignal.Len() {
					// 	return true
					// }

					thisObjSignal := proc.fuzzer.getObjSignal(p1, info, call1)
					thisTraceSignal := proc.fuzzer.getTraceSignal(p1, info, call1)
					if triageObj {
						// FIXME: do we need to keep objInputSignal???
						if newObjSignal.Intersection(thisObjSignal).Len() == newObjSignal.Len() && info.MinDist <= progDist {
							thisSignal, thisCover, thisDist := getSignalAndCover(p1, info, call1)
							var minCov cover.Cover
							minCov.Merge(thisCover)
							inputCover = minCov
							inputSignal = thisSignal

							if info.MinDist < progDist {
								progDist = info.MinDist
							}
							if thisDist != prog.InvalidDist && thisDist > callDist {
								callDist = thisDist
							}

							return true
						}
					} else if triageTrace {
						if newTraceSignal.Intersection(thisTraceSignal).Len() == newTraceSignal.Len() {
							thisSignal, thisCover, thisDist := getSignalAndCover(p1, info, call1)
							var minCov cover.Cover
							minCov.Merge(thisCover)
							inputCover = minCov
							inputSignal = thisSignal

							if info.MinDist < progDist {
								progDist = info.MinDist
							}
							if thisDist != prog.InvalidDist && thisDist > callDist {
								callDist = thisDist
							}

							return true
						}
					} else {
						thisSignal, thisCover, thisDist := getSignalAndCover(p1, info, call1)
						// we want to keep the signal of object when minimizing.
						if objInputSignal.Intersection(thisObjSignal).Len() == objInputSignal.Len() &&
							newSignal.Intersection(thisSignal).Len() == newSignal.Len() && thisTraceSignal.Intersection(traceInputSingal).Len() == traceInputSingal.Len() {
							// reset input cover and signal after minimizing
							var minCov cover.Cover
							minCov.Merge(thisCover)
							inputCover = minCov
							inputSignal = thisSignal

							if info.MinDist < progDist {
								progDist = info.MinDist
							}
							if thisDist != prog.InvalidDist && thisDist > callDist {
								callDist = thisDist
							}

							return true
						}
					}
				}
				return false
			})
	}

	item.p.Dist = progDist
	// if progDist != prog.InvalidDist {
	// 	atomic.AddUint64(&proc.fuzzer.extStats[ExtAllDist], uint64(progDist))
	// 	atomic.AddUint64(&proc.fuzzer.extStats[ExtProgCount], 1)
	// 	if shouldUpdate && item.p.Tcall != nil {
	// 		proc.fuzzer.choiceTable.UpdateCallDistance(item.p, callDist)
	// 	}
	// }

	data := item.p.Serialize()
	sig := hash.Hash(data)

	// tcallId, rcallId := -1, -1
	// if shouldUpdate && item.p.Tcall != nil {
	// 	tcallId = item.p.Tcall.Meta.ID
	// 	if item.p.Rcall != nil {
	// 		rcallId = item.p.Rcall.Meta.ID
	// 	}
	// }

	log.Logf(1, "added new input for %v to corpus:\n%s", logCallName, data)
	proc.fuzzer.sendInputToManager(rpctype.RPCInput{
		Call:     callName,
		Prog:     data,
		Signal:   inputSignal.Serialize(),
		ObjSig:   objInputSignal.Serialize(),
		TraceSig: traceInputSingal.Serialize(),
		Cover:    inputCover.Serialize(),
		Dist:     progDist,
		// TcallId:  tcallId,
		// RcallId:  rcallId,
	})

	proc.fuzzer.addInputToCorpus(item.p, inputSignal, objInputSignal, traceInputSingal, sig)

	if item.flags&ProgSmashed == 0 {
		proc.fuzzer.workQueue.enqueue(&WorkSmash{item.p, item.call})
	}
}

func reexecutionSuccess(info *ipc.ProgInfo, oldInfo *ipc.CallInfo, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldInfo.Errno == 0 && info.Calls[call].Errno != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *ipc.ProgInfo, call int) (signal.Signal, []uint32, uint32) {
	inf := &info.Extra
	if call != -1 {
		inf = &info.Calls[call]
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call)), inf.Cover, inf.Dist
}

func getPatchSignalAndCover(p *prog.Prog, info *ipc.ProgInfo, call int) (signal.PatchSig, []uint32, uint32) {
	inf := &info.Extra
	if call != -1 {
		inf = &info.Calls[call]
	}
	return signal.PatchFuzzerFromRaw(inf.Similarity, inf.HashvarIdx, inf.Hashvar, signalPrio(p, inf, call)), inf.Cover, inf.Dist
}

// in order to mutate seed and execute
// gpt: 根据程序的状态和配置对Input突变
// hawkeye的power schedule阶段在smashInput里面实现
func (proc *Proc) smashInput(item *WorkSmash) {
	if proc.fuzzer.faultInjectionEnabled && item.call != -1 {
		proc.failCall(item.p, item.call)
	}
	if proc.fuzzer.comparisonTracingEnabled && item.call != -1 {
		proc.executeHintSeed(item.p, item.call)
	}
	maxDist, minDist := proc.fuzzer.readExtremeDist()
	mutateNum := 100
	if minDist != prog.InvalidDist && item.p.Dist != prog.InvalidDist {
		normalized_d := 0.0
		if maxDist != minDist {
			normalized_d = float64(maxDist-item.p.Dist) / float64(maxDist-minDist)
		}
		power_factor := math.Pow(16, normalized_d)
		mutateNum = int(power_factor*9.375 + 50.0)
	}
	fuzzerSnapshot := proc.fuzzer.snapshot()
	for i := 0; i < mutateNum; i++ {
		p := item.p.Clone()
		p.Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, fuzzerSnapshot.corpus)
		log.Logf(1, "#%v: smash mutated", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatSmash)
		// syzdirect
		// proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatSmash)
	}
}

func (proc *Proc) mutateSeed(item *WorkSeed) {

}

func (proc *Proc) failCall(p *prog.Prog, call int) {
	for nth := 0; nth < 100; nth++ {
		log.Logf(1, "#%v: injecting fault into call %v/%v", proc.pid, call, nth)
		opts := *proc.execOpts
		opts.Flags |= ipc.FlagInjectFault
		opts.FaultCall = call
		opts.FaultNth = nth
		info := proc.executeRaw(&opts, p, StatSmash)
		if info != nil && len(info.Calls) > call && info.Calls[call].Flags&ipc.CallFaultInjected == 0 {
			break
		}
	}
}

func (proc *Proc) executeHintSeed(p *prog.Prog, call int) {
	log.Logf(1, "#%v: collecting comparisons", proc.pid)
	// First execute the original program to dump comparisons from KCOV.
	info := proc.execute(proc.execOptsComps, p, ProgNormal, StatSeed)
	if info == nil {
		return
	}

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(call, info.Calls[call].Comps, func(p *prog.Prog) {
		log.Logf(1, "#%v: executing comparison hint", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatHint)
	})
}
func (proc *Proc) execute_async(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) *ipc.ProgInfo {
	info := proc.executeRaw(execOpts, p, stat)
	if info == nil {
		return nil
	}
	//num := proc.fuzzer.getSimilarity(info)
	//if num == 0 {
	//	return info
	//}
	//log.Logf(1, "Similarity: %v", num)
	//proc.fuzzer.getVarHash(info)
	log.Logf(1, "Building relations\n")
	proc.buildRelations(info, p.Serialize())
	return info
}

func (proc *Proc) buildRelations(info *ipc.ProgInfo, data []byte) {
	res := proc.fuzzer.setRel(info, proc.info.Targetlist)
	//if proc.fuzzer.Counter > 0 {
	//	proc.fuzzer.Ctrlnum = 2
	//}
	if res == 1 {
		log.Logf(1, "target in Targetlist, make ctrlnum=1, relations ok!!!!\n")
		for _, target := range proc.info.Targetlist {
			callIdx := -1
			argIdx := -1
			for key, _ := range target {
				callIdx = key
				argIdx = target[key]
			}
			log.Logf(1, "relationship has been built\n")
			proc.fuzzer.syncReltoManager(callIdx, argIdx, data)
		}
		//panic("aa")
		/*
			if len(proc.info.Targetlist) == 1 {
				proc.fuzzer.Counter = 1
				proc.fuzzer.Ctrlnum = 2
				log.Logf(1, "tl: %v\n", proc.info.Targetlist)
				panic("aa")
			} else {
				//log.Logf(1, "traget in targetlist, make ctrlnum=1\n")
				//proc.fuzzer.Ctrlnum = 1
				log.Logf(1, "tl: %v\n", proc.info.Targetlist)
				panic("aa")
			}*/
	} else {
		if res == 0 {
			if len(proc.info.Waitlist) == 0 {
				proc.info.Targetlist = proc.info.Targetlist[:0]
				proc.fuzzer.Counter = 0
			}
			log.Logf(1, "target in waitlist, make ctrlnum=0, relations pending!!!!\n")
			proc.fuzzer.Ctrlnum = 0
		} /*else {
			proc.info.Targetlist =  proc.info.LastTargetlist
			proc.info.Waitlist = proc.info.LastWaitlist
		}*/
	}
}

func (proc *Proc) execute(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) *ipc.ProgInfo {
	// enable collectcover by default
	execOpts.Flags |= ipc.FlagCollectCover
	info := proc.executeRaw(execOpts, p, stat)

	p.Dist = info.MinDist
	// define in direct.go as const: InvalidDist        uint32 = 0xFFFFFFFF
	// 如果program的dist不为空，且比MaxDist大，就提示应该更新 MaxDist
	if p.Dist != prog.InvalidDist && p.Dist > prog.MaxDist {
		log.Fatalf("prog dist %v higher than max dist %v", p.Dist, prog.MaxDist)
		panic("max dist should improve")
	}

	//这个num是？
	num := proc.fuzzer.getTraceSize(info)
	if num == 0 {
		// discard triaging if there is no object covered
		return info
	}
	//log.Logf(3, "We got %v objcov", num)
	// triage every syscall in the prog if new covs are generated
	// for syscalls covering new object, we use mark it as object triage.

	// calls, extra := proc.fuzzer.checkNewSignal(p, info)
	// for _, callIndex := range calls {
	// 	proc.enqueueCallTriage(p, flags, callIndex, info.Calls[callIndex])
	// }
	// if extra {
	// 	proc.enqueueCallTriage(p, flags, -1, info.Extra)
	// }

	objCalls, _ := proc.fuzzer.checkNewObjSignal(p, info)
	traceCalls, _ := proc.fuzzer.checkNewTraceSignal(p, info)
	patchCalls, _ := proc.fuzzer.checkNewPatchSignal(p, info)
	for _, callIndex := range objCalls {
		//log.Logf(1, "test789")
		//排序
		log.Logf(1, "enqueuing new objCalls")
		if len(info.Calls[callIndex].ObjCover) != 0 {
			proc.enqueueCallTriage(p, flags|ProgTriageObj, callIndex, info)
		}
	}
	for _, callIndex := range traceCalls {
		log.Logf(1, "enqueuing new signal call")
		if len(info.Calls[callIndex].Hashvar) != 0 {
			proc.enqueueCallTriage(p, flags|ProgPatchfuzzer, callIndex, info)
			proc.enqueueCallTriage(p, flags|ProgTraceTag, callIndex, info)
		} else {
			proc.enqueueCallTriage(p, flags|ProgTraceTag, callIndex, info)
			proc.enqueueCallTriage(p, flags, callIndex, info)
		}
	}
	for _, callIndex := range patchCalls {
		log.Logf(1, "enqueuing new patch Calls")
		if len(info.Calls[callIndex].Hashvar) != 0 {
			proc.enqueueCallTriage(p, flags|ProgPatchfuzzer, callIndex, info)
			proc.enqueueCallTriage(p, flags, callIndex, info)
		}
	}

	// proc.fuzzer.callStatsMu.Lock()
	// if p.Tcall != nil {
	// 	proc.fuzzer.callStats[p.Tcall.Meta.Name] += 1
	// }
	// proc.fuzzer.callStatsMu.Unlock()

	// calls, _ := proc.fuzzer.checkNewSignal(p, info)

	// for _, callIndex := range calls {
	// only explore syscalls that have object cover
	// FIXME: unknow if this has any side-effect
	/*
		for _, callIndex := range objCalls {
			// skip if no object is covered
			if len(info.Calls[callIndex].ObjCover) == 0 {
				continue
			}
			log.Logf(2, "enqueuing new signal call")
			proc.enqueueCallTriage(p, flags, callIndex, info)
		}*/
	return info
	// will not cover extra
	// if extra {
	// 	proc.enqueueCallTriage(p, flags, -1, info)
	// }
	//return info
}

func (proc *Proc) enqueueCallTriage(p *prog.Prog, flags ProgTypes, callIndex int, info *ipc.ProgInfo) {
	if callIndex > 0 {
		// info.Signal points to the output shmem region, detach it before queueing.
		info.Calls[callIndex].Signal = append([]uint32{}, info.Calls[callIndex].Signal...)
		// None of the caller use Cover, so just nil it instead of detaching.
		// Note: triage input uses executeRaw to get coverage.
		info.Calls[callIndex].Cover = nil
	} else if callIndex == -1 {
		// info.Signal points to the output shmem region, detach it before queueing.
		info.Extra.Signal = append([]uint32{}, info.Extra.Signal...)
		// None of the caller use Cover, so just nil it instead of detaching.
		// Note: triage input uses executeRaw to get coverage.
		info.Extra.Cover = nil
	}
	proc.fuzzer.workQueue.enqueue(&WorkTriage{
		p:        p.Clone(),
		call:     callIndex,
		progInfo: info,
		flags:    flags,
	})
}

func (proc *Proc) executeRaw(opts *ipc.ExecOpts, p *prog.Prog, stat Stat) *ipc.ProgInfo {
	if opts.Flags&ipc.FlagDedupCover == 0 {
		log.Fatalf("dedup cover is not enabled")
	}
	for _, call := range p.Calls {
		if !proc.fuzzer.choiceTable.Enabled(call.Meta.ID) {
			fmt.Printf("executing disabled syscall %v", call.Meta.Name)
			// TODO: enable syscalls in poc
			panic("disabled syscall")
		}
	}

	// Limit concurrency window and do leak checking once in a while.
	ticket := proc.fuzzer.gate.Enter()
	defer proc.fuzzer.gate.Leave(ticket)

	proc.logProgram(opts, p)
	for try := 0; ; try++ {
		atomic.AddUint64(&proc.fuzzer.stats[stat], 1)
		output, info, hanged, err := proc.env.Exec(opts, p)
		if err != nil {
			if try > 10 {
				log.Fatalf("executor %v failed %v times:\n%v", proc.pid, try, err)
			}
			log.Logf(4, "fuzzer detected executor failure='%v', retrying #%d", err, try+1)
			debug.FreeOSMemory()
			time.Sleep(time.Second)
			continue
		}
		log.Logf(2, "result hanged=%v: %s", hanged, output)
		return info
	}
}

func (proc *Proc) logProgram(opts *ipc.ExecOpts, p *prog.Prog) {
	if proc.fuzzer.outputType == OutputNone {
		return
	}

	data := p.Serialize()
	strOpts := ""
	if opts.Flags&ipc.FlagInjectFault != 0 {
		strOpts = fmt.Sprintf(" (fault-call:%v fault-nth:%v)", opts.FaultCall, opts.FaultNth)
	}

	// The following output helps to understand what program crashed kernel.
	// It must not be intermixed.
	switch proc.fuzzer.outputType {
	case OutputStdout:
		now := time.Now()
		proc.fuzzer.logMu.Lock()
		fmt.Printf("%02v:%02v:%02v executing program %v%v:\n%s\n",
			now.Hour(), now.Minute(), now.Second(),
			proc.pid, strOpts, data)
		proc.fuzzer.logMu.Unlock()
	case OutputDmesg:
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "syzkaller: executing program %v%v:\n%s\n",
				proc.pid, strOpts, data)
			syscall.Write(fd, buf.Bytes())
			syscall.Close(fd)
		}
	case OutputFile:
		f, err := os.Create(fmt.Sprintf("%v-%v.prog", proc.fuzzer.name, proc.pid))
		if err == nil {
			if strOpts != "" {
				fmt.Fprintf(f, "#%v\n", strOpts)
			}
			f.Write(data)
			f.Close()
		}
	default:
		log.Fatalf("unknown output type: %v", proc.fuzzer.outputType)
	}
}
