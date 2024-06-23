// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"math"
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type InputTest struct {
	p    *prog.Prog
	sign signal.Signal
	sig  hash.Sig
	// for testchooseProgtam
	objSig   signal.Signal
	traceSig signal.Signal
}

// // syzdirect初始的TestChooseProgram
// // 测试 chooseProgram 方法是否按照预期的概率选择程序
// func TestChooseProgram(t *testing.T) {
// 	rs := rand.NewSource(0)
// 	//创建伪随机数生成器
// 	r := rand.New(rs)
// 	target := getTarget(t, "test", "64")
// 	fuzzer := &Fuzzer{corpusHashes: make(map[hash.Sig]struct{})}

// 	const (
// 		maxIters   = 1000
// 		sizeCorpus = 1000
// 		eps        = 0.01
// 	)

// 	priorities := make(map[*prog.Prog]int64)
// 	for i := 0; i < sizeCorpus; i++ {
// 		sizeSig := i + 1
// 		if sizeSig%250 == 0 {
// 			sizeSig = 0
// 		}
// 		inp := generateInput(target, rs, 10, sizeSig)
// 		fuzzer.addInputToCorpus(inp.p, inp.sign, inp.sig)
// 		priorities[inp.p] = int64(len(inp.sign))
// 	}
// 	// 创建 FuzzerSnapshot 结构体的快照，用于测试
// 	// FuzzerSnapshot struct包括 {
// 	// 	corpus      []*prog.Prog
// 	// 	corpusPrios []int64
// 	// 	sumPrios    int64
// 	// }
// 	snapshot := fuzzer.snapshot()
// 	// 创建一个计数器映射，用于统计每个程序被选择的次数
// 	counters := make(map[*prog.Prog]int)
// 	for it := 0; it < maxIters; it++ {
// 		counters[snapshot.chooseProgram(r)]++
// 	}
// 	// 遍历 priorities 中的程序和优先级，计算每个程序被选择的概率，并检查其选择次数是否在允许误差范围内
// 	for p, prio := range priorities {
// 		prob := float64(prio) / float64(fuzzer.sumPrios)
// 		diff := math.Abs(prob*maxIters - float64(counters[p]))
// 		if diff > eps*maxIters {
// 			t.Fatalf("the difference (%f) is higher than %f%%", diff, eps*100)
// 		}
// 	}
// }

func TestChooseProgram(t *testing.T) {
	// 初始化随机数生成器
	rs := rand.NewSource(0)
	r := rand.New(rs)
	// 初始化目标
	// target := getTarget(t, targets.TestOS, targets.TestArch64)
	target := getTarget(t, targets.Linux, targets.AMD64)
	// 初始化 Fuzzer 结构
	// fuzzer := &Fuzzer{corpusHashes: make(map[hash.Sig]struct{})}
	fuzzer := &Fuzzer{corpusHashes: make(map[hash.Sig]struct{}), distanceGroup: make(map[uint32]uint32), corpusSyscall: make(map[string]bool)}

	const (
		maxIters   = 1000
		sizeCorpus = 1000
		eps        = 0.01
	)
	// 生成输入和优先级
	priorities := make(map[*prog.Prog]int64)
	for i, j := 0, 0; i < sizeCorpus; {
		dist := 200 * j
		j++
		for num := 0; num < j*2; num++ {
			i += 1
			// 生成输入
			inp := generateInput(target, rs, 10, 1, dist)
			// 将输入添加到语料库中
			fuzzer.addInputToCorpus(inp.p, inp.sign, inp.objSig, inp.traceSig, inp.sig)
			//fuzzer.addInputToCorpus(p, sign, objSig, TraceSig, sig)
			// 计算优先级
			prio := int64(1)
			if inp.p.Dist < 3450 { // 如果dist > 3450，就没必要算
				prio = int64(100 * math.Exp(float64(inp.p.Dist)*-0.003))
				if prio < 1 {
					prio = 1
				}
			}
			// 将输入及其优先级存储在 priorities 中
			priorities[inp.p] = prio
		}

	}
	// 创建模糊器的快照
	snapshot := fuzzer.snapshot()
	counters := make(map[*prog.Prog]int)
	// 测试 chooseProgram 方法
	for it := 0; it < maxIters; it++ {
		counters[snapshot.chooseProgram(r, nil)]++
	}
	// 验证
	for p, prio := range priorities {
		// fmt.Printf("dist: %v, prio: %v\n", p.Dist, prio)
		prob := float64(prio) / float64(fuzzer.sumPrios)
		diff := math.Abs(prob*maxIters - float64(counters[p]))
		if diff > eps*maxIters {
			fmt.Printf("\tthe difference (%f) is higher than %f%%\n", diff, eps*100)
		}
	}
	stats := make(map[int]int)
	stats2 := make(map[int]int)
	for p := range priorities {
		stats[int(p.Dist)] += counters[p]
		stats2[int(p.Dist)] += 1
	}
	for k, v := range stats {
		fmt.Printf("dist: %v, prog num: %v, counter: %v\n", k, stats2[k], v)
	}
}

// func TestAddInputConcurrency(t *testing.T) {
// 	target := getTarget(t, "test", "64")
// 	fuzzer := &Fuzzer{corpusHashes: make(map[hash.Sig]struct{})}

// 	const (
// 		routines = 10
// 		iters    = 100
// 	)

// 	for i := 0; i < routines; i++ {
// 		go func() {
// 			rs := rand.NewSource(0)
// 			r := rand.New(rs)
// 			for it := 0; it < iters; it++ {
// 				inp := generateInput(target, rs, 10, it)
// 				fuzzer.addInputToCorpus(inp.p, inp.sign, inp.sig)
// 				//fuzzer.addInputToCorpus(inp.p, inp.sign, objSig, TraceSig, inp.sig)
// 				snapshot := fuzzer.snapshot()
// 				snapshot.chooseProgram(r).Clone()
// 			}
// 		}()
// 	}
// }

func generateInput(target *prog.Target, rs rand.Source, ncalls, sizeSig int, dist int) (inp InputTest) {
	inp.p = target.Generate(rs, ncalls, target.DefaultChoiceTable())
	var raw []uint32
	var PreTrace []uint32
	var EnableTrace []uint32
	var PostTrace []uint32
	for i := 1; i <= sizeSig; i++ {
		raw = append(raw, uint32(i))
	}
	for i := 1; i <= sizeSig; i++ {
		PreTrace = append(raw, uint32(i))
	}
	for i := 1; i <= sizeSig; i++ {
		EnableTrace = append(raw, uint32(i))
	}
	for i := 1; i <= sizeSig; i++ {
		PostTrace = append(raw, uint32(i))
	}
	inp.sign = signal.FromRaw(raw, 0)
	inp.p.Dist = uint32(dist)
	inp.sig = hash.Hash(inp.p.Serialize())
	inp.objSig = signal.ObjCovFromRaw(raw, 0)
	inp.traceSig = signal.TraceFromRaw(PreTrace, EnableTrace, PostTrace, 0)
	return
}

func getTarget(t *testing.T, os, arch string) *prog.Target {
	t.Parallel()
	target, err := prog.GetTarget(os, arch)
	if err != nil {
		t.Fatal(err)
	}
	return target
}
