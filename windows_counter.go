package sigar

/*
#cgo LDFLAGS: -lpdh

#define UNICODE

#include <TCHAR.h>
#include <pdh.h>
#include <windows.h>


static PDH_HQUERY pdhQuery;
static PDH_HCOUNTER cpuTotal;
static PDH_HCOUNTER freeMem;
static PDH_HCOUNTER zeroFreeMem;


void init(){
    PdhOpenQuery((LPCWSTR)NULL, (DWORD_PTR)NULL, &pdhQuery);
    PdhAddCounter(pdhQuery, L"\\Processor(_Total)\\% Processor Time", (DWORD_PTR)NULL, &cpuTotal);
	PdhAddCounter(pdhQuery, L"\\Memory\\Available Bytes", (DWORD_PTR)NULL, &freeMem);
	PdhAddCounter(pdhQuery, L"\\Memory\\Free & Zero Page List Bytes", (DWORD_PTR)NULL, &zeroFreeMem);
    PdhCollectQueryData(pdhQuery);
}

double getCPUValue(){
    PDH_FMT_COUNTERVALUE counterVal;
    PdhCollectQueryData(pdhQuery);
    PdhGetFormattedCounterValue(cpuTotal, PDH_FMT_DOUBLE, NULL, &counterVal);
    return counterVal.doubleValue;
}

double getFreeMemValue(){
    PDH_FMT_COUNTERVALUE counterVal;
    PdhCollectQueryData(pdhQuery);
    PdhGetFormattedCounterValue(freeMem, PDH_FMT_LARGE, NULL, &counterVal);
    return counterVal.largeValue;
}

double getZeroFreeMemValue(){
    PDH_FMT_COUNTERVALUE counterVal;
    PdhCollectQueryData(pdhQuery);
    PdhGetFormattedCounterValue(zeroFreeMem, PDH_FMT_LARGE, NULL, &counterVal);
    return counterVal.largeValue;
}

*/
import "C"

import (
	"sync"
	"time"
)

type WinCounter struct {
	LastCPU     float64
	FreeMem     int64
	ZeroFreeMem int64
	l           sync.Mutex
}

func NewWinCounter() *WinCounter {
	C.init()
	res := &WinCounter{}
	res.LastCPU = 0
	res.FreeMem = 0
	res.ZeroFreeMem = 0
	res.UpdateSample()
	ticker := time.NewTicker(1 * time.Second)

	go func() {
		for {
			select {
			case <-ticker.C:
				res.UpdateSample()
			}
		}
	}()

	return res
}

func (winCount *WinCounter) UpdateSample() {
	winCount.l.Lock()
	defer winCount.l.Unlock()

	cpuSample := C.getCPUValue()
	freeMem := C.getFreeMemValue()
	zeroFreeMem := C.getZeroFreeMemValue()
	winCount.LastCPU = float64(cpuSample)
	winCount.FreeMem = int64(freeMem)
	winCount.ZeroFreeMem = int64(zeroFreeMem)

}
