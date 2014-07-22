package sigar_test

import (
	sigar "github.com/cloudfoundry/gosigar"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"time"
)

var winCounter *sigar.WinCounter = sigar.NewWinCounter()

var _ = Describe("WindowsCounter", func() {
	It("gets the CPU counter", func() {
		//We must wait for the CPU couter to start
		time.Sleep(1 * time.Second)
		Ω(winCounter.LastCPU).Should(BeNumerically(">", 0))
	})
	It("gets the free memory counter", func() {
		Ω(winCounter.FreeMem).Should(BeNumerically(">", 0))
	})
	It("gets the zero free memory counter", func() {
		Ω(winCounter.ZeroFreeMem).Should(BeNumerically(">", 0))
	})
})
