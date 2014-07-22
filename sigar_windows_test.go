package sigar_test

import (
	sigar "github.com/cloudfoundry/gosigar"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"math/rand"
	"os"
)

var _ = Describe("SigarWindows", func() {
	Describe("Memory", func() {
		It("gets the total memory", func() {
			mem := sigar.Mem{}
			err := mem.Get()

			Ω(err).ShouldNot(HaveOccurred())
			Ω(mem.Total).Should(BeNumerically(">", 0))
			Ω(mem.Free).Should(BeNumerically(">", 0))
			Ω(mem.ActualFree).Should(BeNumerically(">", 0))
			Ω(mem.ActualUsed).Should(BeNumerically(">", 0))
		})
	})

	Describe("Disk", func() {
		It("gets the total disk space", func() {
			usage := sigar.FileSystemUsage{}
			err := usage.Get(os.TempDir())

			Ω(err).ShouldNot(HaveOccurred())
			Ω(usage.Total).Should(BeNumerically(">", 0))
		})
	})

	Describe("Uptime", func() {
		It("gets the uptime of the system", func() {

			uptime := sigar.Uptime{}
			err := uptime.Get()

			Ω(err).ShouldNot(HaveOccurred())
			Ω(uptime.Length).Should(BeNumerically(">", 0))
		})
	})

	Describe("LoadAverage", func() {
		It("gets the load average of the system", func() {

			loadAverage := sigar.LoadAverage{}

			err := loadAverage.Get()
			Ω(err).ShouldNot(HaveOccurred())
			//Ω(loadAverage.One).Should(BeNumerically(">", 0))
		})
	})
	Describe("Swap", func() {
		It("gets the page file of the system", func() {

			swap := sigar.Swap{}

			err := swap.Get()
			Ω(err).ShouldNot(HaveOccurred())
			Ω(swap.Total).Should(BeNumerically(">", 0))
			Ω(swap.Used).Should(BeNumerically(">", 0))
			Ω(swap.Free).Should(BeNumerically(">", 0))

		})
	})
	Describe("CPU", func() {
		It("Retrieves CPU status", func() {

			cpu := sigar.Cpu{}
			err := cpu.Get()

			Ω(err).ShouldNot(HaveOccurred())
			Ω(cpu.Idle).Should(BeNumerically(">", 0))
			Ω(cpu.Sys).Should(BeNumerically(">", 0))
			Ω(cpu.User).Should(BeNumerically(">", 0))
			Ω(cpu.Irq).Should(BeNumerically(">", 0))

		})
		It("Has at least one core", func() {
			cpuList := sigar.CpuList{}
			err := cpuList.Get()

			Ω(err).ShouldNot(HaveOccurred())
			Ω(len(cpuList.List)).Should(BeNumerically(">", 0))

		})
	})

	Describe("ProcList", func() {
		It("gets the process list of the system", func() {

			procList := sigar.ProcList{}

			err := procList.Get()
			Ω(err).ShouldNot(HaveOccurred())
			Ω(len(procList.List)).Should(BeNumerically(">", 0))
		})
	})
	Describe("Process", func() {
		It("retieves process information for a given process", func() {
			procState := sigar.ProcState{}

			//get a random process
			procList := sigar.ProcList{}
			_ = procList.Get()
			rand.Seed(23)
			pid := procList.List[rand.Intn(len(procList.List))]

			err := procState.Get(pid)
			Ω(err).ShouldNot(HaveOccurred())
			Ω(procState.Name).ShouldNot(BeEquivalentTo(""))

			Ω(procState.Priority).Should(BeNumerically(">", 0))
		})
		It("retieves process time for a given process", func() {
			procTime := sigar.ProcTime{}

			//get a random process
			procList := sigar.ProcList{}
			_ = procList.Get()
			rand.Seed(41)
			pid := procList.List[rand.Intn(len(procList.List))]

			err := procTime.Get(pid)
			Ω(err).ShouldNot(HaveOccurred())
			Ω(procTime.StartTime).Should(BeNumerically(">", 0))
			Ω(procTime.User).Should(BeNumerically(">", 0))
			Ω(procTime.Sys).Should(BeNumerically(">", 0))
			Ω(procTime.Total).Should(BeNumerically(">", 0))

		})
		It("retieves command line parmeters", func() {
			procArgs := sigar.ProcArgs{}

			//get a random process
			procList := sigar.ProcList{}
			_ = procList.Get()
			rand.Seed(52)
			pid := procList.List[rand.Intn(len(procList.List))]

			err := procArgs.Get(pid)
			Ω(err).ShouldNot(HaveOccurred())
			Ω(len(procArgs.List)).Should(BeNumerically(">", 0))

		})
		It("retieves process memory usage", func() {
			procMem := sigar.ProcMem{}

			//get a random process
			procList := sigar.ProcList{}
			_ = procList.Get()
			rand.Seed(22)
			pid := procList.List[rand.Intn(len(procList.List))]

			err := procMem.Get(pid)
			Ω(err).ShouldNot(HaveOccurred())
			Ω(procMem.Size).Should(BeNumerically(">", 0))
			Ω(procMem.Resident).Should(BeNumerically(">", 0))
			Ω(procMem.Share).Should(BeNumerically(">", 0))
			Ω(procMem.PageFaults).Should(BeNumerically(">", 0))

		})
		It("retieves process exe", func() {
			procExe := sigar.ProcExe{}

			//get a random process
			procList := sigar.ProcList{}
			_ = procList.Get()
			rand.Seed(23)
			pid := procList.List[rand.Intn(len(procList.List))]

			err := procExe.Get(pid)
			Ω(err).ShouldNot(HaveOccurred())
			Ω(len(procExe.Name)).Should(BeNumerically(">", 0))

		})
	})
})
