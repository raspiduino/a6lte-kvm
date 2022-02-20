# Windows for ARM(64) on a6lte-kvm
## PMU
EDK II and Windows ARM require the following registers to be trapped and emulated in [`sys_regs.c`](https://github.com/raspiduino/a6lte-kvm/blob/pmu/arch/arm64/kvm/sys_regs.c):
```
root@localhost:~# cat /proc/kmsg | grep "sys_regs"
[EDK II bootup]
<7>[ 1830.070417]  [0:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 0, CRn = 1, CRm = 0, Op2 = 0, Rt = 0, is_write = 1
<7>[ 1830.070447]  [0:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 0, CRn = 1, CRm = 0, Op2 = 0, Rt = 0, is_write = 1
<7>[ 1830.550467]  [2:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 0, CRn = 2, CRm = 0, Op2 = 2, Rt = 0, is_write = 1
<7>[ 1830.550510]  [2:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 0, CRn = 2, CRm = 0, Op2 = 0, Rt = 0, is_write = 1
<7>[ 1830.551762]  [2:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 0, CRn = 10, CRm = 2, Op2 = 0, Rt = 0, is_write = 1
<7>[ 1830.551778]  [2:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 0, CRn = 1, CRm = 0, Op2 = 0, Rt = 0, is_write = 1
<7>[ 1830.551794]  [2:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 0, CRn = 1, CRm = 0, Op2 = 0, Rt = 0, is_write = 1
<7>[ 1830.551809]  [2:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 0, CRn = 1, CRm = 0, Op2 = 0, Rt = 0, is_write = 1
<7>[ 1830.551824]  [2:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 0, CRn = 1, CRm = 0, Op2 = 0, Rt = 0, is_write = 1
<7>[ 1830.551839]  [2:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 0, CRn = 1, CRm = 0, Op2 = 0, Rt = 0, is_write = 1
[After manually load bootaa64.efi]
<7>[ 2293.777493]  [2:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 3, CRn = 9, CRm = 13, Op2 = 0, Rt = 8, is_write = 0  => PMCCNTR_EL0
<7>[ 2293.777546]  [2:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 3, CRn = 9, CRm = 12, Op2 = 0, Rt = 8, is_write = 0  => PMCR_EL0
<7>[ 2293.777571]  [2:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 3, CRn = 9, CRm = 12, Op2 = 2, Rt = 10, is_write = 1 => PMCNTENCLR_EL0
<7>[ 2293.777595]  [2:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 3, CRn = 9, CRm = 12, Op2 = 3, Rt = 8, is_write = 1  => PMOVSCLR_EL0   (unimplemented)
<7>[ 2293.777617]  [2:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 0, CRn = 9, CRm = 14, Op2 = 2, Rt = 10, is_write = 1 => PMINTENCLR_EL1 (unimplemented)
<7>[ 2293.777639]  [2:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 3, CRn = 9, CRm = 12, Op2 = 0, Rt = 8, is_write = 1  => PMCR_EL0
<7>[ 2293.777661]  [2:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 3, CRn = 14, CRm = 15, Op2 = 7, Rt = 9, is_write = 1 => PMCCFILTR_EL0
<7>[ 2293.777708]  [2:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 3, CRn = 9, CRm = 12, Op2 = 1, Rt = 8, is_write = 1  => PMCNTENSET_EL0
<7>[ 2293.777738]  [2:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 3, CRn = 9, CRm = 14, Op2 = 0, Rt = 9, is_write = 1  => PMUSERENR_EL0  (unimplemented)
<7>[ 2293.781100]  [2:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 3, CRn = 9, CRm = 13, Op2 = 0, Rt = 20, is_write = 0 => PMCCNTR_EL0
<7>[ 2293.782409]  [2:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 3, CRn = 9, CRm = 13, Op2 = 0, Rt = 19, is_write = 0 => PMCCNTR_EL0
<7>[ 2293.791457]  [2:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 3, CRn = 9, CRm = 13, Op2 = 0, Rt = 8, is_write = 0  => PMCCNTR_EL0
<7>[ 2293.795274]  [3:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 3, CRn = 9, CRm = 13, Op2 = 0, Rt = 19, is_write = 0 => PMCCNTR_EL0
<7>[ 2294.109411]  [3:qemu-system-aar: 6889] KVM sys_regs trap: Op0 = 3, Op1 = 3, CRn = 9, CRm = 13, Op2 = 0, Rt = 8, is_write = 0  => PMCCNTR_EL0
```
Note that the log's value is in decimal (output with `%d`), not hex! I also added some notes to make it easier to understand which register is being trapped.
<br>The above log is generated inserting a simple `prink` to [this line](https://github.com/raspiduino/a6lte-kvm/blob/25292853c38cb2bd1d28fe9cf7032a760fa78a76/arch/arm64/kvm/sys_regs.c#L1309) in the code:

```c
int kvm_handle_sys_reg(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	struct sys_reg_params params;
	unsigned long esr = kvm_vcpu_get_hsr(vcpu);

	params.is_aarch32 = false;
	params.is_32bit = false;
	params.Op0 = (esr >> 20) & 3;
	params.Op1 = (esr >> 14) & 0x7;
	params.CRn = (esr >> 10) & 0xf;
	params.CRm = (esr >> 1) & 0xf;
	params.Op2 = (esr >> 17) & 0x7;
	params.Rt = (esr >> 5) & 0x1f;
	params.is_write = !(esr & 1);

	// Stupid printk for debugging trap-and-emulate process
	printk(KERN_DEBUG "KVM sys_regs trap: Op0 = %d, Op1 = %d, CRn = %d, CRm = %d, Op2 = %d, Rt = %d, is_write = %d\n", params.Op0, params.Op1, params.CRn, params.CRm, params.Op2, params.Rt, params.is_write);

	return emulate_sys_reg(vcpu, &params);
}
```
Remember to
```c
#include <linux/kern_levels.h>
```
or your compiler will complain!

I also wrote a simple Python script for converting the log to strings which can be used to find the line that the registers is trapped in `sys_regs.c`:
```python
def trap(s):
	a = s.split(", ")
	b = []

	Op0 = int(a[0].split(" = ")[1])
	b.append("Op0(0b" + f'{Op0:02b}' + ")")

	Op1 = int(a[1].split(" = ")[1])
	b.append("Op1(0b" + f'{Op1:03b}' + ")")

	CRn = int(a[2].split(" = ")[1])
	b.append("CRn(0b" + f'{CRn:04b}' + ")")

	CRm = int(a[3].split(" = ")[1])
	b.append("CRm(0b" + f'{CRm:04b}' + ")")

	Op2 = int(a[4].split(" = ")[1])
	b.append("Op2(0b" + f'{Op2:03b}' + ")")

	return ', '.join(b)

```
Save it at `trap.py`. Then open your Python console, run:
```python
>>> import trap
>>> trap.trap("Op0 = 3, Op1 = 3, CRn = 9, CRm = 13, Op2 = 0")
'Op0(0b11), Op1(0b011), CRn(0b1001), CRm(0b1101), Op2(0b000)'
>>>
```
Replace the string passed to `trap.trap()` to the line you want to convert. Then open `sys_regs.c`, use <kbd>CTRL</kbd>+<kbd>F</kbd> and paste the converted string to search.

---------
Link to registers trap code:
|Register name and trap code|Description|ARM document link|Implement status|
|-----|-----|-----|-----|
|[`PMCCNTR_EL0`](https://github.com/raspiduino/a6lte-kvm/blob/25292853c38cb2bd1d28fe9cf7032a760fa78a76/arch/arm64/kvm/sys_regs.c#L597)|Performance Monitors Cycle Count Register|[Link](https://developer.arm.com/documentation/ddi0595/2021-06/AArch64-Registers/PMCCNTR-EL0--Performance-Monitors-Cycle-Count-Register)|Implemented|
|[`PMCR_EL0`](https://github.com/raspiduino/a6lte-kvm/blob/25292853c38cb2bd1d28fe9cf7032a760fa78a76/arch/arm64/kvm/sys_regs.c#L574)|Performance Monitors Control Register|[Link](https://developer.arm.com/documentation/ddi0595/2020-12/External-Registers/PMCR-EL0--Performance-Monitors-Control-Register)|Implemented|
|[`PMCNTENCLR_EL0`](https://github.com/raspiduino/a6lte-kvm/blob/25292853c38cb2bd1d28fe9cf7032a760fa78a76/arch/arm64/kvm/sys_regs.c#L573)|Performance Monitors Count Enable Clear register|[Link](https://developer.arm.com/documentation/ddi0595/2021-06/AArch64-Registers/PMCNTENCLR-EL0--Performance-Monitors-Count-Enable-Clear-register)|Implemented|
|[`PMOVSCLR_EL0`](https://github.com/raspiduino/a6lte-kvm/blob/25292853c38cb2bd1d28fe9cf7032a760fa78a76/arch/arm64/kvm/sys_regs.c#L583)|Performance Monitors Overflow Flag Status Clear Register|[Link](https://developer.arm.com/documentation/ddi0595/2021-06/AArch64-Registers/PMOVSCLR-EL0--Performance-Monitors-Overflow-Flag-Status-Clear-Register)|Unimplemented|
|[`PMINTENCLR_EL0`](https://github.com/raspiduino/a6lte-kvm/blob/25292853c38cb2bd1d28fe9cf7032a760fa78a76/arch/arm64/kvm/sys_regs.c#L539)|To be filled|To be filled|Unimplemented|
|[`PMCCFILTR_EL0`](https://github.com/raspiduino/a6lte-kvm/blob/25292853c38cb2bd1d28fe9cf7032a760fa78a76/arch/arm64/kvm/sys_regs.c#L686)|Performance Monitors Cycle Count Filter Register|[Link](https://developer.arm.com/documentation/ddi0595/2020-12/AArch64-Registers/PMCCFILTR-EL0--Performance-Monitors-Cycle-Count-Filter-Register)|Implemented|
|[`PMCNTENSET_EL0`](https://github.com/raspiduino/a6lte-kvm/blob/25292853c38cb2bd1d28fe9cf7032a760fa78a76/arch/arm64/kvm/sys_regs.c#L576)|Performance Monitors Count Enable Set register|[Link](https://developer.arm.com/documentation/ddi0595/2020-12/AArch64-Registers/PMCNTENSET-EL0--Performance-Monitors-Count-Enable-Set-register)|Implemented|
|[`PMUSERENR_EL0`](https://github.com/raspiduino/a6lte-kvm/blob/25292853c38cb2bd1d28fe9cf7032a760fa78a76/arch/arm64/kvm/sys_regs.c#L606)|Performance Monitors User Enable Register|[Link](https://developer.arm.com/documentation/ddi0595/2020-12/AArch64-Registers/PMUSERENR-EL0--Performance-Monitors-User-Enable-Register)|Unimplemented|

The process is being made at the [`pmu`](https://github.com/raspiduino/a6lte-kvm/tree/pmu) branch and will soon be merged back to `main` branch when it finished.
<br> You can help us to make the work faster by sending pull requests! Thank you!
