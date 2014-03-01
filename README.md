Description
====
This is a Linux-based guest OS extension for vAMP. For more information about vAMP, refer to [here](https://github.com/virtualAMP/vamp-linux) first. The role of this extension is to simply isolate interactive tasks on separate vCPUs from background ones in order to prevent different types of tasks from time-sharing a single vCPU. This extension is implemented as a user-land program, which exploits information exposed by the vAMP hypervisor extension through guest kernel. The information indicates which tasks are currently identified as background workloads, and the exposure is done by using shared memory between guest kernel and hypervisor. The kernel lets the user-space program via *procfs*.

Usage
====
#### 1. Paravirtualized kernel
For this extension to work, the paravirtualized kernel should be installed first in a guest VM. The [vamp-linux](https://github.com/virtualAMP/vamp-linux) includes a paravirtualized feature for vAMP as well as its hypervisor extension, so you can use the kernel as a guest kernel.

#### 2. User-level guest OS extension
The extension uses *cgroup cpuset* to place tasks on a specified set of vCPUs, so make sure that the guest kernel supports it (most Linux distributions support cgroups by default).  

To build, you can simply do make.

```
# make
```

The program *vdiguest* has the following options:

* `-f <# of initial fast vCPUs>` is the number of fast vCPUs for interactive tasks. This number is initially given and is incremented as fast vCPUs are saturated (highly utilized). Usually 1 is sufficient, but at least 2 is needed to track audio-generating tasks (See Section 3.1.3 and 3.3 in the [paper](http://vee2014.cs.technion.ac.il/papers/VEE14-final23.pdf))
* `-m <mode>` is the mode to govern how to adjust the number of fast and slow vCPUs. The available modes are explained by usage information in vdiguest program (simply enter ./vdiguest). The mode 2 is used for the evaluation in the paper. 
* `-p <monitoring period>` is the monitoring period with which the extension periodically polls the background task information, which is shared by vAMP hypervisor extension. 1000msec is used for the evaluation.
* `-i <irq num to be pinned>` is the IRQ number of an I/O device that is pinned to fast vCPUs for quickly processing interrupts. For example, it can be set to the IRQ number of virtio disk. See the detail in Section 3.3 in the paper.
* `-v <verbose level>` is the verbose level to show how it works.

After options, you should put keyboard and mouse input event channels like /dev/input/event#.
In the Ubuntu-based KVM guest, /dev/input/event1 and /dev/input/event2 are typically keyboard and mouse channels, respectively; but, you should check it. For example, use the following command.

```
# ./vdiguest -f 1 -v 0 -p 1000 -m 2 -i 53 /dev/input/event1 /dev/input/event2
```

This does not support daemon mode currently, so you can run in background by adding &.

#### 3. Helper script for *pulseaudio*
Aside from input devices, vdiguest should identify audio output as well. Since vdiguest works in an event-driven manner, it is unable to know when it starts to do isolation without audio event tracking. To make vdiguest identify the audio event, a helper script is needed to run. *vdiguest-pulseaudio* is a pulseaudio-specific script using *pacmd* to inform vdiguest of audio event via FIFO (/tmp/vdiguest-audio). This script needs only one parameter as a monitoring period.

```
# ./vdiguest-pulseaudio 1
``` 


