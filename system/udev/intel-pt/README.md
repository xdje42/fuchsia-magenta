# Intel Processor Trace driver

See Chapter 36 of the Intel Architecture Software Developer's Manual.

## Trace modes

There are two modes of tracing:

- per cpu
- specified threads

Only one may be active at a time.

Per CPU tracing is started/stopped with ioctl_ipt_start()/ioctl_pt_stop().

Thread-specific tracing is started/stopped by writing to regset #2
(currently #2 - likely to change). As with other writes to thread registers,
the thread must be stopped.

### Per CPU tracing

In this mode of operation each cpu is traced, regardless of what is
running on the cpu, except as can be controlled by PT configuration MSRs
(e.g., cr3 filtering, kernel/user, address filtering).

### Specified thread tracing

In this mode of operation individual threads are traced, even as they
migrate from CPU to CPU. This is achieved via the PT state save/restore
capabilities of the XSAVES and XRSTORS instructions.

Filtering control (e.g., cr3, user/kernel) is not available in this mode.
Address filtering is possible, but is still TODO.

## Notes

- We currently only support Table of Physical Addresses mode currently,
so that we can also support stop-on-full behavior in addition to wrap-around.

- Each cpu has the same size trace buffer.

- While it's possible to allocate and configure buffers outside of the driver,
this is not done so that we have control over their contents. ToPA buffers
must have specific contents or Bad Things can happen.

TODOs (beyond those in the source)

- support tracing individual threads using xsaves

- handle driver crashes
  - need to turn off tracing
  - need to keep buffer/table vmos alive until tracing is off
