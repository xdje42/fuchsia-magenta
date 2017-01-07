# Intel Processor Trace driver

See Chapter 36 of the Intel Architecture Software Developer's Manual.

## Notes

- We currently only support Table of Physical Addresses mode currently,
so that we can have stop-on-full behavior rather than wrap-around.

- Each cpu has the same size trace buffer.

TODOs (beyond those in the source)

- support tracing individual threads using xsaves
