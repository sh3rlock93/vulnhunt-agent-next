# M11.3 caller/callee capacity alias recovery

M11.3 closes the ranking gap exposed by the libjpeg-turbo issue 387 blind run.
The implementation remains generic: no libjpeg symbol or path is used by the
analyzer.

## Scope

- Root nested assignment lvalues at their destination object instead of an
  array index.
- Track pointer-array and local pointer aliases back to pointer parameters.
- Propagate callee write summaries through those aliases to caller parameters.
- Treat a cross-call memory write as a complete capacity path even when no
  consumed-length return or local pointer advance exists.
- Retain the assignment that derives a memory-write extent and distinguish raw
  arithmetic from a dedicated size/width/height/capacity/extent helper.  The
  helper case remains an unknown guard rather than being declared safe.

## Release gate

The blind fixture pins the parent and fix commits of libjpeg-turbo issue 387.
Discovery receives only the vulnerable tree and a fixed 12-session budget.  The
oracle and fixed tree are opened after the discovery artifacts are frozen and
hashed.  The gate requires:

- caller-to-wrapper-to-leaf pointer aliases and writes to be recovered;
- the vulnerable chain to rank as complete and unchecked within the first six
  paid Hunter sessions (deferred and duplicate records do not consume one);
- both required source files to fit in a context no larger than 24 KB;
- the fixed chain not to remain complete and unchecked; and
- all terminal routes and policy versions to be auditable.
