# Wet Socks

_Report leaky sockets with a `LD_PRELOAD` module_

## What Is This

Detect potentially leaky sockets, using a `LD_PRELOAD` module preload. Sockets that are still alive after a given time are listed in a dump file produced regularly for audit purpose.

The following calls are intercepted to audit:

* `socket`
* `socketpair`
* `accept`
* `accept4`
* `close`

## Building

```shell
cmake .
make
```

## Usage

```shell
LD_PRELOAD=libwetsocks.so your_program your_arguments ...
```

## Example

```shell
LD_PRELOAD=$PWD/libwetsocks.so myserver >/dev/null
```

## Settings

The following environment variables can be defined to tune the thresholds:

* `WETSOCKS_DUMP_EVERY_S` : Dump every seconds (300)
* `WETSOCKS_YOUNGEST_ENTRY_S` : Youngest socket to be considered leaking (1800)
* `WETSOCKS_WARMUP_ENTRY_S` : Grace for process to stabilize at startup (300)
* `WETSOCKS_DUMP_FILE_PREFIX` : Dump file prefix (leaky-socket-stats-for-pid-)
* `WETSOCKS_SILENT` : Don't emit any superfluous stuff on stderr (false)

## How ?

This small library design is pretty straightforward:

* Define exported (strong) symbols that will override glibs weak symbols (`accept`, etc.)
* Call `RTLD_NEXT` symbol otherwise

A bit of fancy C++ syntaxic sugar has been used to ease helpers, but everything could probably be moved to plain C++.

