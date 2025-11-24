# eBPF TCP Close-Wait Monitor

This project provides an eBPF-based tool for observing how long TCP connections remain in the **TCP_CLOSE_WAIT** state. It hooks into kernel TCP state transitions, records timestamps for relevant sockets, and reports per-connection durations when they enter and exit CLOSE_WAIT.

## Overview

TCP connections can enter `CLOSE_WAIT` when the remote peer closes the connection but the local application has not yet performed its own `close()`. Long durations in this state often signal issues in application logic, such as stuck threads, resource leaks, or delayed cleanup.

This tool helps identify problematic connections by measuring how long each socket stays in `TCP_CLOSE_WAIT`.

## Features

- Attaches to kernel TCP state change tracepoints or kprobes (depending on configuration).
- Tracks individual sockets by their tuple (source/destination addresses and ports).
- Records timestamps when a socket enters `TCP_CLOSE_WAIT`.
- Computes and reports the total duration when the socket transitions out of that state.
- Sends events to userspace via a ring buffer.
- Supports CO-RE (Compile Once, Run Everywhere) for portability across kernel versions.

## How It Works

1. **State Tracking**  
   The eBPF program detects when a socket transitions into `TCP_CLOSE_WAIT` and stores the current timestamp in a hash map keyed by socket identity.

2. **Duration Measurement**  
   When the same socket changes out of `CLOSE_WAIT` (for example to `LAST_ACK`), the program calculates the time delta between entry and exit.

3. **Event Delivery**  
   The computed duration is emitted to userspace via a ring buffer, where the userspace application prints or processes it.

## Building

You will need:

- Clang/LLVM with BPF target  
- libbpf (system-installed or vendor-bundled)  
- Kernel headers  
- A recent Linux kernel with eBPF support enabled

Build and Run the project:

```bash
make -B
sudo ./tcpcw
