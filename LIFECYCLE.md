# Connectsnoop Lifecycle

```mermaid
flowchart TD
    A[make build] --> B[Compile bpf/connectsnoop.bpf.c]
    B --> C[Write bpf/connectsnoop.bpf.o]
    C --> D[Build Go loader bin/connectsnoop]
    D --> E[sudo ./bin/connectsnoop]

    E --> F[Read eBPF ELF section]
    F --> G[Load program with bpf BPF_PROG_LOAD]
    G --> H[Read sys_enter_connect tracepoint ID]
    H --> I[Open tracepoint perf event]
    I --> J[Attach program with PERF_EVENT_IOC_SET_BPF]
    J --> K[Enable perf event]

    K --> L[Tail /sys/kernel/tracing/trace_pipe]
    M[Process calls connect] --> N[eBPF handle_connect runs]
    N --> O[Read sockaddr from user memory]
    O --> P[Print destination with bpf_trace_printk]
    P --> L
    L --> Q[Print connect lines to terminal]

    R[Ctrl-C or SIGTERM] --> S[Close trace_pipe]
    S --> T[Close perf event fd]
    T --> U[Close eBPF program fd]
    U --> V[Kernel detaches and releases program]
```

## Notes

- The object file has no maps or relocations, so the Go loader reads raw
  instructions directly from the ELF section.
- The tracepoint attachment is owned by the open perf-event fd. When the process
  exits and closes that fd, the kernel detaches the program.
- `trace_pipe` is a live stream. Reading it consumes matching trace output.
