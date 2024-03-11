# umriss

Extract per thread or aggregated syscall information from strace output files.

Umriss can outline syscall usage as reported by strace by aggregating and
creating a list of syscalls in order of appearance.
The intended use case is to simplify the process of creating seccomp rulesets.

## Usage

The default is to aggregate per thread, ignore number of arguments to the syscall, and list call count.

```
$ umriss example1.log example2.log
[pid example1.log:17095]
     1  execve
     3  brk
     1  access
     2  openat
     3  fstat
     8  mmap
     2  close
     1  read
     2  pread64
     1  arch_prctl
     1  set_tid_address
     1  set_robust_list
     1  rseq
     3  mprotect
     1  prlimit64
     1  munmap
     1  getrandom
     1  write
     1  exit_group
[pid example2.log:18054]
     1  execve
     3  brk
     1  access
     3  openat
     4  fstat
    12  mmap
     3  close
     2  read
     2  pread64
     1  arch_prctl
     1  set_tid_address
     1  set_robust_list
     1  rseq
     4  mprotect
     1  prlimit64
     1  munmap
     1  getrandom
     2  write
     1  clock_nanosleep
     1  exit_group
```

You can `--squash` threads and use `--nargs` to split same-name syscalls by
argument count.

```
$ umriss --squash --nargs example1.log example2.log
     2  execve(3)
     6  brk(1)
     2  access(2)
     5  openat(3)
     7  fstat(2)
    20  mmap(6)
     5  close(1)
     3  read(3)
     4  pread64(4)
     2  arch_prctl(2)
     2  set_tid_address(1)
     2  set_robust_list(2)
     2  rseq(4)
     7  mprotect(3)
     2  prlimit64(4)
     2  munmap(2)
     2  getrandom(3)
     3  write(3)
     2  exit_group(1)
     1  clock_nanosleep(4)
```

It's also possible to start counting `--from` the first occurrence of a syscall.

```
$ umriss --from mmap example1.log
[pid example1.log:17095]
     8  mmap
     2  close
     1  openat
     1  read
     2  pread64
     2  fstat
     1  arch_prctl
     1  set_tid_address
     1  set_robust_list
     1  rseq
     3  mprotect
     1  prlimit64
     1  munmap
     1  getrandom
     2  brk
     1  write
     1  exit_group
```

More informative output can be created by using `--annotate`, showing a brief description of each syscall.

```
$ umriss --annotate example1.log
[pid example1.log:17095]
     1  execve                 execute program
     3  brk                    change data segment size
     1  access                 check real user's permissions for file
     2  openat                 open file relative to directory file descriptor
     3  fstat                  file status
     8  mmap                   map/unmap files/devices into memory
     2  close                  close file descriptor
     1  read                   read from file descriptor
     2  pread64                read from/write to file descriptor at given offset
     1  arch_prctl             set architecture-specific thread state
     1  set_tid_address        set pointer to thread ID
     1  set_robust_list        get/set list of robust futexes
     1  rseq
     3  mprotect               set protection on region of memory
     1  prlimit64
     1  munmap                 map/unmap files/devices into memory
     1  getrandom
     1  write                  to file descriptor
     1  exit_group             exit all threads in process
```

The output can be changed into a list of `add_rule` operations for [the Nim seccomp package](https://github.com/FedericoCeratto/nim-seccomp).

```
$ umriss --output seccomp example1.log
[pid example1.log:17095]
ctx.add_rule(Allow, "execve")
<output omitted to save space>
```

Using `--annotate` with `--output seccomp` will manifest comments.

```
$ umriss --output seccomp --annotate example1.log
[pid example1.log:17095]
ctx.add_rule(Allow, "execve")                # execute program
<output omitted to save space>
```

## All Options
```
Usage:
  umriss [optional-params] files...
Extract per thread or aggregated syscall information from strace output files
Options(opt-arg sep :|=|spc):
  -h, --help                       print this cligen-erated help
  --help-syntax                    advanced: prepend,plurals,..
  --version       bool    false    print version
  -o=, --output=  string  "stats"  the type of output to generate:
                                     stats: print syscall statistics (default)
                                     seccomp: create and print a list of seccomp add_rule commands
  -s, --squash    bool    false    do not separate syscalls by thread
  -n, --nargs     bool    false    make number of syscall arguments significant
  -a, --annotate  bool    false    show short description of each syscall
  -f=, --from=    string  ""       only record syscalls after observing given syscall
  --seccomp-ctx=  string  "ctx"    specify context var name for seccomp output
```