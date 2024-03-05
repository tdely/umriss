import std / [os, strformat, tables]

type
  Syscalls = OrderedTable[string, int]
  Stats = OrderedTable[string, Syscalls]

const num = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}

proc count(res: var Stats, pid, sc: string, squash: bool) =
  let pid = if squash: "" else: pid
  if not res.hasKey(pid):
    res[pid] = Syscalls()
  if not res[pid].hasKey(sc):
    res[pid][sc] = 1
  else:
    inc res[pid][sc]

proc parseLine(line: string): tuple[pid, syscall: string] =
  var
    i: int
    c: char
    pid, sc: string
  assert line[i] in num
  while i <= line.high:
    c = line[i]
    i.inc
    if c == '<':
      break
    elif c == '(':
      if sc.len > 0:
        result = (pid: pid, syscall: sc)
      break
    elif c in num and sc.len == 0:
      pid.add c
    elif c != ' ':
      sc.add c

proc printStats(stats: Stats) =
  for pid, tbl in stats.pairs:
    if pid != "":
      echo fmt"[pid {pid:>6}]"
    for sc, count in tbl.pairs:
      echo fmt"{count:>4}  {sc}"

proc printSeccomp(stats: Stats, ctx: string) =
  for pid, tbl in stats.pairs:
    if pid != "":
      echo fmt"[pid {pid:>6}]"
    for sc in tbl.keys:
      echo ctx & ".add_rule(Allow, \"" & sc & "\")"

proc run(action = "stats"; squash = false; seccomp_ctx = "ctx"; files: seq[string]): int =
  if files.len == 0:
    echo "expects one or more arguments"
    return 1
  var
    stats: Stats
    line: string
  for fp in files:
    var f = open(fp, fmRead)
    while f.readLine(line):
      if (let p = parseLine(line); p.syscall != ""):
        let k = if squash: p.pid else: extractFilename(fp) & ':' & p.pid
        stats.count(k, p.syscall, squash)
  case action:
  of "stats":
    stats.printStats()
  of "seccomp":
    stats.printSeccomp(seccomp_ctx)
  else:
    echo "unknown --action: " & action
    return 1

when isMainModule:
  import cligen

  const
    progName = "umriss"
    progUse = "Usage:\n  " & progName & " [optional-params] files..."
    progVer {.strdefine.} = strip(gorge("git tag -l --sort=version:refname '*.*.*' | tail -n1"))

  clCfg.version = progVer

  dispatchCf run, cmdName = progName, cf = clCfg, noHdr = true,
    usage = progUse & "\n\nOptions(opt-arg sep :|=|spc):\n$options",
    help = {
      "action": """the action to perform:
  stats: print syscall statistics (default)
  seccomp: create and print a list of seccomp add_rule commands""",
      "squash": "do not separate syscalls by thread",
      "seccomp-ctx": "specify context var name for seccomp action",
    }
