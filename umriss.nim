import std / [os, strformat, strutils, tables]
import umriss/syscalls

type
  Syscalls = OrderedTable[string, int]
  Stats = OrderedTable[string, Syscalls]

const num = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}

proc count(stats: var Stats, pid, sc: string) =
  if not stats.hasKey(pid):
    stats[pid] = Syscalls()
  if not stats[pid].hasKey(sc):
    stats[pid][sc] = 1
  else:
    inc stats[pid][sc]

proc squash(stats: sink Stats): Stats =
  result[""] = Syscalls()
  for syscalls in stats.values:
    for sc, count in syscalls.pairs:
      if not result[""].hasKey(sc):
        result[""][sc] = count
      else:
        inc(result[""][sc], count)

proc parseArguments(line: sink string, i: var int): seq[string] =
  var
    c, b: char
    arg: string
    queue: seq[char]
    instring: bool
  assert line[i] == '('
  inc i
  while i <= line.high:
    c = line[i]
    if b != '\\':
      if c == '"':
        if queue.len > 0 and queue[^1] == '"':
          discard queue.pop()
          instring = false
        else:
          queue.add '"'
          instring = true
      elif not instring:
        if c in {',', ')'} and queue.len == 0:
          result.add newStringOfCap(arg.len)
          result[^1] = move(arg)
          if c == ',':
            arg = ""
          else:
            break
        elif c in {'(', '[', '{'}:
          queue.add case c
            of '(':
              ')'
            of '[':
              ']'
            of '{':
              '}'
            else:
              raise newException(Defect, "this shouldn't be able to happen")
        elif queue.len > 0 and c == queue[^1]:
          discard queue.pop()
    b = if c == '\\' and b == '\\': ' ' else: c
    if arg.len > 0 or c notin {',', ' '}:
      arg.add c
    inc i

proc parseLine(line: sink string): tuple[pid, syscall: string, nargs: int] =
  var
    i: int
    c: char
    pid, sc: string
  assert line[i] in num
  while i <= line.high:
    c = line[i]
    if c == '<':
      break
    elif c == '(':
      if sc.len > 0:
        let args = line.parseArguments(i)
        result = (pid: pid, syscall: sc, nargs: args.len)
      break
    elif c in num and sc.len == 0:
      pid.add c
    elif c != ' ':
      sc.add c
    i.inc

proc printStats(stats: Stats, annotate: bool) =
  for pid, tbl in stats.pairs:
    if pid != "":
      echo fmt"[pid {pid}]"
    for sc, count in tbl.pairs:
      var output = fmt"{count:>6}  {sc}"
      if annotate:
        let
          i = sc.find('(')
          desc = getSyscallDesc(if i != -1: sc[0..i-1] else: sc)
        output = fmt"{output:<30} " & desc
      echo output

proc printSeccomp(stats: Stats, ctx: string, annotate: bool) =
  for pid, tbl in stats.pairs:
    if pid != "":
      echo fmt"[pid {pid}]"
    for sc in tbl.keys:
      var
        nargs: string
        name = sc
      if (let i = sc.find('('); i) != -1:
        nargs = sc[i+1..^2]
        name = sc[0..i-1]
      var output = ctx & ".add_rule(Allow, \"" & name & "\""
      output.add if nargs.len > 0: fmt", {nargs})" else: ")"
      if annotate:
        if (let desc = getSyscallDesc(name); desc.len) > 0:
          output = fmt"{output:<45}" & "# " & desc
      echo output

proc run(action = "stats"; squash = false; nargs = false; annotate = false; `from` = ""; seccomp_ctx = "ctx"; files: seq[string]): int =
  if files.len == 0:
    echo "expects one or more arguments"
    return 1
  var
    stats: Stats
    line: string
  for fp in files:
    var
      f = open(fp, fmRead)
      hits: int
    let fname = extractFilename(fp)
    while f.readLine(line):
      if (let p = parseLine(line); p.syscall != ""):
        let k = fname & ':' & p.pid
        if `from` == "" or (stats.hasKey(k) or p.syscall == `from`):
          if nargs:
            stats.count(k, fmt"{p.syscall}({p.nargs})")
          else:
            stats.count(k, p.syscall)
          inc hits
    close f
    if hits == 0:
      stderr.writeLine "warning: no syscalls recorded for file " & fname
  if stats.len == 0:
    return 0
  if squash:
    stats = squash(stats)
  case action:
  of "stats":
    stats.printStats(annotate)
  of "seccomp":
    stats.printSeccomp(seccomp_ctx, annotate)
  else:
    echo "unknown --action: " & action
    return 1

when isMainModule:
  import cligen

  const
    progName = "umriss"
    progVer {.strdefine.} = strip(gorge("git tag -l --sort=version:refname '*.*.*' | tail -n1"))
    progUse = fmt"""
Usage:
  {progName} [optional-params] files...
Extract per thread or aggregated syscall information from strace output files
Options(opt-arg sep :|=|spc):
$options"""

  clCfg.version = progVer

  dispatchCf run, cmdName = progName, cf = clCfg, noHdr = true,
    usage = progUse,
    help = {
      "action": """the action to perform:
  stats: print syscall statistics (default)
  seccomp: create and print a list of seccomp add_rule commands""",
      "annotate": "show short description of each syscall",
      "from": "only record syscalls after observing given syscall",
      "nargs": "make number of syscall arguments significant",
      "squash": "do not separate syscalls by thread",
      "seccomp-ctx": "specify context var name for seccomp action",
    }
