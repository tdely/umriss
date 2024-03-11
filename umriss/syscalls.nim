import std/tables

const url* = "https://linux.die.net/man/2/"

when defined(generateSyscalls):
  import std / [htmlparser, os, strtabs, strutils, xmltree]
  import puppy

  proc buildTable(): Table[string, string] =
    let
      html = parseHtml(fetch(url))
      d = html.child("html").child("body").child("div").findAll("div")[1]
      dts = d.findAll("dt")
      dds = d.findAll("dd")
    var i: int
    while i < dts.len:
      let a = dts[i].child("a")
      if a != nil:
        let name = dts[i].child("a").attrs["href"]
        result[name] = dds[i].innerText.strip()
      else:
        break
      inc i

  proc generateFile(tbl: Table[string, string]) =
    var output = "import std/tables\n\nconst syscallTable* = {\n"
    for k, v in tbl.pairs:
      output.add "  \"" & k & "\": \"" & v & "\",\n"
    output.add "}.toTable()\n"
    writeFile(currentSourcePath.parentDir / "_syscalls.nim", output)

  let syscallTable = buildTable()
  generateFile(syscallTable)
else:
  include "_syscalls.nim"

proc getSyscallDesc*(name: string): string {.inline.} =
  syscallTable.getOrDefault(name, "")
