version       = "0.5.0"
author        = "Tobias Dély"
description   = "Extract syscall stats from strace output files"
license       = "MIT"
binDir        = "bin"
bin           = @["umriss"]

requires "nim >= 2.0.2"
requires "cligen >= 1.7.0 & < 2.0.0"
