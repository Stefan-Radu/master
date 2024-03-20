
def main: IO Unit := do
  let stdin <- IO.getStdin
  let stdout <- IO.getStdout

  IO.print "What is your name?: "
  let input <- stdin.getLine
  let name := input.dropRightWhile Char.isWhitespace

  stdout.putStrLn s!"Hello, {name}!"

