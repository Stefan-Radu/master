import Lake
open Lake DSL

package experiemnts {
  -- add package configuration options here
}

lean_lib Experiemnts {
  -- add library configuration options here
}

@[defaultTarget]
lean_exe experiemnts {
  root := `Main
}
