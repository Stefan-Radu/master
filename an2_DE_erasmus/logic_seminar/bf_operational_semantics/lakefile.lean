import Lake
open Lake DSL

package «bf_operational_semantics» where
  -- add package configuration options here

lean_lib «BfOperationalSemantics» where
  -- add library configuration options here

@[default_target]
lean_exe «bf_operational_semantics» where
  root := `Main
