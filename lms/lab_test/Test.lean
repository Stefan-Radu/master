/-
  Problem 1:
  Consider the following inductive type `T`.
  Define the function `T.isNat` such that 
  `T.isNat x` returns `true` if and only if 
  `x` contains no `pred` constructors.

  It should satisfy the tests given below.
-/
inductive T where 
| zero : T 
| succ : T → T 
| pred : T → T 

def T.isNat : T → Bool := 
  fun t: T =>
    match t with
    | zero => true
    | succ hl => T.isNat hl
    | pred _ => false

example : T.isNat (T.zero) = true := by rfl
example : T.isNat (T.succ (T.succ T.zero)) = true := by rfl
example : T.isNat (T.succ (T.pred T.zero)) = false := by rfl 

variable (p q : Prop)

/- Probem 2: Prove the following theorem -/

theorem dni {p: Prop}: p → ¬¬p := 
  fun hp: p  => 
  let h': ¬p ∨ ¬¬p := Classical.em ¬p
  match h' with
  | Or.inl hnp => 
    let f: False := hnp hp
    False.elim f
  | Or.inr hnnp => hnnp


-- ¬p := p -> False
-- ¬¬p := (p -> False) -> False

theorem dni' {p: Prop}: p → ¬¬p := 
  fun hp: p => fun hnp: ¬p => hnp hp

theorem p2 : p ∧ q → ¬¬q ∨ ¬p := 
  fun hpandq: p ∧ q =>
    have hq: q := And.right hpandq
    have hnnq: ¬¬q := dni hq
    -- m-am uitiat in metrou pe documentatie si mi am vazut 
    -- ca merge scris asa si am zis ca e mai frumos
    show ¬¬q ∨ ¬p from Or.inl hnnq 

theorem p2' : p ∧ q → ¬¬q ∨ ¬p := 
  fun hpandq: p ∧ q =>
    have hqonnq: ¬q ∨ ¬¬q := Classical.em ¬q
    match hqonnq with
    | Or.inl hnq => False.elim (hnq (And.right hpandq))
    | Or.inr hnnq => Or.inl hnnq

variable (r : Nat → Prop)

/- Problem 3: Prove the following theorem -/

theorem p3 : (p → ∀ x, r x) → (∀ x, p → r x) := 
  fun hpaxrx: p → ∀ x: Nat, r x => 
  fun hx: Nat => 
  fun hp: p => 
  have hrx: ∀ x: Nat, r x := hpaxrx hp
  show r hx from hrx hx
