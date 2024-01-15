open Lean
open Lean.Parser

-- TODO this should actually be UInt8,
-- but the proofs are way harder then..
structure State : Type where
  inp: List Nat
  out: String
  before: List Nat
  current: Nat
  after: List Nat
  deriving Repr

namespace State

notation "*" s:100 => State.current s

end State

namespace State

def isZero (s: State) : Bool := *s = 0

def applyPInc (s: State): State :=
    match s.after with
      | [] => s -- if the end of the band is reached, do nothing
      | h :: t => ⟨s.inp, s.out, *s :: s.before, h, t⟩

def applyPDec (s: State): State :=
    match s.before with
      | [] => s -- if the beginning of the band is reached, do nothing
      | h :: t => ⟨s.inp, s.out, t, h, *s :: s.after⟩

def applyVInc (s: State): State := ⟨s.inp, s.out, s.before, *s + 1, s.after⟩

def applyVDec (s: State): State := 
  match *s with
  | 0 => ⟨s.inp, s.out, s.before, 0, s.after⟩
  | k + 1 => ⟨s.inp, s.out, s.before, k, s.after⟩

def applyInput (s: State): State :=
  match s.inp with
    | [] => ⟨[], s.out, s.before, *s, s.after⟩
    | h :: t => ⟨t, s.out, s.before, h, s.after⟩

def applyOutput (s: State): State :=
  let out := s.out ++ (Char.ofNat (*s)).toString
  ⟨s.inp, out, s.before, *s, s.after⟩

end State

#eval ¬(State.mk [] "" [] 1 []).isZero
#check State.mk [1, 2, 3] "" [] 0 []

inductive Op : Type where
  | nop        : Op
  | pInc       : Op
  | pDec       : Op
  | vInc       : Op
  | vDec       : Op
  | brakPair   : Op -> Op
  | seq        : Op -> Op -> Op
  | output     : Op
  | input      : Op

notation "#"   => Op.nop
notation ">"   => Op.pInc
notation "<"   => Op.pDec
notation "+"   => Op.vInc
notation "~"   => Op.vDec
notation "^"   => Op.output
notation ","   => Op.input
notation "[" ops "]" => (Op.brakPair ops)
notation a:50 "_" b:51  => Op.seq a b

namespace Op

def toString op := 
    match op with
    | Op.nop => ""
    | Op.pInc => ">"
    | Op.pDec => "<"
    | Op.vInc => "+"
    | Op.vDec => "-"
    | Op.output => "."
    | Op.input => ","
    | Op.brakPair op' => "[" ++ toString op' ++ "]"
    | Op.seq op1 op2 => (Op.toString op1) ++ (toString op2)

instance: ToString Op where
  toString op := op.toString

def f {α : Type}: α → Bool := by
  intro _
  exact true
    
theorem ln_take_l_lt_len_l {α : Type} (l: List α) (f: α → Bool):
  (l.takeWhile f).length < l.length.succ :=
  by 
    induction l with
    | nil => 
      simp
      rw [List.takeWhile]
      simp
      exact Nat.zero_lt_succ 0
    | cons head tail h =>
      rw [List.takeWhile]
      cases f head with
      | false =>
        simp
        apply Nat.zero_lt_succ
      | true =>
        simp
        apply Nat.succ_lt_succ
        rw [Nat.succ_eq_add_one] at h
        assumption

theorem ln_drop_l_lt_len_l {α : Type} (l: List α) (f: α → Bool):
  (l.dropWhile f).length < l.length.succ :=
  by 
    induction l with
    | nil => 
      rw [List.dropWhile]
      simp
      exact Nat.zero_lt_succ 0
    | cons head tail h =>
      rw [List.dropWhile]
      cases f head with
      | false =>
        simp
        apply Nat.succ_lt_succ
        exact Nat.lt_succ_self (List.length tail)
      | true =>
        simp
        have h' := Nat.lt_succ_self (Nat.succ (List.length tail))
        exact Nat.lt_trans h h'

-- THIS IS WROOONG
-- and also writing a good one seems to be very hard to proove 
-- that it terminates
def fromString (s: String): Op :=
  parse (s.toUTF8.toList)
where
  parse (chrl: List UInt8): Op :=
    match chrl with
    | [] => nop
    | h :: t =>
      match h with
      | 62 => Op.seq Op.pInc   (parse t)        -- 62 > 
      | 60 => Op.seq Op.pDec   (parse t)        -- 60 <
      | 43 => Op.seq Op.vInc   (parse t)        -- 43 +
      | 45 => Op.seq Op.vDec   (parse t)        -- 45 -
      | 46 => Op.seq Op.output (parse t)        -- 46 .
      | 44 => Op.seq Op.input  (parse t)        -- 44 ,
      | 91 =>                                   -- 91 [
        let head := t.takeWhile (λ x => x ≠ 93) -- 93 ]
        have _ : head.length < t.length.succ := 
          by
            have h' : head = List.takeWhile (λ x => x ≠ 93) t := by simp
            rw [h']
            exact ln_take_l_lt_len_l t (λ x => x ≠ 93)

        let tail := t.dropWhile (λ x => x ≠ 93) -- 93 ]
        have _ : tail.length < t.length.succ := 
          by 
            have h' : tail = List.dropWhile (λ x => x ≠ 93) t := by simp
            rw [h']
            exact ln_drop_l_lt_len_l t (λ x => x ≠ 93)
            
        let body := parse head
        let rest := parse tail
        Op.seq (Op.brakPair body) rest
      | _ => parse t -- anything else skip
    termination_by 
      parse chrl => chrl.length
      -- this is not written by. I'll just take it for granted
      -- I don't have the enery anymore to figure out exact what it does
      -- But, it should in theory deal with the fact that λ x => x ≠ 93
      -- is interpreted very stangely
    decreasing_by first | decreasing_tactic | simp_wf; simp only [ne_eq, decide_not] at *; assumption
      
end Op

#eval (Op.fromString "[<>.,+-]><")
#check (Op.fromString "[<>.,+-]><")
