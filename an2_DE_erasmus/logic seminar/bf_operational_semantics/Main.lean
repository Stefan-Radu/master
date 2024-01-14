open Lean
open Lean.Parser

structure State : Type where
  inp: List UInt8
  out: List String
  before: List UInt8
  current: UInt8
  after: List UInt8
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

def applyVDec (s: State): State := ⟨s.inp, s.out, s.before, *s - 1, s.after⟩

def applyInput (s: State): State :=
  match s.inp with
    | [] => ⟨[], "<<error occurred: Not enough input>>" :: s.out,
              s.before, *s, s.after⟩
    | h :: t => ⟨t, s.out, s.before, h, s.after⟩

def applyOutput (s: State): State :=
  let c := (Char.ofNat (*s).val).toString
  ⟨s.inp, c :: s.out, s.before, *s, s.after⟩

end State


#check True ∧ False
#check Prop
#check Bool

#eval ¬(State.mk [] [] [] 1 []).isZero
#check State.mk [1, 2, 3] [""] [] 0 []

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

notation "#" => Op.nop
notation ">"   => Op.pInc
notation "<"   => Op.pDec
notation "+"   => Op.vInc
notation "-"   => Op.vDec
notation "."   => Op.output
notation ";"   => Op.input
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
    | Op.input => ";"
    | Op.brakPair op' => "[" ++ toString op' ++ "]"
    | Op.seq op1 op2 => (Op.toString op1) ++ (toString op2)

instance: ToString Op where
  toString op := op.toString

def fromString (s: String): Option Op :=
  let validChars (s: String): Bool :=
    s.all (λ (x: Char) => "><+-.;[]".contains x) 
  if (validChars s) then
    sorry
  else 
    none

--def parseBrakPair (s: String): Option (Op × String) :=
  --match s with 
  --| [] => none
  --| h :: t =>
    --if h == ']' then
      --some (Op.nop, t)
    --else if h == '[' then
      --match parseBrakPair t with
      --| some op s => 
        --let currentOp := op
        --match parseBrakPair s with
        --| some op' s' =>
          


      --let rest := parseBrakPair t
      --let currentOp := 
        --match h with

--def parse (s: List Char): Op × (List Char) :=
  --match s with
  --| [] => (nop, [])
  --| h :: t => 
    --if h == '[' then
      --let (op, s) := parse t
      --let (op', s') := parse s
      --(seq (brakPair op) op', s')
    --else if h == ']' then
      --(nop, t)
    --else
      --let (op, s) := parse t
      --let currentOp := 
        --match h with
        --| '>' => Op.pInc
        --| '<' => Op.pDec
        --| '+' => Op.vInc
        --| '-' => Op.vDec
        --| '.' => Op.output
        --| ';' => Op.input
        --|   _ => Op.nop
      --(seq currentOp op, s)

end Op

/- [->+<] -/

def bfAddition: Op := Op.brakPair (
  ( Op.seq  Op.vDec
  ( Op.seq  Op.pInc
  ( Op.seq  Op.vInc  Op.pDec ))))

#check Nat.zero_ne_one
def kk := bfAddition.toString
#eval kk
#eval kk.splitOn "]"

inductive BigStep: Op × State → State → Prop where
  | nop  (s: State): BigStep (Op.nop, s)  s
  | pInc (s: State): BigStep (Op.pInc, s) s.applyPInc
  | pDec (s: State): BigStep (Op.pDec, s) s.applyPDec
  | vInc s: BigStep (Op.vInc, s) s.applyVInc
  | vDec s: BigStep (Op.vDec, s) s.applyVDec
  | brakPairTrue {ops} {s t u: State}
    (c: s.deref ≠ 0)
    (body: BigStep (ops, s) t)
    (rest: BigStep ((Op.brakPair ops), t) u):
      BigStep (Op.brakPair ops, s) u
  | brakPairFalse ops (s: State) (c: s.deref = 0):
      BigStep (Op.brakPair ops, s) s
  | seq (ops1 s ops2 t u)
    (h:  BigStep (ops1, s) t)
    (h': BigStep (ops2, t) u):
      BigStep ((Op.seq ops1 ops2), s) u
  | input s: BigStep (Op.input, s) s.applyInput
  | output s: BigStep (Op.output, s) s.applyOutput

infix:110 " ⟹ " => BigStep

-->>>>>> 5>

theorem bfAdd_1_2 : (bfAddition, (State.mk [] [] (BFBand.mk [] 1 [2] ))) ⟹
    (State.mk [] [] (BFBand.mk [] 0 [3] )) := by
    rw [bfAddition]
    apply BigStep.brakPairTrue;
    { simp }
    { apply BigStep.seq;
      { apply BigStep.vDec }
      { apply BigStep.seq;
        { apply BigStep.pInc }
        { apply BigStep.seq;
          { apply BigStep.vInc }
          { apply BigStep.pDec }}}}
    { apply BigStep.brakPairFalse;
      { simp } }

@[simp] theorem BigStep_nop_Iff {s t} :
  (Op.nop, s) ⟹ t ↔ t = s := by
    apply Iff.intro
    case mp =>
      intro h
      cases h
      case nop => rfl
    case mpr =>
      intro ht
      rw [ht]
      exact BigStep.nop s

@[simp] theorem BigStep_pInc_Iff {s t} :
  (Op.pInc, s) ⟹ t ↔ (t = s.applyPInc) := by
    apply Iff.intro
    . intro h
      cases h
      . rfl
    . intro h
      rw [h]
      exact BigStep.pInc s

@[simp] theorem BigStep_pDec_Iff {s t} :
  (Op.pDec, s) ⟹ t ↔ (t = s.applyPDec) := by
    apply Iff.intro
    . intro h
      cases h
      . rfl
    . intro h
      rw [h]
      exact BigStep.pDec s

@[simp] theorem BigStep_seq_Iff { os ot s u }:
  (Op.seq os ot, s) ⟹ u ↔ (∃ t, (os, s) ⟹ t ∧ (ot, t) ⟹ u) :=
  by
    apply Iff.intro
    case mp =>
      intro hseq
      cases hseq with
      | seq os s st t u s1 s2 =>
        apply Exists.intro t
        apply And.intro <;> assumption
    case mpr =>
      intro h
      cases h with
      | intro t hand =>
        have hl := And.left hand
        have hr := And.right hand
        exact (BigStep.seq os s ot t u hl hr)

@[simp] theorem BigStep_input_Iff { s t: State }:
  (Op.input, s) ⟹ t ↔ (t = s.applyInput) :=
  by
    apply Iff.intro
    . intro h
      cases h <;> rfl
    . intro h
      rw [h] <;>
      apply BigStep.input

@[simp] theorem BigStep_output_Iff { s t: State }:
  (Op.output, s) ⟹ t ↔ (t = s.applyOutput) :=
  by
    apply Iff.intro
    . intro h
      cases h <;> rfl
    . intro h
      rw [h] <;>
      apply BigStep.output

theorem BigStep_brakPair_Iff {op: Op} {s u: State} :
  (Op.brakPair op, s) ⟹ u ↔ (
    (s.deref ≠ 0 ∧ (∃ (t: State), (op, s) ⟹ t ∧ (Op.brakPair op, t) ⟹ u))
  ∨ (s.deref = 0 ∧ (u = s))) :=
  by 
    apply Iff.intro
    . intro h
      cases h with
      | brakPairTrue c d e =>
        apply Or.inl
        apply And.intro
        . assumption
        . apply Exists.intro
          apply And.intro <;> assumption
      | brakPairFalse _ _ c => 
        apply Or.inr
        apply And.intro
        . assumption
        . rfl
    . intro h
      cases h with
      | inl hl => 
        have hc := hl.left
        have hr := hl.right
        cases hr with
        | intro t hand =>
          have body := hand.left
          have rest := hand.right
          apply BigStep.brakPairTrue <;> assumption
      | inr hr => 
        cases hr with
        | intro hal har => 
          rw [har]
          apply BigStep.brakPairFalse <;> assumption

@[simp] theorem BigStep_brakPairTrue_Iff {op: Op} {s u: State} (cond: s.deref ≠ 0) :
  (Op.brakPair op, s) ⟹ u ↔ (∃ (t: State), (op, s) ⟹ t ∧ (Op.brakPair op, t) ⟹ u) :=
  by
    apply Iff.intro
    . intro h
      cases h with
      | brakPairTrue c body rest =>
        apply Exists.intro
        apply And.intro <;> assumption
      | _ => contradiction
    . intro h
      cases h with
      | intro t expr =>
        have hl := expr.left
        have hr := expr.right
        apply BigStep.brakPairTrue <;> assumption

@[simp] theorem BigStep_brakPairFalse_Iff {op: Op} {s u: State} (cond: s.deref = 0) :
  (Op.brakPair op, s) ⟹ t ↔ s = t :=
  by
    apply Iff.intro
    . intro h
      cases h
      . contradiction
      . rfl
    . intro h
      rw [h]
      apply BigStep.brakPairFalse
      rw [h] at cond
      assumption

---------------------------------------------------------------------------

-- TODO introduct repeated instruction
-- TODO prove that there is an equivalence between repeat and just many instructions
-- TODO prove some more complex algorithm
-- TODO .fromString

---- swapping two values

/-
x[temp0+x-]
y[x+y-]
temp0[y+temp0-]
-/

-- t 0
-- x 1
-- y 2

--def bfSwap': Op :=   
  --let t_x := 
    --Op.seq Op.pInc (
    --Op.brakPair (
    --Op.seq Op.pDec (
    --Op.seq Op.vInc (
    --Op.seq Op.pInc Op.vDec ))))
  --let x_y :=
    --Op.seq Op.pInc (
    --Op.brakPair (
    --Op.seq Op.pDec (
    --Op.seq Op.vInc (
    --Op.seq Op.pInc Op.vDec))))
  --let y_t :=
    --Op.seq Op.pDec (
    --Op.seq Op.pDec (
    --Op.brakPair (
    --Op.seq Op.pInc (
    --Op.seq Op.pInc (
    --Op.seq Op.vInc (
    --Op.seq Op.pDec (
    --Op.seq Op.pDec Op.vDec )))))))

  --(Op.seq t_x (Op.seq x_y y_t))

def bodyTXY: Op := <_+_>_-
def bfSwapTX: Op := >_[<_+_>_-]         -- x[t+x-]
def bfSwapXY: Op := >_[<_+_>_-]         -- y[x+y-]
def bfSwapYT: Op := <_<_[>_>_+_<_<_-]   -- t[y+t-]

--#eval bfswapTX

def bfSwap: Op := (bfSwapTX)_(bfSwapXY)_(bfSwapYT)

--def s': State := |> [] [] [] 0 [x, y] <|

def startState (x y: Nat) := State.mk [] [] (BFBand.mk [] 0 [x, y])
def initState1 (x y: Nat) := State.mk [] [] (BFBand.mk [x] 0 [y])

theorem swap'' (l1: List Nat) (l2: List String) (x y z: Nat):
  (bodyTXY, State.mk l1 l2 (BFBand.mk [z] (x + 1) [y])) 
  ⟹ State.mk l1 l2 (BFBand.mk [z + 1] x [y]) :=
  by
    rw [bodyTXY]
    apply BigStep.seq
    . apply BigStep.pDec
    . apply BigStep.seq
      . apply BigStep.vInc
      . apply BigStep.seq
        . apply BigStep.pInc
        . apply BigStep.vDec

--example (y k: Nat) : ∀ x, (bodyTXY, State.mk [] [] (BFBand.mk [x] k [y]))
  --⟹ State.mk [] [] (BFBand.mk [x + k] y []) :=
  --by
    --rw [bodyTXY]

    --intro x
    --induction k with
    --| zero => 

/-
def bfSwapTX: Op := >_[<_+_>_-]         -- x[t+x-]
def bfSwapXY: Op := >_[<_+_>_-]         -- y[x+y-]
def bfSwapYT: Op := <_<_[>_>_+_<_<_-]   -- t[y+t-]

def bfSwap: Op := (bfSwapTX)_(bfSwapXY)_(bfSwapYT)_
-/

--#eval bfswapTX

def bfs: Op := [<_+_>_-]

theorem swap1 {l r: List Nat} {b: Nat} (a: Nat): (bfs, State.mk [] [] (BFBand.mk (a :: l) b r)) ⟹ State.mk [] [] (BFBand.mk ((a + b) :: l) 0 r) :=
  by 
    rw [bfs]
    induction b generalizing a with
    | zero =>
      simp
      apply BigStep.brakPairFalse
      rw [State.deref]
    | succ k h =>
      apply BigStep.brakPairTrue
      case c =>
        rw [State.deref]
        simp
      case body =>
        apply BigStep.seq
        . apply BigStep.pDec
        . apply BigStep.seq
          . apply BigStep.vInc
          . apply BigStep.seq
            . apply BigStep.pInc
            . apply BigStep.vDec
      case rest =>
        rw [State.applyVDec]
        rw [State.applyVInc]
        rw [State.applyPDec]
        rw [State.applyPInc]
        simp
        have h' := h (a + 1)
        rw [Nat.succ_eq_add_one]
        rw [Nat.add_comm k 1]
        rw [← Nat.add_assoc a 1 k]
        exact h'





















---------------------------------------------------------------------------------
--inductive SmallStep: Op × State → Op × State → Prop where
  --| pointerRight (s: State):
      --SmallStep (pInc, s) (
        --nop,
        --let b := s.band
        --⟨s.input, s.output,
        --match b.after with
            --| [] => ⟨b.current :: b.before, 0, []⟩
            --| h :: t => ⟨b.current :: b.before, h, t⟩ ⟩)
  --| pointerLeft (s: State):
      --SmallStep (pDec, s) ( --nop,
        --match s.band.before with
          --| [] => ⟨s.input, s.output, ⟨[], 0, s.band.current :: s.band.after⟩⟩
          --| h :: t => ⟨s.input, s.output, ⟨t, h, s.band.current :: s.band.after⟩⟩)
  --| valueInc (s: State):
      --SmallStep (vInc, s) (
        --nop,
        --⟨s.input, s.output, ⟨s.band.before, s.band.current + 1, s.band.after⟩⟩)
  --| valueDec (s: State):
      --SmallStep (vDec, s) (
        --nop,
        --⟨s.input, s.output, ⟨s.band.before, s.band.current - 1, s.band.after⟩⟩)
  --| brakPair_true (op: Op) (s: State):
      --SmallStep (Op.brakPair op, s) (Op.seq op (Op.brakPair op), s)
  --| brakPair_false (op: Op) (s: State):
      --SmallStep (Op.brakPair op, s) (Op.nop, s)
  --| seqStep (ops ops' ops'': Op) (s s' : State) (step: SmallStep (ops, s) (ops', s')) :
      --SmallStep ((Op.seq ops ops''), s) ((Op.seq ops' ops''), s')
  --| seqSkip (ops: Op) (s: State):
      --SmallStep ((Op.seq Op.nop ops), s) (ops, s)
  --| input (s: State):
      --SmallStep (Op.input, s) (
        --nop,
        --let b := s.band
        --match s.input with
          --| [] => ⟨[],
                   --"¬<<error occurred: Not enough input>>¬" :: s.output,
                   --⟨b.before, 0, b.after⟩⟩
          --| h :: t => ⟨t, s.output, ⟨b.before, h, b.after⟩⟩)
  --| output (s: State):
      --SmallStep (Op.output, s) (
        --nop,
        --let b := s.band
        --let c := (Char.ofNat b.current).toString
        --⟨s.input, c :: s.output, b⟩)
