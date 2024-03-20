-- This module serves as the root of the `BfOperationalSemantics` library.
-- Import modules here that should be built as part of the library.

import «BfOperationalSemantics».BigStep

-----------------
-- Dec to zero --
-----------------

-- (--, [2] ⟹   [0])  -- (*s -= 2, [2] ⟹   [0])

-- ([-], [n] ⟹   [0]) -- (while(*s) { *s -= 1}, [n] ⟹   [0])

theorem dec_2: (~_~, (State.mk [] "" [] 2 [])) ⟹   State.mk [] "" [] 0 [] :=
  by
    apply BigStep.seq
    case h =>
      apply BigStep.vDec
    case h' =>
      apply BigStep.vDec

theorem dec_n {n: Nat}: ([~], (State.mk [] "" [] n []))
  ⟹   State.mk [] "" [] 0 [] :=
  by
    induction n
    case zero =>
      . apply BigStep.brakPairFalse
        . simp
    case succ d hd =>
      . apply BigStep.brakPairTrue
        . simp
        . apply BigStep.vDec
        . rw [State.applyVDec]
          simp
          assumption

-------------------------
-- two number addition --
-------------------------

def bfAddition: Op := Op.brakPair (
  ( Op.seq  Op.vDec
  ( Op.seq  Op.pInc
  ( Op.seq  Op.vInc  Op.pDec ))))

#eval bfAddition

-- sum 1 2 eq 3
theorem bfSum_1_2 : (bfAddition, (State.mk [] "" [] 1 [2])) 
  ⟹  State.mk [] "" [] 0 [3] :=
  by
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
    { apply BigStep.brakPairFalse 
      . rw [State.applyPDec]
        rw [State.applyVInc]
        rw [State.applyPInc]
        rw [State.applyVDec] }

theorem bfSum_1_1' : (bfAddition, (State.mk [] "" [] 1 [1])) 
  ⟹  State.mk [] "" [] 0 [2] :=
  by
    rw [bfAddition]
    apply BigStep.brakPairTrue
    . rw [State.current]
      simp
    . apply BigStep.seq
      apply BigStep.vDec
      apply BigStep.seq
      apply BigStep.pInc
      apply BigStep.seq
      apply BigStep.vInc
      apply BigStep.pDec
    . apply BigStep.brakPairFalse
      rw [State.applyPDec]
      rw [State.applyVInc]
      rw [State.applyPInc]
      rw [State.applyVDec]


-- same as before, but take numbers from input
def bfSum_in: Op := ,_>_,_<_(bfAddition)

#eval bfSum_in

-- sum a b eq a + b

theorem bfSum: (bfSum_in, (State.mk (a :: b :: i) o l x (y :: r)))
  ⟹  State.mk i o l 0 ((a + b) :: r) := 
  by 
    rw [bfSum_in]
    apply BigStep.seq
    apply BigStep.input
    apply BigStep.seq
    apply BigStep.pInc
    apply BigStep.seq
    apply BigStep.input
    apply BigStep.seq
    apply BigStep.pDec
    rw [State.applyPDec]
    repeat rw [State.applyInput]
    rw [State.applyPInc]
    simp
    rw [bfAddition]
    induction a generalizing b with
    | zero =>
      rw [Nat.zero_eq]
      rw [Nat.zero_add]
      apply BigStep.brakPairFalse
      . rw [State.current]
    | succ k h =>
      apply BigStep.brakPairTrue
      . rw [State.current]
        simp
      . apply BigStep.seq
        apply BigStep.vDec
        apply BigStep.seq
        apply BigStep.pInc
        apply BigStep.seq
        apply BigStep.vInc
        apply BigStep.pDec
      . rw [State.applyVDec]
        rw [State.applyPDec]
        rw [State.applyPInc]
        rw [State.applyVInc]
        simp
        rw [Nat.succ_eq_add_one]
        rw [Nat.add_assoc]
        rw [Nat.add_comm 1 b]
        exact @h (b + 1)

------------------------
-- Swapping two values--
------------------------

-- swap (a, b) eq (b, a)

-- The hard way

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


-- The easier way
def bfSwap' : Op := [<_+_>_~]

-- The easiest way
--def bfSwap' : Op := Op.fromString "[<+>-]"

#eval bfSwap'

theorem swap' (l r: List Nat) (b a: Nat): (bfSwap', State.mk [] "" (a :: l) b r) 
  ⟹  State.mk [] "" ((a + b) :: l) 0 r :=
  by 
    rw [bfSwap']
    induction b generalizing a with
    | zero =>
      apply BigStep.brakPairFalse
      simp
    | succ k h =>
      apply BigStep.brakPairTrue
      case c =>
        rw [State.current]
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

def bfSwap'': Op := [>_>_+_<_<_~]

theorem swap'' (l r: List Nat) (a b x: Nat): 
  (bfSwap'', State.mk [] "" l a (x :: b :: r))
  ⟹ State.mk [] "" l 0 (x :: (b + a) :: r) :=
  by 
    rw [bfSwap'']
    induction a generalizing b with
    | zero =>
      rw [Nat.zero_eq]
      apply BigStep.brakPairFalse
      . rw [State.current]
    | succ k h =>
      apply BigStep.brakPairTrue
      . rw [State.current]
        simp
      . repeat (apply BigStep.seq; apply BigStep.pInc)
        apply BigStep.seq; apply BigStep.vInc
        repeat (apply BigStep.seq; apply BigStep.pDec)
        apply BigStep.vDec
      . rw [State.applyVDec]
        rw [State.applyVInc]
        repeat (rw [State.applyPInc])
        repeat (rw [State.applyPDec])
        simp
        have h' := h (b + 1)
        rw [Nat.add_assoc b 1 k] at h'
        rw [Nat.add_comm 1 k] at h'
        rw [Nat.succ_eq_add_one]
        exact h'

#eval bfSwap'
def bfSwapTX: Op := >_(bfSwap')         -- x[t+x-]
def bfSwapXY: Op := >_(bfSwap')         -- y[x+y-]
def bfSwapYT: Op := <_<_(bfSwap'')      -- t[y+t-]

def bfSwap: Op := (bfSwapTX)_(bfSwapXY)_(bfSwapYT)
#eval bfSwap

theorem swap: (bfSwap, State.mk [] "" l 0 (x :: y :: r))
  ⟹  State.mk [] "" l 0 (y :: x :: r) :=
  by 
    rw [bfSwap]
    rw [bfSwapTX]
    apply BigStep.seq
    . apply BigStep.seq
      . apply BigStep.pInc
      . rw [State.applyPInc]
        simp
        exact swap' l (y :: r) x 0
    rw [bfSwapXY]
    apply BigStep.seq
    . apply BigStep.seq
      . apply BigStep.pInc
      . rw [State.applyPInc]
        simp
        exact swap' (x :: l) r y 0
    rw [bfSwapYT]
    apply BigStep.seq
    . apply BigStep.pDec
    . apply BigStep.seq
      . apply BigStep.pDec
      . repeat rw [State.applyPDec]
        simp
        have h' := swap'' l r x 0 y
        rw [Nat.zero_add] at h'
        assumption

-----------------
-- Hello World --
-----------------


def hello_world_s: String := "
++++++++               Set Cell #0 to 8
[
    >++++               Add 4 to Cell #1, this will always set Cell #1 to 4
    [                   as the cell will be cleared by the loop
        >++             Add 2 to Cell #2
        >+++            Add 3 to Cell #3
        >+++            Add 3 to Cell #4
        >+              Add 1 to Cell #5
        <<<<-           Decrement the loop counter in Cell #1
    ]                   Loop until Cell #1 is zero, number of iterations is 4
    >+                  Add 1 to Cell #2
    >+                  Add 1 to Cell #3
    >-                  Subtract 1 from Cell #4
    >>+                 Add 1 to Cell #6
    [<]                 Move back to the first zero cell you find, this will
                        be Cell #1 which was cleared by the previous loop
    <-                  Decrement the loop Counter in Cell #0
]                       Loop until Cell #0 is zero, number of iterations is 8

The result of this is:
Cell no :   0   1   2   3   4   5   6
Contents:   0   0  72 104  88  32   8
Pointer :   ^

>>.                     Cell #2 has value 72 which is 'H'
>---.                   Subtract 3 from Cell #3 to get 101 which is 'e'
+++++++..+++.           Likewise for 'llo' from Cell #3
>>.                     Cell #5 is 32 for the space
<-.                     Subtract 1 from Cell #4 for 87 to give a 'W'
<.                      Cell #3 was set to 'o' from the end of 'Hello'
+++.------.--------.    Cell #3 for 'rl' and 'd'
>>+.                    Add 1 to Cell #5 gives us an exclamation point
>++.                    And finally a newline from Cell #6"

-- well this is wrong :(
--def hello_world := Op.fromString hello_world_s

--def hello_world_op: Op := +_+_+_+_+_+_+_+_[>_+_+_+_+_[>_+_+_>_+_+_+_>_+_+_+_>_+_<_<_<_<_~]_>_+_>_+_>_~_>_>_+_[<]_<_~]_>_>_^_>_~_~_~_^_+_+_+_+_+_+_+_^_^_+_+_+_^_>_>_^_<_~_^_<_^_+_+_+_^_~_~_~_~_~_~_^_~_~_~_~_~_~_~_~_^_>_>_+_^_>_+_+_^
def hello_world_op: Op := +_+_+_+_+_+_+_+_[>_+_+_+_+_[>_+_+_>_+_+_+_>_+_+_+_>_+_<_<_<_<_~]_>_+_>_+_>_~_>_>_+_[<]_<_~]

#check hello_world_op
#eval hello_world_op


def hello_world_op1: Op := +_+_+_+_+_+_+_+

theorem hello_world1 (i l r: List Nat):
  (hello_world_op1, State.mk i "" l 0 r)
  ⟹ State.mk i "" l 8 r :=
  by
     rw [hello_world_op1]
     repeat (apply BigStep.seq; apply BigStep.vInc)
     apply BigStep.vInc

def hello_world_op2: Op := >_+_+_+_+_
  [>_+_+_>_+_+_+_>_+_+_+_>_+_<_<_<_<_~]
  _>_+_>_+_>_~_>_>_+_[<]_<_~

def hello_world_op21: Op := >_+_+_+_+

theorem hello_world21 (i l r: List Nat) (a b: Nat):
  (hello_world_op21, State.mk i "" l a (b :: r))
  ⟹ State.mk i "" (a :: l) (b + 4) r :=
  by
    rw [hello_world_op21]
    apply BigStep.seq
    apply BigStep.pInc
    repeat (apply BigStep.seq; apply BigStep.vInc)
    apply BigStep.vInc

def hello_world_op22: Op := >_+_+_>_+_+_+_>_+_+_+_>_+_<_<_<_<_~

theorem hello_world22 (i l r: List Nat) (a b c d x: Nat):
  (hello_world_op22, State.mk i "" l (x + 1) (a :: b :: c :: d :: r))
  ⟹ State.mk i "" l x ((a + 2) :: (b + 3) :: (c + 3) :: (d + 1) :: r) :=
  by 
    rw [hello_world_op22]
    repeat ( first 
           | apply BigStep.seq 
           | apply BigStep.pInc
           | apply BigStep.vInc
           | apply BigStep.pDec)
    apply BigStep.vDec

theorem hello_world2 {i l r: List Nat} {a b c x₁ x₂ x₃ x₄ : Nat} :
  (hello_world_op2, State.mk i "" l (a + 1) (b :: x₁ :: x₂ :: x₃ :: x₄ :: c :: r))
  ⟹ State.mk i "" l a (0 :: (x₁ + 9) :: (x₂ + 13) :: (x₃ + 11) :: (x₄ + 4) :: (c + 1) :: r) := sorry
    --rw [hello_world_op2]
    --repeat ( first 
           --| apply BigStep.seq 
           --| apply BigStep.pInc
           --| apply BigStep.vInc )
    --repeat ( first
           --| rw [State.applyVInc]
           --| rw [State.applyPInc] )
    --simp
--  I give up on this lol, it literally kills my poor laptop
-- I'll try an easier one

---------
-- CAT --
---------

def cat_op: Op := ,_[^_,]
#eval cat_op

--def hello_world_inp := [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33, 0]
def hello_world_inp := [72]

-- apparently it's very very hard to output anything... ugh

--def cat {l r: List Nat} {x : Nat} : (cat_op, State.mk hello_world_inp "" l x r)
  --⟹ State.mk [] "H" l 0 r := 
  --by 
    --rw [cat_op]
    --rw [hello_world_inp]
    --apply BigStep.seq
    --apply BigStep.input
    --rw [State.applyInput]
    --apply BigStep.brakPairTrue
    --. simp
    --. apply BigStep.seq
      --apply BigStep.output
      --simp
      --rw [State.applyInput]
    --. repeat rw [State.applyOutput]
      --simp
      
      





    

    --apply BigStep.brakPairFalse
    --. rw [State.current]




      






