
#check 3
#check 2 = 2
#check Prop
#check Type
#check (Type 1)
#check @id
#check id
#check List.cons
#check @List.cons


#eval 3
#eval "hello world"
#eval [1, 2, 3]
#eval 4 :: [1, 2, 3]

def a: Nat := 42
def hw: String := "hello " ++ "world!"

#check a  -- Nat
#check hw -- String
#eval hw  -- "hello world!"


def add_1 (k: Nat): Nat := k + 1
def add_1': Nat → Nat := λ k =>  k + 1
def add_2 (a b: Nat) := a + b

#check add_1  
#check add_1' 
#check add_1 3

inductive Bool where
  | false : Bool
  | true : Bool

def add: Nat → Nat → Nat := fun (a b: Nat) => a + b
def add' (a b: Nat): Nat := a + b
def add'' (a b: Nat) := a + b

def applyTwice (f: Nat → Nat) (k: Nat) := f (f k)

#eval applyTwice (add 3) 4 -- 10

#check @add'
#eval add' 1 2

#check λ x => x + 1 
#eval  (λ x => x + 1) 41

#eval [1, 2, 3]       
#eval 5 :: [1, 2]     
#eval [1, 2] ++ [3, 4]
#eval (List.range 5)  

#eval (List.range 5).map (λ x => x ^ 2) 
#eval  (λ x => x ^ 2) <$> (List.range 5)

#eval  (List.range 5).foldl (λ x y => x + y) 0
#eval  (List.range 5).foldl (. + .) 0         

#eval  (List.range 5).filter (λ x => x ≤ 2)
#eval  (List.range 5).filter (. ≤ 2)       

--#eval [x^2 | x ← [1 ,2 ,3 ,4 ,5]]

def a' : Bool := true
def b' : Bool := false

#check a' && b'

-- Pattern matching

#print Nat                                     
-- inductive Nat : Type
-- number of parameters: 0
-- constructors:
-- Nat.zero : Nat
-- Nat.succ : Nat → Nat

def factorial n :=
  match n with
  | 0    => 1
--| zero => 1
  | k + 1  => (k + 1) * factorial k
--| succ k => (k + 1) * factorial k

#eval factorial 5

-- ...

#check Nat
#check Nat->Nat

example (x y: Nat ): 27 * x + y = 27 * x + y := by rfl 

example : p ∨ q → q ∨ p :=
  λ (h: p ∨ q) => Or.elim h Or.inr Or.inl

example : p ∨ q → q ∨ p :=
by
  intro (h: p ∨ q)
  apply Or.elim
  . exact h
  . apply Or.inr
  . apply Or.inl

#check @Or.inl
#check @Or.inr
#check @Or.elim

example : p ∨ q → q ∨ p :=
  λ hpq => 
    match hpq with
    | Or.inl hp => Or.inr hp
    | Or.inr hq => Or.inl hq

example : p ∨ q → q ∨ p :=
  λ (h: p ∨ q) => Or.elim h Or.inr Or.inl

example : p ∨ q → q ∨ p :=
  fun (h: p ∨ q) => 
    let hq: q → q ∨ p := Or.inl
    let hp: p → q ∨ p := Or.inr
    let hpq: p ∨ q → q ∨ p := Or.elim h hp hq
    hpq

example : p ∨ q → q ∨ p :=
by
  intro (h: p ∨ q)
  apply Or.elim
  . exact h
  . apply Or.inr
  . apply Or.inl

#check @Or.inl
#check @Or.inr
#check @Or.elim
example : p ∨ q → q ∨ p :=
  λ (h: p ∨ q) => Or.elim h Or.inr Or.inl

example : p ∨ q → q ∨ p :=
by
  intro (h: p ∨ q)
  apply Or.elim
  . exact h
  . apply Or.inr
  . apply Or.inl

#check @Or.inl
#check @Or.inr
#check @Or.elim

#check String
#check Char
#check UInt32
#check Fin
#check Nat

inductive Nat': Type where
  | zero : Nat'
  | succ : Nat' → Nat'
  deriving Repr

--#check (Nat'.zero)
--#eval (Nat'.zero)
--#check (Nat'.succ Nat'.zero)
--#eval (Nat'.succ Nat'.zero)

--inductive Vec' (α : Type) : (n : Nat') → Type where
  --| empty : Vec' α zero
  --| cons  : {n : Nat'} → α → Vec' α n → Vec' α (Nat'.succ n)

--def k: Vec' Char (.succ (.succ .zero)) := .cons 'b' .empty

#check @List

--def foo {b: Bool}: if b then Nat else String :=
  --match b with
  --| true => "hello lean"
  --| false => (3: Nat)

--#check Nat

--inductive Vec: (α : Type u) → (n: Nat) → Type u where
  --| nil : Vec α n
  --| cons : α → Vec α n → Vec α (n + 1) 

--#check @Vec

--example : Vec Nat 0 := .nil
--example : Vec Nat 0 := sorry -- .cons 3 .nil
--example : Vec Nat 1 := .cons 3 .nil
--example : Vec Nat 1 := sorry -- .cons 4 (.cons 3 .nil)

---------------------------------------

     --eval : Stx → (String → ℤ ) → ℤ
     ---- expressions such as
     --eval (Stx.add e1 e2) st = (eval e1 st) + (eval e2 st)



    --Statement → { State × State }

    --e.g.

    --nop       → { (s, s) | s ∈  States }
    --x = a     → { (s, t) | s, t ∈  States, t = s[x ← a] } 
    --S ; T     → r1 ∘ r2 = { (a, c) | ∃ b, (a, b) ∈  r1 ∧ (b, c) ∈  r2 }

    --... 


inductive Vect (α : Type) : Nat → Type where
  | nil   : Vect α 0
  | cons  : α → Vect α n → Vect α (n + 1)
  deriving Repr

#eval Vect.cons 7 $ .cons 5 .nil
-- length 2
example: Vect Nat 2 := .cons 5 $ .cons 4 .nil
-- length 1
example: Vect Nat 2 := .cons 5 $ 4 .nil

def replicate {α: Type} (x: α) (n: Nat): Vect α n :=
  match n with
  | 0     => .nil
  | k + 1 => .cons x (replicate x k)

#eval replicate 42 5 -- [42, 42, 42, 42, 42]

def compare {α β: Type} {n1 n2: Nat} (v1: Vect α n1) (v2: Vect β n2): Bool :=
  match v1 with
  | Vect.nil => true
  | Vect.cons _ v1' => 
    match v2 with
    | .nil => false
    | .cons _ v2' => compare v1' v2'

#eval compare (Vect.cons 3 $ .cons 2 $ .nil)
  (Vect.cons "a" $ .cons "aa" $ .nil)

def strange_foo (b: Bool)
  : if b then String else Nat := 
    match b with
    | true => "lean"
    | false => (42: Nat)

#eval strange_foo true 
#eval strange_foo false


--#check -- gives the type                
--#eval  -- evaluates                  
--#print -- prints definition            

#check rfl


theorem pq_to_qp: p ∨ q → q ∨ p := 
by 
  intro h
  apply Or.elim h
  . intro hp
    exact Or.inr hp
  . intro hq
    exact Or.inl hq

variable (p q: Prop)


def k: Nat := 3 

def p_eq_p {p: Prop}: p = p := by rfl

#check p_eq_p

def α: Type := Bool
def β: Type → Type := List

#check α 
#check β Nat
#check p = p 
#check Prop  
#check Type  
#check Type 1
#check Type 2
-- ...

theorem test₁: p → q → (q ∧ p) :=
  λ hp hq => And.intro hq hp

#print List

def foo {N: Nat} (v: vector Int N): Int :=
  match N with 
  | 0 => 0
  | k + 1 => 


#check And.intro
#print And.intro

theorem test₂: p → q → (q ∧ p) :=
by 
  intros hp hq
  apply And.intro
  . assumption
  . assumption

example: p → q → (q ∧ p) :=
by 
  intros hp hq
  apply And.intro
  . assumption
  . assumption

example: p → q → (q ∧ p) :=
  fun hp hq => And.intro hq hp

example: p → q → (q ∧ p) :=
by
  intros hp hq
  apply And.intro hq hp
  


#check List
#print List

--inductive Vect.{u} (α : Type u):  (n: Nat) → Type u where
  --| nil: Vect α 0
  --| cons α → : Vect α (n + 1) 

--  +[-->-[>>+>-----<<]<--<---]>-.>>>+.>>..+++[.>]<<<<.+++.------.<<-.>>>>+.

--theorem t₁: (a → (b → c)) → (a → b) → (a → c) :=
--by
  --intros habc hab ha
  --have hb: b := hab ha 
  --have hbc: b → c := habc ha
  --have hc: c := hbc hb
  --exact hc

--theorem t₂: (a → (b → c)) → (a → b) → (a → c) :=
  --λ habc hab ha =>
    --let hb: b := hab ha
    --let hbc: b → c := habc ha
    --let hc: c := hbc hb
    --hc

namespace Nat

example (n: Nat): 0 + n = n := 
by
  induction n
  case zero => simp
  case succ d _ => simp
