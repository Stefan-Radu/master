
/-
  # LAB2: Propositional logic in Lean
-/

set_option autoImplicit false 
open Classical
/-
  `Prop` is the type of propositions. 
  Examples of propositions are equalities, like the ones we've seen in Lab1. 
-/
#check Prop 
#check 5 = 3

/-
  A proposition is itself a type. If `p : Prop`, we can speak of terms `h` of type `p`.
  We interpret some `h : p` as a *proof* of `p`, so we can say that `p` is the type of all its proofs.
  Proving a proposition `p` therefore means providing some term of type `p`.
  For instance, `rfl` from Lab1 is such term of type `x = x`, and therefore a proof that `x = x`.
-/

section PropositionalLogic 

/-
  Lean defines the usual propositional constructors: conjunction, disjunction, negation.
  Each of them is governed by so-called principles of *introduction* and *elimination*.
  The introduction principle answers the question:
  *how can one, in general, prove a conjunction / disjunction?*,
  while the elimination principle refers to 
  *how can one prove something from a conjunction / disjunction?*
-/

/-
  Using `variable`, we can consider in this section two arbitrary propositions `p` and `q`,
  as if we said *let p and q be any propositions*.
-/

variable (p q : Prop)

/-
  ## And 
  The notation `p ∧ q` is used for `And p q`. 
-/
#check And
#check And p q
#check @And.intro 
#check @And.left 
#check @And.right 

/-
  ## Or
  The notation `p ∨ q` is used ofr `Or p q`.
-/
#check Or 
#check Or p q
#check @Or.inl 
#check @Or.inr 
#check @Or.elim

/-
  #False
-/

#check False
#check @False.elim

-- C : Sort u
-- Prop := Sort 0
-- Type 0 := Sort 1
-- .. Type u := Sort (u + 1)

-- Prop : Type 0: Type 1 : Type 2 ...
-- Sort 0 : Sort 1: Sort 2: Sort 0...

#check Prop
#check Type 0

example : Prop = Sort 0 := by rfl

universe u
example : Type u = Sort (u + 1) := by rfl

/-
  ## Not
  Negation is defined by `Not p := p → False`.
-/
#check Not 
#check Not p


variable {α β : Type}
def f (a : α) (b : α → β) : β := b a

example (hp: p) (hnp: ¬p): False :=
  -- hp : p
  -- hnp : p -> False || ca si cum as zice hnp: p -> False
  -- cumva ca mai sus cu α β
  hnp hp

#check em

/-
  Exercise 1: Prove the following theorem.
  Hint: Look at the `applyFunction` function defined in Lab1
-/

-- puteam sa fol si def
-- theorem nu te lasa sa inferi tipul intors

theorem modus_ponens : p → (p → q) → q := 
  fun (hp : p) (hpq : p → q) => hpq hp

theorem modus_ponens' (p q : Prop) : p → (p → q) → q := 
  fun (hp : p) (hpq : p → q) => hpq hp

/-
  Exercise 2: Prove the following theorem.
  Hint: Look at the `swap` function defined in Lab1
-/
theorem and_comm : p ∧ q → q ∧ p := 
  fun hpq : p ∧ q =>
  let hp : p := And.left hpq
  let hq : q := And.right hpq
  And.intro hq hp

theorem and_comm' : p ∧ q → q ∧ p := 
  fun hpq : p ∧ q =>
  let hp : p := hpq.left
  let hq : q := hpq.right
  And.intro hq hp

theorem and_comm'' : p ∧ q → q ∧ p := 
  fun hpq : p ∧ q =>
  let hp : p := hpq.left
  let hq : q := hpq.right
  .intro hq hp -- inferenta de namespace din tipul de return

theorem and_comm''' : p ∧ q → q ∧ p := 
  fun hpq : p ∧ q => ⟨ hpq.right, hpq.left ⟩

theorem and_comm'''' : p ∧ q → q ∧ p := 
  fun hpq : p ∧ q => ⟨ hpq.2, hpq.1 ⟩

theorem and_comm''''' : p ∧ q → q ∧ p := 
  fun ⟨ hp, hq ⟩ => ⟨ hq, hp ⟩

theorem and_comm'''''' : p ∧ q → q ∧ p := 
  fun ( .intro hp hq ) => ⟨ hq, hp ⟩

theorem and_comm''''''' : p ∧ q → q ∧ p := fun hpq =>
  match hpq with
  | .intro hp hq => ⟨ hq, hp ⟩

theorem And.and_comm'''''''' : p ∧ q → q ∧ p := fun hpq =>
  match hpq with
  | intro hp hq => ⟨ hq, hp ⟩

-- chestie cool
-- practic poti omite definirea lambdaului daca omiti numele variabilelor
-- si infera el automa tipurile si whatever

def addOne : Nat -> Nat := (. + 1)
def SumTwo : Nat -> Nat -> Nat := (. + .)
def g : String -> String -> String := (. ++ " " ++ .)

/-
  In principle, any theorem can be proved by simply writing a function of the appropriate type 
  (the type of the theorem's statement), like above.
  This can get unwieldy for complex proofs, so Lean offers a different embedded language called *tactic mode*.
  At any point in a proof, there is a *proof state* composed of a number of hypotheses and a number of goals needing to be proved.
  A tactic changes the proof state, until no more goals are left.
-/

end PropositionalLogic

variable { p q : Prop }

theorem modus_ponens_tactics : p → (p → q) → q := by --we enter tactic mode with `by`. Note the infoview on the right.
  -- we need to prove an implication. We first suppose its premise.
  intros hp -- suppose a proof of `p → q` exists, and call it `h_imp_q`
            -- note the change in the proof state
  -- we still have an implication to prove, so we again assume its premise.
  intros hpq 
  -- we need to prove `q`. We can obtain `q` from the conclusion of `hpq` if we provide the right premise to it
  apply hpq -- the goal would follow from `hpq` if we proved its required conclusion. Note the goal change
  -- the goal is now just an assumption 
  assumption

theorem and_comm_tactics : p ∧ q → q ∧ p := by --we enter tactic mode with `by`. Note the infoview on the right.
  -- we need to prove an implication. We first suppose its premise 
  intros hpq -- suppose a proof of `p wedge q` exists, and call it `hpq`
             -- note the change in the proof state 
  -- we know p ∧ q, and from it can obtain both `p` and `q` by 
  cases hpq with | intro hp hq => 
  -- we need to prove `q ∧ p`. We know this can be proved from `And.intro` 
  apply And.intro 
  -- in order to apply `And.intro` we need to to have both a proof of `p` and a proof of `q`
  -- Lean produced two new goals, both of which are trivial two solve
  case left => assumption 
  case right => assumption 
  

/-
  Usually, tactic mode and term mode may be freely combined.
  For instance, a more concise version of the above may be:
-/
theorem and_comm_tactics' : p ∧ q → q ∧ p := by 
  intros hpq 
  cases hpq with | intro hp hq => -- ca un fel de match <vezi mai sus>
  exact And.intro hq hp

/-
  Exercise 3: Prove the following theorem, using tactic mode
-/
example : p → q → (p ∧ q) := by
  intros hp hq
  exact And.intro hp hq

example : p → q → (p ∧ q) := by
  intros hp hq
  apply And.intro
  case left => exact hp -- sau assumption
  case right => assumption -- sau exact hq

--example : p → q → (p ∧ q) := by
  --intros hp hq
  --apply And.intro
  --case left | right => assumption

example : p → q → (p ∧ q) := by
  intros hp hq
  apply And.intro
  assumption
  assumption

example : p → q → (p ∧ q) := by
  intros hp hq
  apply And.intro
  repeat assumption -- repeats until failure

example : p → q → (p ∧ q) := by
  intros hp hq
  apply And.intro <;> assumption 
  -- runs the next tactic for all generetab objective
  -- different from repeat. applies for all objectives in paralel

/-
  Exercise 4: Give the shortest possible *term mode* proof you can think of for the above statement
-/
example : p → q → (p ∧ q) := (⟨.,.⟩) -- universul in culori

example : p → q → (p ∧ q) := And.intro -- e fix functia aia

example : p → q → (p ∧ q) := .intro -- shorter

-- p ∧ ¬p == False
example (k: p ∧ ¬p): False := (And.right k) (And.left k)

theorem a0 (p: Prop): (p ∧ ¬p) → False := 
  fun conj => 
  let hp := conj.left
  let hnp := conj.right
  hnp hp

theorem a1 (p q: Prop): p → (q → p) :=
  fun hp _ => hp

/-
  Axiom 3 (reversed)
-/

theorem a3rev (p q : Prop) : (p → q) → (¬q → ¬p) :=
  fun hpq hnq hp => 
  let hq: q := hpq hp
  hnq hq

theorem doubleNegation (p: Prop) : ¬¬p → p :=
  fun h =>
  let h' : p ∨ ¬p := em p
  match h' with
  | Or.inl hp => hp
  | Or.inr hnp => 
    let f: False := h hnp
    let hp: p := f.elim
    hp

/-
  todo -> Axiom 3
-/

example (p q : Prop) : (¬p → ¬q) → (q → p) := 
  fun hnpnq hq =>
  let h: p ∨ ¬p := em p
  match h with
  | Or.inl hp => hp
  | Or.inr hnp => 
    let hnq: ¬q := hnpnq hnp
    (hnq hq).elim


example (p q : Prop) : (¬p → ¬q) → (q → p) := by
  intros npnq q
  have h := em p
  cases h with
  | inl hp => exact hp
  | inr hnp => exact ((npnq hnp) q).elim
