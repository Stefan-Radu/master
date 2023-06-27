/-
  *** Quantifiers *** 

  Recall that `∀ x : α, β x` is the type of dependent functions (or `Π`-type`)
  mapping each `x : α` to a term of type `β x`, where `β : α → Type`.

  If we replace `β : α → Type` with `p : α → Prop` (i.e. `p` is a predicate on `α`),
  the statement that `p` holds for all `x` as in first order logic.
  The propositions-as-types metaphor keeps working,
  saying this time that a proof of `∀ x : α, p x` is a function 
  that, for any `x`, produces a proof of `p x` 
  (note how, for each `x`, `p x` is a different proposition and thus, a different type).
-/

example : ∀ x : Nat, x = x := 
  fun x : Nat => Eq.refl x -- `Eq.refl x` is a proof that `x = x` for any `x`

example : ∀ (x y : Nat), x = x := 
  fun (x y : Nat) => Eq.refl x -- merge dar nu folosim y la nimic

--example : ∀ (x y : Nat), x = x := 
  --fun (x y : Nat) => Eq.refl y -- evident nu merge ca tipul de iesire e diferit de cel de intrare

/-
  `∃` is dual to `∀` and corresponds to the type-theoretical notion 
  of a dependent pair (or `Σ`-type). 
  For propositions, this means that a proof of `∃ x : α, p x` 
  is a "pair" composed of an `x : α` (that appropriate value that we claim that exists) 
  and a proof of `p x` (the proof that the chosen value is indeed appropriate).

  This is formally written using `Exists.intro (x : α) (h : p x)`. 
-/

example : ∃ x : Nat, x > 3 := 
  Exists.intro 4 (by simp /- a proof that `4 > 3`, how we prove this is not the point -/)

--example : ∃ x : Nat, x > 3 :=
  --Exists.intro 2 (by simp)  -- evident nu va merge

  -- by simp face calculele din spate ca ne e lene (aka nu stim)

/- 
  **Exercise 1:** 
  Prove the following statements about natural numbers. 
-/

example : ∃ n : Nat, ∀ m : Nat, m + n = m := 
  Exists.intro 0 (by simp) -- asta pare ca merge peste tot

example : ∃ n : Nat, ∀ m : Nat, m + n = m := 
  Exists.intro 0 (by intros; simp) 

example : ∃ n : Nat, ∀ m : Nat, m + n = m := 
  Exists.intro 0 (fun m => Eq.refl m) 

#check Nat.zero_add 

/- From now on, let `p` and `q` be two predicates on `α` -/
variable (α : Type) (p q : α → Prop) (r : Prop)

/-
  **Exercise 2:**
  Prove the following. 
-/

-- cu fun
example : ∀ x : α, (p x → ∃ x : α, p x) := 
  fun (x : α) (h : p x) => Exists.intro x h

/-
f x := x
f := id

f x y := g x y
f := g

fun x => f x = f (n-equiv)
-/

example : ∀ x : α, (p x → ∃ x : α, p x) := Exists.intro

-- cu tactic mode
example : ∀ x : α, (p x → ∃ x : α, p x) := 
  fun (x : α) (h : p x) => Exists.intro x h

example : ∀ x : α, (p x → ∃ x : α, p x) := by
  intros x h
  exists x
  done -- asta practic nu face nimic 
  --assumption

-- sau
example : ∀ x : α, (p x → ∃ x : α, p x) := by
  intros x h
  apply Exists.intro x ?_ -- merge si _ sau nimic
  trivial

example : (∀ x : α, p x ∧ q x) ↔ (∀ x : α, p x) ∧ (∀ x, q x) := 
  Iff.intro
    (fun h => And.intro (fun a => (h a).left) (fun a => (h a).right))
    (fun ⟨hp, hq⟩ => fun a => ⟨hp a, hq a⟩)
    -- (fun ⟨hp, hq⟩ => fun a => And.intro (hp a) (hq a))
    

example : ((∃ x, p x) → r) → (∀ x, p x → r) :=  
  fun h a h' => 
    have expx: ∃ x, p x := Exists.intro a h' -- have e gen let dar nu mai specifica definitia (teoretic)
    h expx

/- 
  **Exercise 3:** 
  The following is not true as it is. Fix it an prove it * 
-/

#check Inhabited 
#print Inhabited -- asta arata definitia

example (a : α): (∀ x : α, p x) → ∃ x : α, p x := 
  fun h => Exists.intro a (h a) -- practic am presuspus ca tipul α nu e vid, zicand ca luam un a de tip α

example [Inhabited α]: (∀ x : α, p x) → ∃ x : α, p x := 
  fun h => 
    let a: α := Inhabited.default
  -- sau let a := @Inhabited.default α _
    Exists.intro a (h a)

/-
  **Exercise 4:** 
  Prove whether `∀ p : Prop, p` is true or false. 
-/

def q': Prop := ∀ p : Prop, p

example : (∀ p : Prop, p) → False := 
  fun h => h False

-- definitie alternativa a falsului
example : q' → False := 
  fun h => h False

/-
  **Exercise 5:** 
  Prove the following.
-/
-- exista un numar par si exista un numar impar ¬→ ca exista un numar si par si impar

example : ∃ (α : Type) (p q : α → Prop), ¬((∃ x, p x ∧ (∃ x, q x)) → ∃ x, p x ∧ q x) := sorry 
