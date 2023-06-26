section Exercitiul1

inductive form where 
  | atom : form 
  | neg : form → form 
  | impl : form → form → form 
  | box : form → form 

notation:40 "¬"p => form.neg p 
infix:50 "→" => form.impl 
notation p "∧" q => ¬(p → ¬q)
notation p "∨" q => ¬(¬p ∧ ¬q)
prefix:80 "□" => form.box 
notation "⋄"p => ¬(□(¬p))

open form 

def ex1 : form → Nat :=
  fun f => 
    match f with
    | atom => 1
    | neg k => ex1 k
    | impl k l => (ex1 k) + (ex1 l)
    | box k => (ex1 k)


#eval ex1 ((¬(atom → atom)) → (□atom → (¬atom → atom)))
#check ex1

end Exercitiul1
/-
  # Exercitiul 2
  Demonstrati urmatoarea teorema in logica propozitionala, utilizand Lean.
  ⊢ p → (s → ¬q) → (¬p ∨ q) → s → r 
  Poate fi aleasa orice metoda, sau *tactic-mode*, sau *term-mode*.
  **NU** se cer ambele metode! 
-/

/-
¬p ∨ q => ¬(¬¬p ∧ ¬q) => ¬¬(¬¬p → ¬¬q)

-/

theorem dne {p : Prop} : (¬¬p) → p :=
  fun h =>
  let h' := Classical.em p
  match h' with
  | Or.inl hp => hp
  | Or.inr hnp => 
    let f: False := h hnp
    let hp: p := f.elim
    hp

theorem ex2term {p q r s: Prop} : p → (s → ¬q) → (¬p ∨ q) → s → r := 
  fun (hp: p) (hshnq: s → ¬q) (hnporhq: ¬p ∨ q) (hs: s) =>
    have hnq: ¬q := hshnq hs
    have hpq': p → (¬¬q) := dne $ dne hnporhq
    have hnnq: ¬¬q := hpq' hp
    have hq: q := dne hnnq
    False.elim (hnq hq)


/-
  # Exercitiul 3
  Sa se implementeze urmatoarea functie in Lean:
  ex3 : Nat → Nat → Nat 
  ex3 (x, y) := 
  {
    1                 daca x = 0 si y = 0
    y + 1             daca x = 0
    ex3(x, 1)         daca y = 0
    ex3(x, ex3(x, y)) altfel 
  }
  Implementarea trebuie sa fie facuta prin *recursie structurala*.
  Verificati ce rezultat obtineti pentru x = 2 si y = 3. 

ex3(x, y) := 
{
  1                         x=0, y=0
  y + 1                     x=0, y!=0
  ex3(x-1, 1)               x!=0, y=0
  ex3(x-1, ex3(x-1, y-1))   x!=0, y!=0
}

-/

def ex3: Nat → Nat → Nat :=
  fun x y =>
    match x, y with
    | 0, 0 => 1
    | 0, hy + 1 => hy + 2
    | hx + 1, 0 => ex3 hx 1
    | hx + 1, hy + 1 => ex3 hx (ex3 hx hy)

#eval ex3 2 3


--def ex3: Nat → Nat → Nat :=
  --fun x y =>
    --if x == 0 then 
      --if y == 0 then 1
      --else y + 1
    --else 
      --if y == 0 then ex3 x 1
      --else ex3 x (ex3 x y)

--def ex3': Nat → Nat → Nat :=
  --fun x y =>
    --match x, y with
    --| 0, 0 => 1
    --| 0, hy => hy + 1
    --| hx, 0 => ex3' hx 1
    --| hx, hy => ex3' hx (ex3' hx hy)
