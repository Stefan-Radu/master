
-- the type of propositions
#check Prop
-- Prop = Bool ? NO 
-- Given `p : Prop`. `p` is again a type (the type of its proofs).
-- `h : p` (`h` is a proof of `p`)
-- "Propositions-as-types" / "Curry-Howard correspondence"

namespace BasicPropostions

  -- 2 ∈ ℕ is a proposition in "mathematics with pen and paper"

  -- 2 : ℕ is **NOT** a proposition in Lean, it's just a type annotation
  
  def p : Prop := Nat.succ 2 = 3

  def q := 0 = 0 

  def r := 0 ≠ 0



  theorem th : 0 = 0 := rfl
  theorem th': 0 ≠ 0 := rfl

  #check th
  #check 2

end BasicPropostions


namespace LogicalConstructors

  -- `p q : Prop` ==> `p ∧ q : Prop`

  variable (p q : Prop) -- From here, let `p` and `q` be two arbitrary propositions.

  #check p ∧ q -- And p q 

  #check p ∨ q -- Or q

  #check ¬p -- Not p

  #check False 

  #check True

  #check p → q -- 

end LogicalConstructors 


-- identity x = x
def identity : Int → Int := fun x : Int => x

namespace PropositionalTheorems

  variable (p : Prop)

  theorem p_imp_p : p → p := fun h : p => h

  -- α → β → γ     =     α → (β → γ) 
  theorem p_imp_q_imp_p : p → q → p := 
    fun (hp : p) (hq : q) => hp

  

  variable (q : Prop)

  #print And
  #check @And.intro    -- introduction principle 
  #check @And.left     -- elimination principle 
  #check @And.right    -- elimination principle 

  #print Or 
  #check @Or.inl 
  #check @Or.inr 
  #check @Or.elim

  #print True -- `True.intro : True`, a trivial proof

  #print False -- no way to construct `h : False`
  #check @False.elim

  #print Not
  -- ¬p  =  p → False

  #print Iff
  #check @Iff.intro

  -- term mode proofs

  theorem p_and_q_imp_q : p ∧ q → q := 
    fun hpq : p ∧ q => And.right hpq 

  theorem p_and_q_imp_q' : p ∧ q → q := 
    fun hpq : p ∧ q => hpq.right

  theorem p_and_q_imp_q'' : p ∧ q → q := And.right 
  
  theorem and_comm : p ∧ q → q ∧ p := 
    fun hpq : p ∧ q => And.intro hpq.right hpq.left

  theorem and_comm' : p ∧ q → q ∧ p := 
    fun hpq : p ∧ q => ⟨hpq.right, hpq.left⟩   

  
  theorem p_imp_p_or_q : p → p ∨ q := 
    fun hp : p => Or.inl hp

  #check @Or.inl
  #check p_imp_p_or_q

  theorem p_imp_p_or_q' : p → p ∨ q := Or.inl

  theorem or_comm : p ∨ q → q ∨ p := 
    fun hpq : p ∨ q => Or.elim hpq Or.inr Or.inl

  theorem or_comm' : p ∨ q → q ∨ p := 
    fun hpq : p ∨ q => Or.elim hpq Or.inr (p_imp_p_or_q q p)

  theorem or_comm'' : p ∨ q → q ∨ p := 
    fun hpq : p ∨ q => Or.elim hpq Or.inr (p_imp_p_or_q _ _)

  theorem p_not_p_imp_false : p → (¬p) → False := 
    fun (hp : p) (hnp : p → False) => hnp hp

  theorem p_and_not_p_imp_false : p ∧ ¬p → False := 
    fun hpnp : p ∧ ¬p => hpnp.right hpnp.left

  theorem p_and_not_p_imp_false' : ¬(p ∧ ¬p) :=  
    fun (hpanp: p ∧ ¬p) => hpanp.right hpanp.left

  theorem p_not_p_imp_anything : p → (¬p) → q := 
    fun (hp: p) (hnp: ¬p) => 
    let f: False := hnp hp
    False.elim f

  #check @Classical.em
  #check @id

  theorem dni : p → ¬¬p := 
    fun hp: p => 
    let h': ¬p ∨ ¬¬p := Classical.em ¬p
    match h' with
    | Or.inl hnp => 
      let f: False := hnp hp
      False.elim f
    | Or.inr hnnp => hnnp

  theorem dne : ¬¬p → p :=
    fun h =>
    let h' : p ∨ ¬p := Classical.em p
    match h' with
    | Or.inl hp => hp
    | Or.inr hnp => 
      let f: False := h hnp
      let hp: p := f.elim
      hp

  theorem p_iff_not_not_p : ¬¬p ↔ p := 
    Iff.intro (dne _) (dni _)

  -- tactic mode proofs 

  theorem p_imp_p_tactic : p → p := by 
    intros hp -- suppose that we have a proof `hp` of `p`
    assumption

  theorem p_imp_q_imp_p_tactic : p → q → p := by 
    intros hp _
    assumption

  theorem p_and_q_imp_q_tactic : p ∧ q → q := by 
    intros hpq
    cases hpq with | intro hp hq => 
    assumption

  theorem and_comm_tactic : p ∧ q → q ∧ p := by 
    intros hpq 
    cases hpq with | intro hp hq => 
    apply And.intro
    case left => assumption
    case right => assumption
    
  theorem p_imp_p_or_q_tactic : p → p ∨ q := by 
    intros hp 
    apply Or.inl
    assumption

  theorem or_comm_tactic : p ∨ q → q ∨ p := sorry

  
  theorem dni_tactic : p → ¬¬p := by 
    intros hp hnp
    apply hnp
    assumption

  theorem dne_tactic : ¬¬p → p := sorry 

end PropositionalTheorems



section Exercises 

  /-
  **Exercise 1: prove the following theorem, with the same statement as `p_iff_not_not_p`, but using tactic mode**
  -/
  theorem p_iff_not_not_p_tactic : p ↔ ¬¬p := by 
    sorry

  /-
  **Exercise 2: prove the following theorem, in any mode you prefer** 
  -/
  theorem and_imp_or : p ∧ q → p ∨ q := 
    fun hpaq: p ∧ q => 
      let hp: p := And.left hpaq
      Or.inl hp

  /-
  **Exercise 3: prove the following theorem, in any mode you prefer** 
  -/
  theorem demorgan₁ : ¬p ∧ ¬q → ¬(p ∨ q) := 
    fun (hnpahnq: ¬p ∧ ¬q) (hpoq: p ∨ q) =>
      let hnp := And.left hnpahnq
      let hnq := And.right hnpahnq
      match hpoq with
      | Or.inl hp => False.elim (hnp hp)
      | Or.inr hq => hnq hq

end Exercises 
