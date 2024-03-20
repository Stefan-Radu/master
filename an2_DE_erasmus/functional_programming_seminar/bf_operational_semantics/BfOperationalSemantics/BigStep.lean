import «BfOperationalSemantics».Basic

inductive BigStep: Op × State → State → Prop where
  | nop  (s: State): BigStep (Op.nop, s)  s
  | pInc (s: State): BigStep (Op.pInc, s) s.applyPInc
  | pDec (s: State): BigStep (Op.pDec, s) s.applyPDec
  | vInc s: BigStep (Op.vInc, s) s.applyVInc
  | vDec s: BigStep (Op.vDec, s) s.applyVDec
  | brakPairTrue {ops} {s t u: State}
    (c: *s ≠ 0)
    (body: BigStep (ops, s) t)
    (rest: BigStep ((Op.brakPair ops), t) u):
      BigStep (Op.brakPair ops, s) u
  | brakPairFalse ops (s: State) (c: *s = 0):
      BigStep (Op.brakPair ops, s) s
  | seq (S s T t u)
    (h:  BigStep (S, s) t)
    (h': BigStep (T, t) u):
      BigStep ((Op.seq S T), s) u
  | input s: BigStep (Op.input, s) s.applyInput
  | output s: BigStep (Op.output, s) s.applyOutput

infix:110 " ⟹  " => BigStep

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
    (*s ≠ 0 ∧ (∃ (t: State), (op, s) ⟹ t ∧ (Op.brakPair op, t) ⟹ u))
  ∨ (*s = 0 ∧ (u = s))) :=
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

@[simp] theorem BigStep_brakPairTrue_Iff {op: Op} {s u: State} (cond: *s ≠ 0) :
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

@[simp] theorem BigStep_brakPairFalse_Iff {op: Op} {s u: State} (cond: *s = 0) :
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
