

/-
  ***Dependent types*** 

  In Lean, the return type of a function may dependent on the *value* of its input.
  Such a function is called *dependently typed* and its type is called 
  a *dependent function type* or a *Π*-type.

  Given a `α : Type` and `β : α → Type`, 
  we can construct the dependent function type `∀ x : α, β x`.
  If `f : ∀ x : α, β x` is a function of this type,
  if we apply it to some argument `a : α`, 
  then the result, `f a`, will be of type `β a`, 
  so a (potentially) different type for each different input `a`.
-/

-- `Nat`, `String`, `Bool`
-- `String → Bool`, `(String → Bool) → Bool`
-- if `α` and `β` are types, then `α → β` is again a type
-- if `f : α → β`, and `a : α`, then `f a : β`

-- if `α : Type` is a type, and `β : α → Type`, then `∀ x : α, β x` a type
-- `f : ∀ x : α, β x` and `a : α`, then `f a : β a`

/-
  We can use dependent type to write functions whose results are correct by definition,
  in the sense that the program won't typecheck if the function we wrote is incorrect 
  (under some notion of "correctness").

  For any type `α` and natural number `n`, `Vector α n` is 
  the type of lists with elements of type `α` and of length equal to `n`.
  That is, one cannot use a vector of a different length 
  where a vector of some length `n` is expected, as that would be a type error.

  Below, is the definition: a `Vector α n` is made of a list 
  together with a proof that the list has length `n`.
-/

-- List α 
-- Vector α n
-- [0, 4] : Vector Nat 2 
-- [0, 4, 3] : Vector Nat 2   typeerror

structure Vector (α : Type) (n : Nat) where 
  data : List α 
  length_correct : data.length = n 

#check Vector

/-
  In order to define a vector, we need to choose a list, and prove that its length is the correct one.
-/
def v : Vector Int 5 := {
  data := [1, 2, 3, 4, 5]
  length_correct := by 
    -- here goes the proof of the correctness of the length 
    -- in this, we need to prove 
    -- `⊢ List.length [1, 2, 3, 4, 5] = 5`
    -- this is an tedious proof, luckily the `decide` tactic finishes the proof 
    -- `decide` is used can be used to prove goals that follow from a simple computation, with explicit values 
    decide
}

/-
  **Exercise 1**: replace the `sorry` with a definition of a vector of strings and length 3
-/
def three_strings : Vector String 3 := {
  data := ["ana", "are", "mere"]
  length_correct := by
    decide
}

#reduce List.reverse [2, 3, 4]
#check @List.reverse

/-
  Defining functions between vectors means defining functions between lists 
  and proving their behaviour with respect to length. 
  For instance, the reversal operations on lists should preserve length, 
  meaning that the reversal operations on vectors will be of type 
  `Vector α n → Vector α n` (no change in `n`).

  We can use builting `List.reverse` for list reversal in order to define it.
-/
def Vector.reverse {α : Type} {n : Nat} (x : Vector α n) : Vector α n := 
  {
    data := List.reverse x.data -- what should happen to the list data contained in the vector
    length_correct := by -- we prove that this transformation maps list of length `n` to list of length `n`
      -- We know that `length x = n`, because `x` is a `Vector α n`,
      -- and the proof of this is stored in the `length_correct field`.
      -- For ease, we may introduce this as a local hypothesis, using `have`
      have x_len : List.length x.data = n := x.length_correct 
      -- We can simplify our goal by changing `length (reverse x)` into `length x`,
      -- because there is a theorem `List.length_reverse` (see the `#check` below) which states that they are equal
      rw [List.length_reverse]
      -- After this rewrite, the goal and the `x_len` are the exact same
      assumption -- or exact x_len 
      -- so we are done
  }


#check @List.length_reverse

/-
  **Exercise 1:** Define the function `Vector.append`,
  which, for any type `α` and natural number `n` and `m`, 
  should take a `Vector α n` and a `Vector α m` 
  and return the vector resulting from their appending.
  Before giving the definition, you also have to decide what the return type of the function should be.
  
  You can use the `List.append` function for appending the underlying lists.
  You can use the `List.length_append` in the proof of `length_correct`
-/
-- List.append xs ys = (xs ++ ys)
#check @List.append
#check @List.length_append
def Vector.append {α : Type} {n m : Nat} (x : Vector α n) (y : Vector α m) : Vector α (n + m) := 
{
  
}



/-
  **Exercise 2:** Any list `x : List α` is either the empty list, or is of the form `h :: t`,
  where `h : α` and `t : List α` (you can think of as being structurally like a linked list).
  Therefore, we may pattern matching to define functions on lists.
-/
@[simp]
def List.repeat {α : Type} (a : α) (n : Nat) : List α :=
match n with 
| 0 => [] 
| (n + 1) => a :: (repeat a n)

#reduce List.repeat "ab" 9

/-
  **Exercise 3:**: 
  Below is a proof by induction for the function the `length (repeat n) = n`. 
  Fill the two `sorry`s in the theorem below.
  Hint: Try using the proof automation tactic called `simp`.
-/

theorem length_repeat {α : Type} : ∀ (a : α) (n : Nat), List.length (List.repeat a n) = n := by 
  intros a n
  induction n
  case zero => 
    sorry
  case succ m ih => 
    sorry



/-
  **Exercise 4:** Define the `Vector.repeat` function which behaves like `List.repeat`,
  but is correct length-wise by the type signature.
-/

def Vector.repeat {α : Type} (a : α) (n : Nat) : _ := sorry


