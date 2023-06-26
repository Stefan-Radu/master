/-
  ### Introduction

  Goals of this lab:
    + learning the basics of Lean and more generally those of interactive theorem proving 
    + implementing some of the logical systems you will learn in the course

  Lean is a interactive theorem prover and a functional programming language
  with a rich type systems based on *dependent type theory*.
  Beyond programming, the expressiveness of the type system will allow us to state *theorems* and prove them, 
  as we will see in future labs.

-/


/-
  ### LAB 1: Basics of functional programming in Lean
  In the future labs, we will mostly focus on theorem proving,
  but the first lab is a brief tour of functional programming in Lean.
-/

/-
  We can use the `#check` command to see the type of a term.
-/
#check 7
#check true
#check "hello world"
#check Nat
#check Bool
#check String 
#check Nat → String


#check Type
#check Type 1

universe u
#check Type u -- asta va avea tip <Type (u + 1)>

/-
    Type 0: Type 1: Type 2: ...

    daca am avea Type: Type -> am putea demonstra False (paradox cunoscut)
    Girads's Paradox
-/


/-
  Tip: You can hover over unicode symbols to see how to input them. 
  For example `→` is typed `\to`.
-/

-- Ignore the following line
set_option autoImplicit false -- e mai bine didactic sa fie asta aici

/-
  ## Defining functions
  We can define functions using the following syntax.
-/
def plus5 (n : Nat) : Nat := n + 5 

/-
  Types may be omitted when Lean is able to infer them.
-/
def plus5' (n : Nat) := n + 5

def plus5'' (n) := n + 5

/-
  We can evaluate a function with `#eval`.
-/
#eval plus5 8

/-
  Lambda expressions (also known as lambda abstractions, anonymous functions, closures) are first-class objects in Lean.
  Below, `fun n : Nat => n + 5` is a term representing the function that maps `n` to `n + 5`.
  We could have also defined our `plus5` function to simply be this lambda expression.
-/
#check fun n : Nat => n + 5 

def plus5''' := fun n : Nat => n + 5

/-
  Note that plus5, plus5', plus5'' and plus5''' are all the *same* definition,
  just written in different notations.
-/

/-  
  ## Currying.
  Functions with multiple arguments are usually *curried*. 
  Consider the addition on natural numbers, `Nat.add`, which should take two `Nat`s and return a `Nat`.
  Its type is `Nat → Nat → Nat`, which is the same as `Nat → (Nat → Nat)` (i.e. `→` is right associative).
  `Nat.add` takes a natural number `n` and returns a function `Nat.add n : Nat → Nat` (the function adding `n` to its argument).
  `Nat.add n` is also called a *partial application* of `Nat.add`.
  If we further apply it to an `n : Nat`, we get `(Nat.add n) m : Nat` (the sum between `n` and `m`).
  Function application is left associative, so we simply write `Nat.add n m`. 
-/

-- Nat → (Nat → Nat)
#check Nat.add
#check Nat.add 5
#check Nat.add 5 7
#eval Nat.add 5 7

/-
  Even one more way to write `plus5`, as a partial application of `Nat.add` to `5`:
-/
def plus5'''' := Nat.add 5

def plus (n : Nat) (m : Nat) := n + m
def plus' (n m : Nat) := n + m

/-
  It is immediate in Lean to write generic functions whose arguments can be of arbitrary types. 
  The details of how this works are beyond the scope of this lab.

  **Exercise 1**: Replace the `sorry` with a definition for `applyFunction` below, which,
  for arbitrary types `α` and `β`, 
  takes some `a : α` and a function `f : α → β` and applies `f` to the argument `a`.
-/

def applyFunction {α β : Type} : α → (α → β) → β := 
    fun (a : α) (f : α → β) => f a

-- putem pune fun = sorry cand nu vrem sa dam definitia (ca un pass in python kinda)

def myId {α : Type} : α → α := fun a => a
def myId' (α : Type) : α → α := fun a => a

#eval myId "abc" -- asa da, pt ca infera argumentul implicit
#eval @myId String "abc" -- transforma argumentele implicite in explicite
#eval myId (α := String) "abc" -- sau pot sa ii specific eu explicit cine sa fie α ca sa nu-l mai infere automat
#eval myId' "abc" -- asa nu, pt ca nu i-am dat primul argument
#eval myId' String "abc" -- asa da

#eval myId' Type String -- nu merge pentru ca se asteapta ca primul argument sa fie de tip <Type>, dar Type e de tip <Type 0> 

def myId'' (α : Type _) : α → α := fun a => a

#eval myId'' Type String -- nu merge ca nu stie "sa calculeze" un tip
#reduce myId'' Type String -- asta merge in schim. e ca o reducere teoretica

#check myId
#check myId'

/-
  ## Defining new types
  We've seen some builtin types, like `Nat` or `String`.
  Defining new types is one of the most important aspects of working in Lean,
  and next we will see some of ways of doing this.
-/

/-
  A *structure*, like in most programming language (called "record" in some languages),
  is a tuple made of a number of named fields of potentially different types.
-/
structure Student where 
  name : String 
  group : Nat

#check Student

/-
  **Exercise 2**:
    Uncomment the next `def` and define a term `me` of type `Student` as below, by filling the underscores.
    In Lean, you can always place an underscore where a term is expected, 
    and the infoview will show you its expected type if you move the carret over it.
-/
def me : Student := { name := "Stefan", group := 410 }

def gr := me.group
#eval gr

#eval toString 300

/-
  We can access the fields of structure using dot notations, 
  like in the following example (also called projection notation).
-/
def personToString : Student → String := 
  fun student => student.name ++ " din grupa " ++ (toString student.group)

/-
  **Exercise 3**:
  Call the `personToString` function on the `me` you defined earlier and `#eval` the result.
-/

def meString := personToString me
#eval meString

/-
  Like with functions, it's easy to construct types depending on other types.
  Given two types `α` and `β`, there is a type `Prod α β` made of pairs `(a, b)` where `a : α` and `b : β`.
  This is a builtin type whose definition is roughly the one below (we put it in the `Hidden` namespace to avoid name conflicts 
  with the builtin `Prod`).
-/

namespace Hidden

  structure Prod (α β : Type) where 
    fst : α
    snd : β

/-
  Note that `Prod` has two type parameters; `Prod` is of type `Type → Type → Type`.
-/

    #check Prod
    #check @Prod.mk

end Hidden


/-
  When we want to defer writing a definition for later, we can replace it to `sorry`,
  a "term" that fits everywhere, for Lean to stop complaining.
  **Exercise 4**:
    Fill the `sorry` below to define the function `swap` that, given the pair `(a, b) : Prod α β`, swaps its components,
    returning the pair `(b, a) : Prod β α`. 
-/

def swap {α β : Type} (p : Prod α β) : Prod β α := (p.snd, p.fst)
def swap' {α β : Type} (p : Prod α β) : Prod β α := ⟨p.snd, p.fst⟩
def swap'' {α β : Type} (p : Prod α β) : Prod β α := 
  { fst := p.snd, snd := p.fst }
def swap''' {α β : Type} (p : Prod α β) : Prod β α := Prod.mk p.snd p.fst
def swap'''' {α β : Type} (p : Prod α β) : Prod β α := Prod.mk p.2 p.1

#eval swap (1, 2)
#eval swap' (1, 2)
#eval swap'' (1, 2)
#eval swap''' (1, 2)
#eval swap'''' (1, 2)


/-
  ## Inductive types, pattern matching and recursion
  Inductive types (related to algebraic datatypes in other languages) 
  are defined by specifying all the ways their terms can be constructed.
  The ways a term of an inductive type can, by definition, 
  be constructed are called *constructors* and are functions whose return type has to be the inductive type being defined.
-/

namespace Hidden 

  /-
    Again in the `Hidden` namespace to avoid naming conflicts, 
    below is the definition of the `Nat` type we used earlier.
  -/

  inductive Nat where
  | zero : Nat 
  | succ : Nat → Nat

  -- zero : Nat
  -- one = succ zero : Nat
  -- two = succ (succ zero) : Nat

  /-
    The constructors are `zero` and `succ`.
    This means that terms of type `Nat` are all either `zero` or of the form `succ n` for some `n : Nat`.
  -/

end Hidden

/-
  The constructors of `Nat` are not in the global namespace; their full names are `Nat.zero` and `Nat.succ`.
  We open the `Nat` namespace to have them available.
-/
open Nat

/-
  Functions on inductive types are defined using *recursion* and *pattern matching*.
-/
def isZero (n : Nat) : Bool := 
  match n with 
  | zero => true 
  | succ m => false 

/-
  The following is a shorthand syntax for the above.
  Note that in the `succ n` pattern we don't do use `n` in the definition, 
  so we can put an underscore instead of giving it a name.
-/
def isZero' : Nat → Bool 
| zero => true 
| succ _ => false

/-
  Definitions by pattern matching can also be recursive.
-/
def nthSum : Nat → Nat
| zero => zero
| succ n => (succ n) + nthSum n

#eval nthSum 5
#print nthSum -- arata definitia

/-
  There are builtin notations like `0` for `zero` and `n + 1` for `succ n` but they are the same thing under the hood.
-/
def nthSum' : Nat → Nat
| 0 => 0
| n + 1 => (n + 1) + nthSum n

/-
  Warning. By default, all functions need to terminate. 
  If it can not tell that function terminate, Lean will give an error.
  This may happen when the function indeed does not terminate (as in the example below),
  or when it does terminate but Lean cannot figure out by itself how to prove termination.
-/

def nonterminating : Nat → Nat 
| n => nonterminating (n + 1)

partial def nonterminating' : Nat → Nat 
| n => nonterminating' (n + 1) -- putem face asta, dar nu le mai putem studia ca functii 
--- pentru ca nu sunt functii matemateice studiabile

unsafe def nonterminating'' : Nat → Nat 
| n => nonterminating'' (n + 1) -- la fel ca partial, dar putin diferit


/-
  **Exercise 5**:
    Using pattern matching, define the `factorial` function, computing the factorial of a natural number.
-/

-- def factorial : Nat → Nat
-- factorial 0 = 1
-- factorial n = n * (factorial n - 1)

def factorial : Nat → Nat
| 0 =>  1
| n + 1 => (n + 1) * (factorial n)

/-
  We can also prove theorems in Lean. This is not the subject of today's lab, 
  but if your definition is correct the line below will not give an error
  and will be a formal proof of the fact that `factorial 5 = 120`.
-/
example : factorial 5 = 120 := rfl


/-
  Another common type in a functional programming, builtin in Lean, is the `Option` type, which is parametric in a type.
  Given a type `α`, `Option α` has two constructors, `none : Option α` and `some : α → Option α`.
  A term of type `Option α` is either `none` or of the form `some a`, for some `a : α`.
  `Option` is commonly used to indicate error values, with `none` representing an error 
  and `some a` a valid value.
-/

namespace Hidden

  inductive Option (α : Type) where 
  | none : Option α 
  | some : α → Option α

end Hidden 

/-
  Subtraction on natural numbers is ill-behaved, in the sense that one cannot subtract m from n when `n < m`.
  Lean's builtin subtraction returns `0` for `n - m` when `n < m`. 
  **Exercise 6**: 
    Define the `sub?` function below, return the right results of `n - m` when `n ≥ m` and an error otherwise.
  Hint:
    Use the `if ... then ... else ...` expression.
-/

/-
conventii ? -> intoarce un Option
          ! -> intoarce o valoare default in cazul in care nu exista un raspuns bun
-/

def sub? : Nat → Nat → Option Nat := fun n m =>
  if n < m then none else some <| n - m -- <| e ca $ in Haskell, dar exista si >| 

-- sub? 5 3 = some 2
-- sub? 2 7 = none

/-
  **Exercise 7**: 
    Define, without using the builtin `Nat.add` or `+`, the `myAdd` function below, adding two natural numbers.
-/
-- def myAdd' (n m : Nat) : Nat := 

def myAdd : Nat → Nat → Nat := fun a b =>
 match b with
 | Nat.zero => a
 | Nat.succ b' => Nat.succ (myAdd a b')

/-
  Like with `factorial`, if your definition is correct, the example below should give no errors.
-/
example : myAdd 28 49 = 77 := rfl 
-- sau
theorem add_77: myAdd 28 49 = 77 := rfl

/-
  Depending on the way you defined `myAdd`, one of the `theorem`s below will probably be correct, 
  but the other will still give an error,
  so you will have formally proved either that `0 + n = n` or that `n + 0 = n` for all natural numbers `n`.
  Try to guess which one will succeed and then uncomment both theorems to see what happens.
-/
-- 0 + n = n
-- theorem zero_add (n : Nat) : myAdd 0 n = n := rfl 

-- n + 0 = n
theorem add_zero (n : Nat) : myAdd n 0 = n := rfl --> trivial pentru ca se math-uieste din prima pe cazul zero
