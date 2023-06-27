// ex0
method Ex0Max(a: int, b: int) returns (c: int)
  // asa da aparent
  ensures c == a || c == b
  ensures c >= b && c >= a
  /* dar daca fac asa nu merge pentru 
    ca verifica doar ca e majorant
    ensures c >= b && c >= a
  */
{
    if (a > b) {
        return a;
    } else {
        return b;
    }
}

// ex2
method Ex2Abs(x: int) returns (y: int)
  requires x < 0
  ensures 0 <= y
  ensures 0 <= x ==> y == x
  ensures x < 0 ==> y == -x
{
    return -x;
}

// ex3
method Ex3Abs(x: int) returns (y: int)
  requires x == -1
  // Don't change the postconditions.
  ensures 0 <= y
  ensures 0 <= x ==> y == x
  ensures x < 0 ==> y == -x
{
  y:= x + 2;
}

method Ex3Abs2(x: real) returns (y: real)
  // Add a precondition here so that the method verifies.
  requires x == -0.5
  // Don't change the postconditions.
  ensures 0.0 <= y
  ensures 0.0 <= x ==> y == x
  ensures x < 0.0 ==> y == -x
{
  y:= x + 1.0;
}


// ex4
function ex4max(a: int, b: int): int
{
  if (a > b) then a else b
}

function method ex5max(a: int, b: int): int
{
    if (a > b) then a else b
}

method Testing() returns (r: int) {
    r := ex5max(3, 5);
    assert r == 5;
}

method Testings() {
    // ex1
    var n := Ex0Max(3, 5);
    assert n == 5;

    // test ex 2
    n := Ex2Abs(-3);
    assert n == 3;

    // test ex 4
    assert ex4max(1, 2) == 2;
    assert ex4max(3, 3) == 3;
    assert ex4max(7, 4) == 7;
}


// ex 7
method ex7m(n: nat)
{
  var i: int := 0;
  while i < n
    invariant 0 <= i <= n  // Change this. What happens?
    /*invariant 0 <= i <= n + 2*/
  {
    i := i + 1;
  }
  assert i == n;
}

// ex 8
method ex8m(n: nat)
{
  var i: int := 0;
  while i != n  // Change this. What happens?
    invariant 0 <= i <= n
  {
    i := i + 1;
  }
  assert i == n;
}

// ex9
function fib(n: nat): nat
{
  if n == 0 then 0
  else if n == 1 then 1
  else fib(n - 1) + fib(n - 2)
}

method ComputeFib(n: nat) returns (b: nat)
  ensures b == fib(n)  // Do not change this postcondition
{
  // Change the method body to instead use c as described.
  // You will need to change both the initialization and the loop.

  var i: int := 0;
  var c := 1;
  b := 0;

  while i < n
    invariant 0 <= i <= n
    invariant b == fib(i)
    invariant c == fib(i + 1)
  {
    b, c := c, b + c;
    i := i + 1;
  }
}

method ComputeFib2(n: nat) returns (b: nat)
  ensures b == fib(n)  // Do not change this postcondition
{
  // Change the method body to instead use c as described.
  // You will need to change both the initialization and the loop.
  if n == 0 { return 0; }
  var i: int := 1;
  var a := 0;
  b := 1;
  while i < n
    invariant 0 < i <= n
    invariant a == fib(i - 1)
    invariant b == fib(i)
  {
    a, b := b, a + b;
    i := i + 1;
  }
}

method Testinggg() {
    var n := ComputeFib(5);
    print n;
    /*print ComputeFib(4);*/
    /*print ComputeFib(3);*/
    /*print ComputeFib(2);*/
    /*print ComputeFib(1);*/
    /*print ComputeFib(0);*/
}

function max(a: int, b: int): int
{
  if (a > b) then a else b
}

method SumMaxBackwards(s: int, m: int) returns (x: int, y: int)
    requires m >= s - m
    ensures s == x + y
    ensures m == max(x, y)
{
    x := m;
    y := s - m;
}
