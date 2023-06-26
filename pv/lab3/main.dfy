
function gcd(a: nat, b: nat): (z: nat)
requires a >= 0 && b >= 0
decreases a + b
{
    if (a == 0) then b
    else if (b == 0) then a
    else if (a > b) then gcd(a - b, b)
    else gcd(a, b - a)
}

method ComputeGCD(a: nat, b: nat) returns (z: nat)
    requires a >= 0 && b >= 0
    ensures z == gcd(a, b)
{
    var x: int := a;
    var y: int := b;

    if (x == 0) {return y;}
    if (y == 0) {return x;}

    while (x > 0) 
        invariant x >= 0 && y > 0
        invariant gcd(x, y) == gcd(a, b)
        decreases x + y
    {
        if (x < y) {
            y := y - x;
        } else {
            x := x - y;
        }
    }
    return y;
}

method ArrayFind(arr : array<int>, k : int) returns (index : int) 
ensures index >= 0 ==> index < arr.Length && arr[index] == k
ensures index >= 0 ==> forall i :: 0 <= i < index ==> arr[i] != k
ensures index < 0 ==> index == -1 && forall i :: 0 <= i < arr.Length ==> arr[i] != k
{
    index := 0;
    while (index < arr.Length)
    invariant index <= arr.Length
    invariant forall i :: 0 <= i < index ==> arr[i] != k
    {
        if (arr[index] == k) {
            return index;
        }
        index := index + 1;
    }
    index := -1;
}

method Test() {
    var x: int := ComputeGCD(18, 12);
    assert x == 6;

    x := ComputeGCD(18, 19);
    assert x == 1;
     
    x := ComputeGCD(19, 18);
    assert x == 1;

    x := ComputeGCD(19, 0);
    assert x == 19;
}
