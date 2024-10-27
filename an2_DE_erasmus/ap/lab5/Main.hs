

k = [1, 2, 3]

rep :: Foldable list => list Integer -> Integer
rep = sum

-- ex 1
-- a) \x y -> (x + y) > 0 
--      (Ord a, Num a) => a -> a -> Bool
-- b) (< 3) 
--      (Ord a) => a -> Bool
-- c) foldRight (\a b -> Cons (abs a) b)
--      (Foldable a) => a -> List a -> a
-- d) f a b = if a == 0 then head b else f (a-1) (tail b)
--      (Eq a, Num a) => a -> List b -> b
-- e) f a b (Left c) = Left (a c)
--    f a b (Right c) = Right (b c)
--      (a -> b) -> (c -> d) -> Either a c -> Either b d

data List a 
    = Nil 
    | Cons a (List a) 
    deriving Show

head :: List a -> a
head (Cons h t) = h

tail :: List a -> List a
tail Nil = Nil
tail (Cons h t) = t
