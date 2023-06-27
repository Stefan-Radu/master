import Test.QuickCheck
import Data.Char

-- 1.1
sum1 = let sum1Helper _ [] = 0
           sum1Helper True (h:t) = (if h `mod` 3 == 1 then h else 0) + sum1Helper False t
           sum1Helper False (_:t) = sum1Helper True t
        in sum1Helper True

-- 1.2
sum2 l = sum [b | (a, b) <- zip [0..] l, even a, b `mod` 3 == 1]

-- 1.3
sum3 = foldr ((+) . \(a, b) -> if even a && b `mod` 3 == 1 then b else 0) 0 . zip [0..]

test1 :: [Int] -> Bool
test1 x = (sum1 x == sum2 x) && (sum1 x == sum3 x)

-- 2.1
ordonate1 :: Ord a => (a -> a -> Bool) -> [a] -> Bool
ordonate1 _ [] = True
ordonate1 _ [_] = True
ordonate1 r (h1:(h2:t)) = (h1 `r` h2) && ordonate1 r (h2:t)

-- 2.2
ordonate2 r l = let f x (Just k) = if x `r` k then Just x else Nothing
                    f x Nothing = Nothing
                    f :: Int -> Maybe Int -> Maybe Int
                 in case foldr f (Just (l !! max 0 (length l - 1))) l of
                    Just k -> True
                    Nothing -> False

test2 r x = ordonate1 r x == ordonate2 r x

-- 3
upperFromInput :: IO ()
upperFromInput = readFile "input" >>= \content -> print $ map toUpper content

-- 4
class PropLogic t where
    eval   :: t -> Bool       -- eval
    (@)    :: t -> Bool       -- eval
    (!)    :: t -> Bool       -- negation
    (->:)  :: t -> t -> Bool  -- implication
    (&&:)  :: t -> t -> Bool  -- conjunction
    (||:)  :: t -> t -> Bool  -- disjunction
    (<->:) :: t -> t -> Bool  -- equivalence

    eval = (@)
    (@) = eval
    (!) x = not (eval x)
    x ->: y = let ex = (@) x
                  ey = (@) y
               in not ex || ey
    x &&: y = (@) x && (@) y
    x ||: y = (@) x || (@) y
    x <->: y = (x ->: y) && (y ->: x)

data LogicFormula
    = Var String Bool
    {-
     -| Not LogicFormula
     -| Impl LogicFormula LogicFormula
     -}

instance PropLogic LogicFormula where
    eval (Var _ val) = val
    {-
     -eval (Not f) = not (eval f)
     -eval (Impl a b) = let ea = eval a
     -                      eb = eval b
     -                   in not ea || eb
     -}

instance PropLogic Bool where
    eval k = k

instance Eq LogicFormula where
    a == b = (@) a == (@) b

instance Show LogicFormula where
    show (Var n v) = "(" ++ n ++ ":" ++ show v ++ ")"
    {-
     -show (Not f) = "!"  ++ show f
     -show (Impl a b) = show a ++ " -> " ++ show b
     -}

main :: IO ()
main = do
    -- 1
    quickCheck test1
    -- 2
    quickCheck $ test2 (<=)
    -- 3
    upperFromInput
    -- 
    let a = Var "a" True
        b = Var "b" True
        f = a ->: b

    print f
    print $ (!) f
    print $ (f ->: (!) f) &&: (f ||: (!) f)

    return ()
