import Prelude
import Control.Concurrent
import Control.Monad
import Text.Printf

{-
    - concurenta in Haskell are loc in monada IO 

    forkIO :: IO () -> IO ThreadId 

    data MVar a 

    newEmptyMVar :: IO (MVar a)
    -- imi permite sa creez o locatie goala de memorie 
    -- m <- newEmptyMVar 

    newMVar :: a -> IO (MVar a)
    -- creeaza o locatie de memorie care contine o valoare specificata
    -- m <- newMVar v 

    takeMVar :: MVar a -> IO a 
    -- v <- takeMVar m 
    -- intoarce in v valoarea din locatia de memorie m
    -- daca m este o locatie goala, atunci se blocheaza threadul 

    putMVar :: MVar a -> a -> IO () 
    -- putMVar m v 
    -- pune in m valoarea v 
    -- blocheaza thread-ul daca locatia de memorie este plina 

    :! ghc --make nume.hs 
    cmd: nume 

    Concurenta in Haskell. Threaduri. Memorie partajata 
-}

-- Implementam doua threaduri care sa incrementeze un contor

inc :: MVar Int -> MVar String -> IO ()
inc m ms = do
    replicateM_ 10 $ do
        x <- takeMVar m
        printf "value in m from %d to %d\n" x (x + 1)
        putMVar m (x + 1)
    putMVar ms "finished"


main = do
    m <- newMVar 0
    ms <- newEmptyMVar

    t1 <- forkIO $ inc m ms
    t2 <- forkIO $ inc m ms

    takeMVar ms
    takeMVar ms
    x <- takeMVar m
    print x
