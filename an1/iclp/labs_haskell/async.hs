import Control.Concurrent 
import Control.Monad 

{-
    Comunicarea asincrona - se creeaza un thread pentru fiecare actiune
    si se asteapta rezultatul actiunii respective 
-}

newtype Async a = Async (MVar a) 

async :: a -> IO (Async a)
async action = do
    m <- newEmptyMVar
    forkIO $ do 
        let val = action
        putMVar m val
    return (Async m)

await :: Async a -> IO a
await (Async m) = do takeMVar m

fib :: Int -> Int
fib 0 = 0
fib 1 = 1
fib n = fib (n - 1) + fib (n - 2)

main = do
    p1 <- async $ fib 10
    p2 <- async $ fib 20

    r1 <- await p1
    r2 <- await p2

    print r1
    print r2
