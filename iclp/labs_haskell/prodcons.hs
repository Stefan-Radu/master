module Main where 

import Control.Concurrent 
import Control.Monad 

{- 
    Problema Producer-Consumer 

    MVar ca monitor 

    - producatorul va citi incontinuu mesaje de la STDIN si le va pune
        intr-o locatie partajata de memorie 
    - un numar finit de consumatori vor afisa mesajele respective
        la STDOUT 
-}

producer :: MVar [String] -> IO ()
producer store = forever $ do
    newLine <- getLine
    curStore <- takeMVar store
    putMVar store (newLine:curStore)

consumer :: MVar [String] -> Int -> IO ()
consumer store cnt = do
    if cnt == 0 
       then return ()
    else do
        forkIO $ forever $ do
            curStore <- takeMVar store
            case curStore of
                [] -> do
                    putMVar store []
                (h:t) -> do
                    print h
                    putMVar store t

        consumer store (cnt - 1)



main = do
    store <- newMVar []
    --sync <- newMVar 3
    forkIO $ producer store
    forkIO $ consumer store 2
