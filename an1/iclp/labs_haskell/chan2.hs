import Control.Monad
import Control.Concurrent


type Stream a = MVar (Item a)
data Item a = Item a (Stream a)
data Chan' a = Chan' (MVar (Stream a)) (MVar (Stream a))

newChan' :: IO (Chan' a)
newChan' = do
    emptyStream <- newEmptyMVar
    readStream <- newMVar emptyStream
    writeStream <- newMVar emptyStream
    return (Chan' readStream writeStream)

readChan' :: Chan' a -> IO a
readChan' (Chan' re _) = do
    rc <- takeMVar re
    Item val s <- takeMVar rc
    putMVar re s
    return val

writeChan' :: Chan' a -> a -> IO ()
writeChan' (Chan' _ writePart) val = do
    writeStream <- takeMVar writePart
    let item = takeMVar writeStream
        newItem = Item val writeStream
    putMVar wr newItem


main = do undefined
