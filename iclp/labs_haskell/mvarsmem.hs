import Control.Concurrent 
import Control.Monad 
import Text.Printf

{-
    Sa se scrie un program concurent care primeste un mesaj la STDIN 
    un thread va prelua mesajul si il va directiona unui alt thread,
    utilizand o zona partajata de memorie, spre a-l modifica,
    iar modificarea va fi pusa si ea intr-o alta locatie de memorie 
    Dupa ce se va termina modificarea, vom afisa mesajul la STDOUT 
-}

recv :: MVar String -> MVar String -> IO ()
recv frM toM = do
    message <- takeMVar frM
    printf "received <%s>; sending <%s>\n" message message
    putMVar toM message

recvModif :: MVar String -> MVar String -> IO ()
recvModif frM toM = do
    message <- takeMVar frM
    let rev = reverse message
    printf "received <%s>; sending <%s>\n" message rev
    putMVar toM rev

main = do
    line <- getLine

    init <- newEmptyMVar
    midd <- newEmptyMVar
    fin  <- newEmptyMVar

    t1 <- forkIO $ recv      init midd
    t2 <- forkIO $ recvModif midd fin

    putMVar init line
    finMsg <- takeMVar fin

    print finMsg
