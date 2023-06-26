import Control.Concurrent
import Control.Monad
import Control.Concurrent.STM

{-
    Programul va avea un anumit numar de threaduri elf = 10 
    alte 9 threaduri ren 
    si un thread principal semafor 

    Elfii si renii formeaza grupuri de anumita capacitate 
        elfi - capacitate 3 
        reni - capacitate 9 

    dupa ce s-a realizat o grupare, ea este preluata de semafor 
    - renii au prioritate 
    - semafor trebuie sa fie liber 

    dupa ce se formeaza un grup, el intra la semafor, desfasoara o activitate si apoi pleaca 

    semafor va lasa sa intre un grup nou numai dupa ce grupul anterior a plecat 

    toate threadurile functioneaza la infinit 
-}

{-
    Ciclul de viata pentru elf/ren 
    - incearca sa intre intr-un grup 
    - dupa ce grupul s-a format, incearca sa intre la semafor 
    - executa o actiune la semafor 
    - pleaca de la semafor 
-}

{-
    dupa ce grupul se formeaza, primeste doua porti 
    - o poarta de intrare, respectiv o poarta de iesire 
    fiecare membru al grupului intra prin poarta de intrare si iese prin cea de iesire 
        corespunzatoare
    
    portile sunt operate de semafor 
-}

delay :: IO ()
delay = threadDelay 2000000

writeStdOut :: MVar () -> String -> IO ()
writeStdOut stdw str = do
    takeMVar stdw
    putStrLn str
    putMVar stdw ()

                   -- nr max chei 
data Gate = MkGate Int (TVar Int)
                        -- nr chei disponibile 

newGate :: Int -> STM Gate
newGate n = do
    tv <- newTVar 0 -- initial, numarul de chei disponibile este 0 
    return $ MkGate n tv

passGate :: Gate -> IO ()
passGate (MkGate n tv) = atomically $ do
    n_left <- readTVar tv
    if n_left == 0
        then
            retry -- daca nu mai sunt chei disponibile, reincearca 
        else
            writeTVar tv (n_left - 1) -- altfel, avem cu o cheie disponibila mai putin

-- cheile sunt date de semafor 
operateGate :: Gate -> IO ()
operateGate (MkGate n tv) = do
    atomically $ writeTVar tv n
    atomically $ do
        n_left <- readTVar tv
        if n_left > 0
            then
                retry
            else
                return ()

                    -- capacitatea unui grup 
data Group = MkGroup Int (TVar (Int, Gate, Gate))
                                -- nr de locuri disponibile
                                -- poarta de intrare
                                -- poarta de iesire 


newGroup :: Int -> IO Group
newGroup n = atomically $ do
    g1 <- newGate n
    g2 <- newGate n
    tv <- newTVar (n, g1, g2)
    return (MkGroup n tv)


joinGroup :: Group -> IO (Gate, Gate)
joinGroup (MkGroup n tv) = atomically $ do
    (n_left, g1, g2) <- readTVar tv
    if n_left == 0
        then
            retry
        else do
            writeTVar tv (n_left - 1, g1, g2)
            return (g1, g2)

awaitGroup :: Group -> STM (Gate, Gate)
awaitGroup (MkGroup n tv) = do
    (n_left, g1, g2) <- readTVar tv
    if n_left > 0
        then
            retry
        else do
            new_g1 <- newGate n
            new_g2 <- newGate n
            writeTVar tv (n, new_g1, new_g2) -- portile pentru urmatorul grup 
            return (g1, g2) -- returneaza portile pentru grupul curent 

-- actiunile propriu-zise 

helper1 :: Group -> IO () -> IO ()
helper1 group do_task = do
    (in_gate, out_gate) <- joinGroup group
    passGate in_gate
    do_task
    passGate out_gate

crossStreet:: Int -> MVar () -> String -> IO ()
crossStreet id stdw who = writeStdOut stdw $ who ++ " " ++ show id ++ " trece strada\n"
passIntersection :: Int -> MVar () -> IO ()
passIntersection id stdw = writeStdOut stdw $ "masina " ++ show id ++ " trece intersectia\n"

pietonHelper :: Group -> Int -> MVar () -> IO ()
pietonHelper group id stdw = helper1 group (crossStreet id stdw "pieton")

animalHelper :: Group -> Int -> MVar () -> IO ()
animalHelper group id stdw = helper1 group (crossStreet id stdw "animal")

masinaHelper :: Group -> Int -> MVar () -> IO ()
masinaHelper group id stdw = helper1 group (passIntersection id stdw)

pieton :: Group -> Int -> MVar () -> IO ThreadId
pieton group id stdw = (forkIO . forever) $ do
    pietonHelper group id stdw
    delay

animal :: Group -> Int -> MVar () -> IO ThreadId
animal group id stdw = (forkIO . forever) $ do
    animalHelper group id stdw
    delay

masina :: Group -> Int -> MVar () -> IO ThreadId
masina group id stdw = (forkIO . forever) $ do
    masinaHelper group id stdw
    delay

chooseGroup :: Group -> String -> STM (String, (Gate, Gate))
chooseGroup group task = do
    gates <- awaitGroup group
    return (task, gates)

pietonOrAnimal p_group a_group = do
    atomically $ orElse
        (chooseGroup p_group "pietoni trec")
        (chooseGroup a_group "animale trec")

semafor :: Group -> Group -> Group -> IO ()
semafor p_group a_group m_group = do undefined 
    -- nu stiu sa aleg intre 3 actiuni
    --putStrLn "-------"
    --(task, (in_gate, out_gate)) <- atomically $
        --orElse (chooseGroup p_group "pietoni trec")
        --(atomically $ orElse (chooseGroup a_group "animale trec")
        --(chooseGroup m_group "masini trec"))
    --putStrLn $ "Let's " ++ task
    --operateGate in_gate
    --operateGate out_gate

main = do
    stdw <- newMVar ()
    grupPietoni <- newGroup 5
    sequence_ [pieton grupPietoni n stdw | n <- [1..11]]

    grupAnimale <- newGroup 1
    sequence_ [animal grupAnimale n stdw | n <- [1..3]]

    grupMasini <- newGroup 10
    sequence_ [masina grupMasini n stdw | n <- [1..35]]

    forever $ semafor grupPietoni grupAnimale grupMasini
