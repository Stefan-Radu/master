import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Scanner;
import java.util.concurrent.*;

class Main2 {

    public static void main(String args[]) {
        File f = new File("f.txt");
        try {
            in = new Scanner(System.in);
            fw = new FileWriter(f);
        } catch (IOException e) {System.out.println(e);}

        Semaphore mtx = new Semaphore(1);
        Semaphore wrt = new Semaphore(1);

        cnt = 0;

        Thread w1 = new Main2().new Writer(wrt); w1.start();
        Thread w2 = new Main2().new Writer(wrt); w2.start();
        Thread r1 = new Main2().new Reader(f, mtx, wrt); r1.start();
        Thread r2 = new Main2().new Reader(f, mtx, wrt); r2.start();
        Thread r3 = new Main2().new Reader(f, mtx, wrt); r3.start();
        Thread r4 = new Main2().new Reader(f, mtx, wrt); r4.start();
        Thread r5 = new Main2().new Reader(f, mtx, wrt); r5.start();
    }

    class Writer extends Thread {
        Writer (Semaphore wrt) {
            this.wrt = wrt;
        }

        public void run() {
            String s;
            while (true) {
                try {
                    wrt.acquire();
                    s = in.nextLine();
                    System.out.println("am citit: " + s);
                    try {
                        fw.write(s + "\n");
                        fw.flush();
                    } catch (IOException e) {
                        System.err.println("4");
                    }
                    wrt.release();
                    Thread.sleep(10);
                } catch (InterruptedException e) {}
            }
        }

        private Semaphore wrt;
    }

    class Reader extends Thread {
        Reader (File f, Semaphore mtx, Semaphore wrt) {
            this.mutex = mtx;
            this.wrt = wrt;
            br = null;
            try {
                br = new BufferedReader(new FileReader(f));
            } catch (FileNotFoundException e) {}
        }

        public void run() {
            String s;
            try {
                while (true) {
                    try {
                        mutex.acquire();
                        cnt++;
                        if (cnt == 1) {
                            wrt.acquire();
                        }
                        mutex.release();

                        while ((s = br.readLine()) != null) {
                            System.out.println("Reader " + 
                                    Thread.currentThread().getName() + 
                                    " has read: " + s);
                            System.out.flush();
                        }

                        mutex.acquire();
                        cnt--;
                        if (cnt == 0) {
                            wrt.release();
                        }
                        mutex.release();

                        // adaugat pt ca altfel cititorii fura lock-ul instant
                        Thread.sleep(10);
                    } catch (InterruptedException e) { }
                }
            } catch (IOException e) { }
        }

        private BufferedReader br;
        private Semaphore mutex, wrt;
    }

    private static int cnt = 0;
    private static Scanner in;
    private static FileWriter fw;
}
