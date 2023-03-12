import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Scanner;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

class Main {

    public static void main(String args[]) {
        File f = new File("f.txt");
        try {
            in = new Scanner(System.in);
            fw = new FileWriter(f);
        } catch (IOException e) {System.out.println(e);}

        ReentrantReadWriteLock rwLock = new ReentrantReadWriteLock();
        readLock = rwLock.readLock();
        writeLock = rwLock.writeLock();

        Thread w1 = new Main().new Writer(); w1.start();
        Thread w2 = new Main().new Writer(); w2.start();
        Thread r1 = new Main().new Reader(f); r1.start();
        Thread r2 = new Main().new Reader(f); r2.start();
        Thread r3 = new Main().new Reader(f); r3.start();
        Thread r4 = new Main().new Reader(f); r4.start();
        Thread r5 = new Main().new Reader(f); r5.start();
    }

    class Writer extends Thread {
        public void run() {
            while (true) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {}
                writeLock.lock();
                String s = in.nextLine();
                System.out.println("am citit: " + s);
                try {
                    fw.write(s + "\n");
                    fw.flush();
                } catch (IOException e) {}
                writeLock.unlock();
            }
        }
    }

    class Reader extends Thread {
        Reader (File f) {
            br = null;
            try {
                br = new BufferedReader(new FileReader(f));
            } catch (FileNotFoundException e) {}
        }

        public void run() {
            String s;
            try {
                while (true) {
                    readLock.lock();
                    if ((s = br.readLine()) != null) {
                        System.out.println("Reader " + 
                                Thread.currentThread().getName() + 
                                " has read: " + s);
                        System.out.flush();
                    }
                    readLock.unlock();
                }
            } catch (IOException e) {}
        }
        private BufferedReader br;
    }

    private static Scanner in;
    private static FileWriter fw;
    private static Lock readLock;
    private static Lock writeLock;
}
