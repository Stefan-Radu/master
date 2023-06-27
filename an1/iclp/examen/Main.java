import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

// fibonacci

//public class Main {
    //public static void main(String args[]) {
        //int n = 10;

        //fib = new int[n];
        //for (int i = 0; i < n; ++i) {
            //fib[i] = -1;
        //}
        //fib[0] = 0;
        //fib[1] = 1;

        //ExecutorService pool = Executors.newCachedThreadPool();
        //for (int i = 0; i < n; ++i) {
            //pool.execute(new Main().new Fib(i));
        //}
        //pool.shutdown();

        //for (int i = 0; i < n; ++i) {
            //System.out.println(fib[i]);
        //}
    //}

    //class Fib implements Runnable {
        //Fib(int i) {
            //index = i;
        //}

        //public void run() {
            //if (index == 0) {
                //synchronized(fib) {
                    //fib[index] = 0;
                //}
                //return;
            //}
            //if (index == 1) {
                //synchronized(fib) {
                   //fib[index] = 1;
                //}
                //return;
            //}

            //while (true) {
                //int a, b;
                //synchronized(fib) {
                    //a = fib[index - 2];
                    //b = fib[index - 1];
                //}

                //if (a != -1 && b != -1) {
                    //fib[index] = a + b;
                    //return;
                //}
            //}
        //}

        //private int index;
    //}

    //private static int[] fib;
//}

// read write

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

        //Thread w1 = new Main().new Writer(); w1.start();
        //Thread w2 = new Main().new Writer(); w2.start();
        //Thread r1 = new Main().new Reader(f); r1.start();
        //Thread r2 = new Main().new Reader(f); r2.start();
        //Thread r3 = new Main().new Reader(f); r3.start();
        //Thread r4 = new Main().new Reader(f); r4.start();
        //Thread r5 = new Main().new Reader(f); r5.start();
    }

    class Writer implements Runnable {
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

    class Reader implements Runnable {
        Reader (File f, int n, int m) {
            //br = null;
            this.n = n;
            this.m = m;
            //try {
                //br = new BufferedReader(new FileReader(f));
            //} catch (FileNotFoundException e) {}
        }

        String readBetween() {
            String res = "";
            for (int i = n; i < m; ++i) {
                //res += db[i];
                res += "linia " + i;
            }
            return res;
        }

        public void run() {
            String s;
            while (true) {
                readLock.lock();
                //if ((s = br.readLine()) != null) {
                s = readBetween();
                System.out.println("Reader " + 
                        Thread.currentThread().getName() + 
                        " has read: " + s);
                System.out.flush();
                readLock.unlock();
            }
        }
        //private BufferedReader br;
        private int n, m;
    }

    private static Scanner in;
    private static FileWriter fw;
    private static Lock readLock;
    private static Lock writeLock;
}
