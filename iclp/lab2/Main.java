import java.util.Random;
import java.util.HashSet;
import java.util.ArrayList;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Main {
    public static void main(String[] args) {
        File d = new File("./test");

        int threadCnt = 3;
        Thread[] producerThreads = new Thread[threadCnt];
        Thread[] consumerThreads = new Thread[threadCnt];
        Producer p = new Main().new Producer(d);
        Consumer c = new Main().new Consumer();

        for (int i = 0; i < threadCnt; ++i) {
            producerThreads[i] = new Thread(p);
            consumerThreads[i] = new Thread(c);
            producerThreads[i].start();
            consumerThreads[i].start();
        }

        try {
            for (int i = 0; i < threadCnt; ++i) {
                producerThreads[i].join();
                consumerThreads[i].join();
            }
        } catch (InterruptedException e) {}
    }

    private class Producer implements Runnable {
        Producer (File dir) {
            this.directory = dir; 
            this.hs = new HashSet<String>();
        }

        private File directory;
        private HashSet<String> hs;

        public void run() {
            produce(this.directory);
        }

        private void produce(File d) {
            File[] files = d.listFiles();
            if (files == null) return;

            for (File file : files) {
                if (file.isDirectory()) {
                    continue;
                }

                synchronized (hs) {
                    System.out.print(Thread.currentThread().getName() + ": ");
                    if (hs.contains(file.getPath())) {
                        System.out.println(file.getPath() +
                                " already added");
                        continue;
                    } else {
                        System.out.println(file.getPath() +
                                " added now");
                        hs.add(file.getPath());
                    }
                }

                if (file.getName().endsWith(".txt")) {
                    synchronized (buff) {
                        buff.add(file.getName());
                        buff.notifyAll();
                    }
                }
            }

            for (File file : files) {
                if (file.isDirectory()) {
                    produce(file);
                } 
            }
        }
    }

    private class Consumer implements Runnable {

        private static AiModule a = new Main().new AiModule();

        public void run() {
            String fileName;

            while (true) {
                synchronized (buff) {
                    if (buff.size() == 0) {
                        try {
                            buff.wait(500);
                            if (buff.size() == 0) {
                                return;
                            }
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }

                    System.out.println(Thread.currentThread().getName() + ": found file, buff.size() = " + buff.size());
                    fileName = buff.remove(buff.size() - 1);
                }

                System.out.println(Thread.currentThread().getName() +
                        ":     " + fileName + " " +
                        a.predict(a.inputTransform(fileName)));
            }
        }
    }

    private class AiModule {
        AiModule() {
            this.r = new Random();
            this.r.setSeed(27);
        }

        private final Random r;

        long inputTransform(String filePath) {
            Path p = Paths.get(filePath);
            long s = 0;
            try {
                s = Files.size(p);
            } catch (IOException e) {}

            return s;
        }

        String predict(long whatever) {
            try {
                Thread.sleep(50); // load ?
                if (r.nextInt() % 2 == 0) {
                    return "Bad";
                } else {
                    return "Good";
                }
            } catch (InterruptedException e) {}
            return "";
        }
    }

    private static ArrayList<String> buff = new ArrayList<String>();
}
