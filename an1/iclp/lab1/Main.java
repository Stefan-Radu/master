import java.util.Scanner;

//public class Main {
    //public static void main(String[] args) {
        //Whatever obj = new Main().new Whatever();
        //Thread thread = new Thread(obj);
        //thread.start();
    //}

    //private class Whatever implements Runnable {
        //public void run() {
            //System.out.println(Thread.currentThread().getName());
            //System.out.println("ceva");
            //try {
                //Thread.sleep(3000);
            //} catch (InterruptedException e) {

            //}
        //}
    //}
//}

public class Main {
    public static void main(String[] args) {
        Scanner s = new Scanner(System.in);
        int n = s.nextInt();

        contor = 0;
        Whatever obj = new Main().new Whatever(n);
        Thread thread = new Thread(obj);
        thread.start();

        for (int i = 0; i < n; ++i) {
            contor--;
        }

        try {
            thread.join();
            System.out.println("la final: " + contor);
        } catch (InterruptedException e) { }
        s.close();
    }

    private class Whatever implements Runnable {
        Whatever(int n) {
            this.n = n;
        }

        public void run() {
            int aux = contor;
            for (int i = 0; i < n; i++) {
                contor++;
                System.out.println(Thread.currentThread().getName());
                System.out.println("Inainte: " + aux + 
                        "\nDupa: " + contor);
            }
        }

        private int n;
    }

    public static int contor;
}
