#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <semaphore.h>

const int max_sim_threads = 2;

sem_t barrier;
int at_barrier = 0;
pthread_mutex_t barrier_mtx;

pthread_mutex_t mtx[2];

void * ThrFunc(void * p) {
    pthread_mutex_lock(&barrier_mtx);

	int * param = (int *) p;
	pthread_mutex_lock(&mtx[*param]);

    at_barrier += 1;
    int go = 0;
    if (at_barrier == 2) go = 1;
    pthread_mutex_unlock(&barrier_mtx);

    if (go) {
        for(int i = 1; i < max_sim_threads; ++i) {
            sem_post(&barrier);
        }
    } else {
        sem_wait(&barrier);
    }

	pthread_mutex_lock(&mtx[1-*param]);
	return 0;
}

int main() {
    sem_init(&barrier, 0, 0);


	pthread_t thr1;
	pthread_t thr2;
	int i1 = 0, i2 = 1;
	pthread_mutex_init(&mtx[0], NULL);
	pthread_mutex_init(&mtx[1], NULL);
    pthread_mutex_init(&barrier_mtx, NULL);

	pthread_create(&thr1, NULL, ThrFunc, &i1);
	pthread_create(&thr2, NULL, ThrFunc, &i2);

	pthread_join(thr1, NULL);
	pthread_join(thr2, NULL);
	pthread_mutex_destroy(&mtx[0]);
	pthread_mutex_destroy(&mtx[1]);
	return 0;
}
