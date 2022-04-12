#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

typedef struct data
{
    char **data_buffer;
    int size;
}data_t;
typedef struct queue
{
    unsigned int tail;     // current tail
    unsigned int head;     // current head
    unsigned int size;     // current number of items
    unsigned int capacity; // Capacity of queue
    data_t **data;          // Pointer to array of data
    pthread_mutex_t lock;
} queue_t;

queue_t *create_queue(unsigned int _capacity);
int queue_empty(queue_t *q);
int queue_full(queue_t *q);
int queue_enqueue(queue_t *q, data_t *item);
data_t *queue_dequeue(queue_t *q);
unsigned int queue_size(queue_t *q);
void free_queue(queue_t *q);