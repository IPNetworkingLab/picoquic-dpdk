#include "circular_buffer.h"

// Create Global defenition of queue_t
typedef struct queue queue_t;

queue_t *create_queue(unsigned int _capacity)
{

    queue_t *myQueue = (queue_t *)malloc(sizeof(queue_t)); // allocate memory of size of queue struct
    if (myQueue == NULL)
    {
        return NULL; // if malloc was unsuccesful return NULL
    }
    else
    {
        // populate the variables of the queue :
        myQueue->tail = -1;
        myQueue->head = 0;
        myQueue->size = 0;
        myQueue->capacity = _capacity;
        myQueue->data = malloc(_capacity * sizeof(data_t)); // allocate memory for the array
        if (pthread_mutex_init(&(myQueue->lock), NULL) != 0)
        {
            printf("\n mutex init failed\n");
            return NULL;
        }
        return myQueue;
    }
}

int queue_empty(queue_t *q)
{
    pthread_mutex_lock(&(q->lock));
    if (q == NULL)
    {
        return -1;
    }
    else if (q->size == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int queue_full(queue_t *q)
{
    if (q == NULL)
    {
        return -1;
    }
    else if (q->size == q->capacity)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int queue_enqueue(queue_t *q, data_t *item)
{
    pthread_mutex_lock(&(q->lock));
    if (q == NULL)
    {
        pthread_mutex_unlock(&(q->lock));
        return -1;
    }
    else if (queue_full(q) == 1)
    {
        // removing last item
        q->tail = (q->tail + 1) % q->capacity;
        q->data[q->tail] = item;
        q->head += 1;
        pthread_mutex_unlock(&(q->lock));
        return 1;
    }
    else
    {
        q->tail = (q->tail + 1) % q->capacity;
        q->data[q->tail] = item;
        q->size++;
        pthread_mutex_unlock(&(q->lock));
        return 1;
    }
}

data_t *queue_dequeue(queue_t *q)
{

    pthread_mutex_lock(&(q->lock));
    if (q == NULL)
    {
        pthread_mutex_unlock(&(q->lock));
        return NULL;
    }
    else if (queue_empty(q) == 1)
    {
        pthread_mutex_unlock(&(q->lock));
        return NULL;
    }
    else
    {
        // firt capture the item
        int item = q->data[q->head];
        q->head = (q->head + 1) % q->capacity;
        // decrease size by 1
        q->size--;
        pthread_mutex_unlock(&(q->lock));
        return item;
    }
}

unsigned int queue_size(queue_t *q)
{
    if (q == NULL)
    {
        return -1;
    }
    else
    {
        return q->size;
    }
}

void free_queue(queue_t *q)
{
    // free the array
    free(q->data);
    // free queue
    free(q);
}