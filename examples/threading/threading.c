#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
// #define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

// Constant to convert miliseconds to microseconds
#define MS_TO_US 1000

void* threadfunc(void* thread_param)
{
    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure

    // Cast to obtain thread arguments from the parameter
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;

    // Sleep ms
    DEBUG_LOG("First wait...");
    usleep(thread_func_args->wait_to_obtain_ms * MS_TO_US);

    // Lock mutex
    DEBUG_LOG("Locking mutex...");
    pthread_mutex_lock(thread_func_args->mutex);

    // Second wait
    DEBUG_LOG("Second wait...");
    usleep(thread_func_args->wait_to_release_ms * MS_TO_US);

    // Unlock mutex
    DEBUG_LOG("Unlocking mutex...");
    pthread_mutex_unlock(thread_func_args->mutex);

    thread_func_args->thread_complete_success = true;

    pthread_exit(thread_param);

    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */

    // Allocate memory for threat data
    struct thread_data * thread_param = (struct thread_data*) malloc(sizeof(struct thread_data)); 
    thread_param->mutex = mutex;
    thread_param->wait_to_obtain_ms = wait_to_obtain_ms;
    thread_param->wait_to_release_ms = wait_to_release_ms;

    // Set up mutex
    pthread_attr_t pta;

    DEBUG_LOG("Initializing thread");

    int rc = pthread_attr_init(&pta);
    if (rc != 0)
    {
        ERROR_LOG(" Got code %d during thread attributes initilization", rc);
        return false;
    }

    DEBUG_LOG("Creating thread");
    rc = pthread_create(thread, &pta, threadfunc, (void *) thread_param);
    if (rc != 0)
    {
        ERROR_LOG(" Got code %d during thread creation", rc);
        return false;
    }

    return true;
}