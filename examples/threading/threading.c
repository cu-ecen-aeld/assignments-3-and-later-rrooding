#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{
    struct thread_data *thread_data = (struct thread_data *)thread_param;

    // TODO: wait,
    int ret = usleep(thread_data->wait_to_obtain_ms);
    if (ret == -1)
        ERROR_LOG("failed to sleep before obtaining mutex");

    // obtain mutex,
    pthread_mutex_lock(thread_data->mutex);
    
    // wait,
    usleep(thread_data->wait_to_release_ms);

    // release mutex as described by thread_data structure
    pthread_mutex_unlock(thread_data->mutex);


    // Set thread_complete_success to true after thread completes
    thread_data->thread_complete_success = true;
    
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    //struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     */

    struct thread_data* thread_data = (struct thread_data*) malloc(sizeof(struct thread_data));
    if (thread_data == NULL) {
        ERROR_LOG("Failed to allocate memory for thread_data");
        return false;
    }
    thread_data->wait_to_obtain_ms = wait_to_obtain_ms;
    thread_data->wait_to_release_ms = wait_to_release_ms;
    thread_data->thread_complete_success = false;
    thread_data->mutex = mutex;

    if (pthread_create(thread, NULL, threadfunc, (void *)thread_data) != 0) {
        ERROR_LOG("Failed to create thread");
        free(thread_data);
        return false;
    }

    /**
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */
    return true;
}

