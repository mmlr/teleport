#ifndef THREAD_H
#define THREAD_H

#include "Common.h"

#include <pthread.h>
#include <signal.h>


template<class T, typename A = void *>
class Thread {
public:
		typedef void (T::*Method)(A);

								Thread(const char *name, Method method,
									T &object, A argument,
									bool interrupt = false,
									pthread_t interruptId = 0)
									:
									fName(name),
									fMethod(method),
									fObject(object),
									fArgument(argument),
									fInterrupt(interrupt),
									fInterruptId(interruptId)
								{
								}

		void					Run()
								{
									LOG_DEBUG("running thread %s\n", fName);
									pthread_create(&fThread, NULL, &_Entry,
										this);
								}

		void					Join()
								{
									LOG_DEBUG("joining thread %s\n", fName);
									void *dummy;
									pthread_join(fThread, &dummy);
									LOG_DEBUG("thread %s joined\n", fName);
								}

		void					Interrupt()
								{
									LOG_DEBUG("interrupting thread %s\n",
										fName);
									pthread_kill(fThread, SIGUSR1);
								}

private:
static	void *					_Entry(void *data)
								{
									Thread<T, A> *thread = (Thread<T, A> *)data;
									thread->_Run();
									return NULL;
								}

		void					_Run()
								{
									LOG_DEBUG("thread %s run\n", fName);

									(fObject.*fMethod)(fArgument);

									if (fInterrupt) {
										LOG_DEBUG("interrupting other\n");
										pthread_kill(fInterruptId, SIGUSR1);
									}

									LOG_DEBUG("thread %s exit\n", fName);
								}

		const char *			fName;
		Method					fMethod;
		T &						fObject;
		A						fArgument;
		bool					fInterrupt;
		pthread_t				fInterruptId;

		pthread_t				fThread;
};

#endif // THREAD_H
