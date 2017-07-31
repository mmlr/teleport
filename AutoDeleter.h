#ifndef AUTO_DELETER_H
#define AUTO_DELETER_H

#include <stdlib.h>


template<class T>
class AutoDeleter {
public:
								AutoDeleter(T *object)
									:
									fObject(object)
								{
								}

								~AutoDeleter()
								{
									delete fObject;
								}

private:
		T *						fObject;
};


class AutoFreeer {
public:
								AutoFreeer(void *buffer)
									:
									fBuffer(buffer)
								{
								}

								~AutoFreeer()
								{
									free(fBuffer);
								}

private:
		void *					fBuffer;
};

#endif // AUTO_DELETER_H
