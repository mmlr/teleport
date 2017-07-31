#ifndef AUTO_DELETER_H
#define AUTO_DELETER_H

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

#endif // AUTO_DELETER_H
