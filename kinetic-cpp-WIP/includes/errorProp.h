#ifndef ERROR_PROP_H_
#define ERROR_PROP_H_

#include <nan.h>

static v8::Local<v8::Value> ErrorWithProperty(const char *property,
                                              const char *message);

#endif
