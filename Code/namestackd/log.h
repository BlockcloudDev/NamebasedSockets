#ifndef __LOG_H_
#define __LOG_H_

#ifdef ANDROID

#include <android/log.h>
#include <stdio.h>

#define ANDROID_LOG_TAG "namestack daemon"
#define ANDROID_LOG(l, ...) __android_log_print((l), ANDROID_LOG_TAG, __VA_ARGS__)

#define LOGV(x, ...) ANDROID_LOG(ANDROID_LOG_VERBOSE, x, __VA_ARGS__)
#define LOGD(x, ...) ANDROID_LOG(ANDROID_LOG_DEBUG, x, __VA_ARGS__)
#define LOGI(x, ...) ANDROID_LOG(ANDROID_LOG_INFO, x, __VA_ARGS__)
#define LOGW(x, ...) ANDROID_LOG(ANDROID_LOG_WARN, x, __VA_ARGS__)
#define LOGE(x, ...) ANDROID_LOG(ANDROID_LOG_ERROR, x, __VA_ARGS__)

#else

#include <stdio.h>

#define LOGV(x, ...) fprintf(stdout, x, __VA_ARGS__)
#define LOGD(x, ...) fprintf(stdout, x, __VA_ARGS__)
#define LOGI(x, ...) fprintf(stdout, x, __VA_ARGS__)
#define LOGW(x, ...) fprintf(stderr, x, __VA_ARGS__)
#define LOGE(x, ...) fprintf(stderr, x, __VA_ARGS__)

#endif

#endif
