#ifndef __CORE_H_INCLUDED__
#define __CORE_H_INCLUDED__

// TODO: Remove this when releasing
//#define DEBUG

#ifdef DEBUG

#define dbg(...) fprintf(stderr, __VA_ARGS__)
#define err(...) \
{\
	fprintf(stderr, "%s:%d, %s error: ", __FILE__, __LINE__, __FUNCTION__);\
	fprintf(stderr, __VA_ARGS__);\
	fprintf(stderr, "\n");\
	fflush(stderr);\
}
#define cleanup_if(expr, ...) \
{\
	if(expr)\
	{\
		fprintf(stderr, "%s:%d, %s error: ", __FILE__, __LINE__, __FUNCTION__);\
		fprintf(stderr, __VA_ARGS__);\
		goto cleanup;\
	}\
}

#else

#define dbg(...)
#define err(...)
#define cleanup_if(expr, ...) \
{\
	if(expr)\
	{\
		goto cleanup;\
	}\
}

#endif // DEBUG

#endif // __CORE_H_INCLUDED__
