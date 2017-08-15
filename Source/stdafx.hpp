#include <array>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <thread>
#include <iomanip>
#include <ctime>
#include <mutex>
#include <atomic>

#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ripemd.h>
#include <openssl/rand.h>


#pragma check_stack(off)
typedef struct bignum_st BIGNUM;
typedef struct ec_point_st EC_POINT;

extern EC_GROUP* g_CurveGroup;
extern BIGNUM* g_CurveOrder;

