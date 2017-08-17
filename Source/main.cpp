/**
 * (c) Ripple
 * (c) https://github.com/samr7/vanitygen
 * (c) Bitcoin
 */

#include "stdafx.hpp"

#include <stdio.h>
#include <cstring>

#ifdef _MSC_VER
    FILE _iob[] = { *stdin, *stdout, *stderr };
    extern "C" FILE * __cdecl __iob_func(void) {
        return _iob;
    }
    #include <windows.h>
#else
    #include <unistd.h>
    #define Sleep(x) sleep(x / 1000);
#endif

const unsigned int TOKEN_ACCOUNT_ID = 0;
const unsigned int TOKEN_FAMILY_SEED = 33;
const std::string  g_RippleAlphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

EC_GROUP*       g_CurveGroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
BIGNUM*         g_CurveOrder = BN_new();
EC_POINT const* g_CurveGen = EC_GROUP_get0_generator(g_CurveGroup);

BIGNUM*  g_Base = BN_new();
std::mutex  g_Lock;
std::mutex  g_RandLock;
std::atomic<std::uint64_t> g_Count;
BIGNUM* g_PrefixRanges[4] = { 0 };

signed char b58_reverse_map[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 50, 33, 7, 21, 41, 40, 27, 45, 8, -1, -1, -1, -1, -1, -1,
    -1, 54, 10, 38, 12, 14, 47, 15, 16, -1, 17, 18, 19, 20, 13, -1,
    22, 23, 24, 25, 26, 11, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
    -1, 5, 34, 35, 36, 37, 6, 39, 3, 49, 42, 43, -1, 44, 4, 46,
    1, 48, 0, 2, 51, 52, 53, 9, 55, 56, 57, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

/*
* Find the bignum ranges that produce a given prefix.
*/
static int
get_prefix_ranges(int addrtype, const char *pfx, BIGNUM **result,
    BN_CTX *bnctx)
{
    int i, p, c;
    int zero_prefix = 0;
    int check_upper = 0;
    int b58pow, b58ceil, b58top = 0;
    int ret = -1;

    BIGNUM *bntarg, *bnceil, *bnfloor;
    BIGNUM *bnap, *bnbp, *bntp;
    BIGNUM *bnhigh = NULL, *bnlow = NULL, *bnhigh2 = NULL, *bnlow2 = NULL;
    BIGNUM *bntmp, *bntmp2;

    bntarg = BN_new();
    bnceil = BN_new();
    bnfloor = BN_new();
    bntmp = BN_new();
    bntmp2 = BN_new();

    p = strlen(pfx);

    for (i = 0; i < p; i++) {
        c = b58_reverse_map[(int)pfx[i]];
        if (c == -1) {
            fprintf(stderr,
                "Invalid character '%c' in prefix '%s'\n",
                pfx[i], pfx);
            goto out;
        }
        if (i == zero_prefix) {
            if (c == 0) {
                /* Add another zero prefix */
                zero_prefix++;
                if (zero_prefix > 19) {
                    fprintf(stderr,
                        "Prefix '%s' is too long\n",
                        pfx);
                    goto out;
                }
                continue;
            }

            /* First non-zero character */
            b58top = c;
            BN_set_word(bntarg, c);

        }
        else {
            BN_set_word(bntmp2, c);
            BN_mul(bntmp, bntarg, g_Base, bnctx);
            BN_add(bntarg, bntmp, bntmp2);
        }
    }

    /* Power-of-two ceiling and floor values based on leading 1s */
    BN_clear(bntmp);
    BN_set_bit(bntmp, 200 - (zero_prefix * 8));
    BN_sub(bnceil, bntmp, BN_value_one());
    BN_set_bit(bnfloor, 192 - (zero_prefix * 8));

    bnlow = BN_new();
    bnhigh = BN_new();

    if (b58top) {
        /*
        * If a non-zero was given in the prefix, find the
        * numeric boundaries of the prefix.
        */

        BN_copy(bntmp, bnceil);
        bnap = bntmp;
        bnbp = bntmp2;
        b58pow = 0;
        while (BN_cmp(bnap, g_Base) > 0) {
            b58pow++;
            BN_div(bnbp, NULL, bnap, g_Base, bnctx);
            bntp = bnap;
            bnap = bnbp;
            bnbp = bntp;
        }
        b58ceil = (int) BN_get_word(bnap);

        if ((b58pow - (p - zero_prefix)) < 6) {
            /*
            * Do not allow the prefix to constrain the
            * check value, this is ridiculous.
            */
            fprintf(stderr, "Prefix '%s' is too long\n", pfx);
            goto out;
        }

        BN_set_word(bntmp2, b58pow - (p - zero_prefix));
        BN_exp(bntmp, g_Base, bntmp2, bnctx);
        BN_mul(bnlow, bntmp, bntarg, bnctx);
        BN_sub(bntmp2, bntmp, BN_value_one());
        BN_add(bnhigh, bnlow, bntmp2);

        if (b58top <= b58ceil) {
            /* Fill out the upper range too */
            check_upper = 1;
            bnlow2 = BN_new();
            bnhigh2 = BN_new();

            BN_mul(bnlow2, bnlow, g_Base, bnctx);
            BN_mul(bntmp2, bnhigh, g_Base, bnctx);
            BN_set_word(bntmp, 57);
            BN_add(bnhigh2, bntmp2, bntmp);

            /*
            * Addresses above the ceiling will have one
            * fewer "1" prefix in front than we require.
            */
            if (BN_cmp(bnceil, bnlow2) < 0) {
                /* High prefix is above the ceiling */
                check_upper = 0;
                BN_free(bnhigh2);
                bnhigh2 = NULL;
                BN_free(bnlow2);
                bnlow2 = NULL;
            }
            else if (BN_cmp(bnceil, bnhigh2) < 0)
                /* High prefix is partly above the ceiling */
                BN_copy(bnhigh2, bnceil);

            /*
            * Addresses below the floor will have another
            * "1" prefix in front instead of our target.
            */
            if (BN_cmp(bnfloor, bnhigh) >= 0) {

                check_upper = 0;
                BN_free(bnhigh);
                bnhigh = bnhigh2;
                bnhigh2 = NULL;
                BN_free(bnlow);
                bnlow = bnlow2;
                bnlow2 = NULL;
            }
            else if (BN_cmp(bnfloor, bnlow) > 0) {
                /* Low prefix is partly below the floor */
                BN_copy(bnlow, bnfloor);
            }
        }

    }
    else {
        BN_copy(bnhigh, bnceil);
        BN_clear(bnlow);
    }

    /* Limit the prefix to the address type */
    BN_clear(bntmp);
    BN_set_word(bntmp, addrtype);
    BN_lshift(bntmp2, bntmp, 192);

    if (check_upper) {
        if (BN_cmp(bntmp2, bnhigh2) > 0) {
            check_upper = 0;
            BN_free(bnhigh2);
            bnhigh2 = NULL;
            BN_free(bnlow2);
            bnlow2 = NULL;
        }
        else if (BN_cmp(bntmp2, bnlow2) > 0)
            BN_copy(bnlow2, bntmp2);
    }

    if (BN_cmp(bntmp2, bnhigh) > 0) {
        if (!check_upper)
            goto not_possible;
        check_upper = 0;
        BN_free(bnhigh);
        bnhigh = bnhigh2;
        bnhigh2 = NULL;
        BN_free(bnlow);
        bnlow = bnlow2;
        bnlow2 = NULL;
    }
    else if (BN_cmp(bntmp2, bnlow) > 0) {
        BN_copy(bnlow, bntmp2);
    }

    BN_set_word(bntmp, addrtype + 1);
    BN_lshift(bntmp2, bntmp, 192);

    if (check_upper) {
        if (BN_cmp(bntmp2, bnlow2) < 0) {
            check_upper = 0;
            BN_free(bnhigh2);
            bnhigh2 = NULL;
            BN_free(bnlow2);
            bnlow2 = NULL;
        }
        else if (BN_cmp(bntmp2, bnhigh2) < 0)
            BN_copy(bnlow2, bntmp2);
    }

    if (BN_cmp(bntmp2, bnlow) < 0) {
        if (!check_upper)
            goto not_possible;
        check_upper = 0;
        BN_free(bnhigh);
        bnhigh = bnhigh2;
        bnhigh2 = NULL;
        BN_free(bnlow);
        bnlow = bnlow2;
        bnlow2 = NULL;
    }
    else if (BN_cmp(bntmp2, bnhigh) < 0) {
        BN_copy(bnhigh, bntmp2);
    }

    /* Address ranges are complete */
    //assert(check_upper || ((bnlow2 == NULL) && (bnhigh2 == NULL)));
    result[0] = bnlow;
    result[1] = bnhigh;
    result[2] = bnlow2;
    result[3] = bnhigh2;
    bnlow = NULL;
    bnhigh = NULL;
    bnlow2 = NULL;
    bnhigh2 = NULL;
    ret = 0;

    if (0) {
    not_possible:
        ret = -2;
    }

out:
    BN_free(bntarg);
    BN_free(bnceil);
    BN_free(bnfloor);
    BN_free(bntmp);
    BN_free(bntmp2);

    if (bnhigh)
        BN_free(bnhigh);
    if (bnlow)
        BN_free(bnlow);
    if (bnhigh2)
        BN_free(bnhigh2);
    if (bnlow2)
        BN_free(bnlow2);

    return ret;
}

std::string baseEncode(std::uint8_t pType, unsigned char* pData, std::size_t pDataSize, BN_CTX* pCtx) {
    std::array<std::uint8_t, 32> Hash;
    std::array<std::uint8_t, 40> Address;

    int zpfx, d;
    BIGNUM *bn, *bndiv, *bnrem, *bnptmp;
    size_t p;

    pData[0] = pType;

    // Hash the hash
    SHA256(pData, pDataSize, &Hash[0]);
    SHA256(&Hash[0], Hash.size(), &Hash[0]);

    // Write Check code
    std::memcpy(&pData[pDataSize], &Hash[0], 4);

    bn = BN_new();
    bndiv = BN_new();
    bnrem = BN_new();

    BN_bin2bn(pData, pDataSize + 4, bn);

    /* Compute the complete encoded address */
    for (zpfx = 0; zpfx < pDataSize + 4 && pData[zpfx] == 0; zpfx++);

    p = Address.size();
    while (!BN_is_zero(bn)) {
        BN_div(bndiv, bnrem, bn, g_Base, pCtx);
        bnptmp = bn;
        bn = bndiv;
        bndiv = bnptmp;
        d = (int) BN_get_word(bnrem);
        Address[--p] = g_RippleAlphabet[d];
    }
    while (zpfx--) {
        Address[--p] = g_RippleAlphabet[0];
    }

    BN_free(bn);
    BN_free(bndiv);
    BN_free(bnrem);

    return std::string(Address.begin() + p, Address.end());
}

void writeBE(uint8_t *pBuffer, std::uint32_t pValue) {

    *pBuffer++ = (pValue >> 24) & 0xFF;
    *pBuffer++ = (pValue >> 16) & 0xFF;
    *pBuffer++ = (pValue >> 8) & 0xFF;
    *pBuffer = (pValue >> 0) & 0xFF;
}

void findkey( const std::string& pFindPrefix, const size_t pThreadID ) {
    std::array<std::uint8_t, 64> WorkBuffer;
    std::array<std::uint8_t, 64> WorkBufferPub;
    std::array<std::uint8_t, 21> SeedBuffer = { 0 };

    BN_CTX* Ctx = BN_CTX_new();

    bignum_st* bnPrivateKey = BN_new();
    bignum_st* bnAccountID = BN_new();
    bignum_st* bnHash = BN_new();

    EC_POINT* ptRoot = EC_POINT_new(g_CurveGroup);
    EC_POINT* ptPublic = EC_POINT_new(g_CurveGroup);

    std::uint32_t seq, subSeq;

    for(;;) {
        seq = 0;
        subSeq = 0;

        {
            std::lock_guard<std::mutex> Lock(g_RandLock);

            // Get some randoms
            if (!RAND_bytes(&SeedBuffer[1], 16)) {
                std::cout << "RAND_bytes failure\n";
                exit(1);
            }
        }

        // generateRootDeterministicKey
        do {
            writeBE(&SeedBuffer[17], seq++);

            // SHA512-Half
            SHA512(&SeedBuffer[1], 20, &WorkBuffer[0]);
            BN_bin2bn(WorkBuffer.data(), 32, bnPrivateKey);

            // Valid Key?
        } while (BN_is_zero(bnPrivateKey) || BN_cmp(bnPrivateKey, g_CurveOrder) >= 0);

        // generateRootDeterministicPublicKey
        {
            // ptRoot = generator * bnPrivateKey
            //gpu_Mul(ptRoot, bnPrivateKey, g_CurveGen, Ctx);
            EC_POINT_mul(g_CurveGroup, ptRoot, bnPrivateKey, nullptr, nullptr, Ctx);
            EC_POINT_point2oct(g_CurveGroup, ptRoot,
                POINT_CONVERSION_COMPRESSED, &WorkBuffer[0], 33, Ctx);
        }

        // generatePublicDeterministicKey
        {
            writeBE(&WorkBuffer[33], 0);
            do
            {
                writeBE(&WorkBuffer[37], subSeq++);

                SHA512(&WorkBuffer[0], 41, &WorkBufferPub[0]);
                BN_bin2bn(&WorkBufferPub[0], 32, bnHash);

            } while (BN_is_zero(bnHash) || BN_cmp(bnHash, g_CurveOrder) >= 0);

            // ptPublic = (generator * bnHash) + ptRoot
            //gpu_Mul(ptPublic, bnHash, g_CurveGen, Ctx);
            EC_POINT_mul(g_CurveGroup, ptPublic, bnHash, nullptr, nullptr, Ctx);
            EC_POINT_add(g_CurveGroup, ptPublic, ptRoot, ptPublic, Ctx);
            EC_POINT_point2oct(g_CurveGroup, ptPublic, 
                POINT_CONVERSION_COMPRESSED, &WorkBuffer[0], 33, Ctx);
        }

        // Account ID
        {
            SHA256(&WorkBuffer[0], 33, &WorkBuffer[0]);
            RIPEMD160(&WorkBuffer[0], 32, &WorkBuffer[1]);

            WorkBuffer[0] = TOKEN_ACCOUNT_ID;
            BN_bin2bn(&WorkBuffer[0], 25, bnAccountID);

            // Is the accound id within range?
            if (BN_cmp(g_PrefixRanges[0], bnAccountID) <= 0) {
                if (BN_cmp(g_PrefixRanges[1], bnAccountID) >= 0) {

                    // Full AccountID
                    auto account = baseEncode(TOKEN_ACCOUNT_ID, &WorkBuffer[0], 21, Ctx);
                    {
                        std::lock_guard<std::mutex> lock(g_Lock);

                        auto t = std::time(nullptr);
                        auto tm = *std::localtime(&t);
                        std::cout << std::put_time(&tm, "[%Y-%m-%d %H:%M:%S] ");

                        std::cout << account << " => " << baseEncode(TOKEN_FAMILY_SEED, &SeedBuffer[0], 17, Ctx) << "\n";
                    }
                }
            }
        }

        ++g_Count;
    }

    BN_free(bnHash);
    BN_free(bnPrivateKey);
    EC_POINT_free(ptRoot);
    EC_POINT_free(ptPublic);
}

int main(int pArgc, char *pArgv[]) {
    std::vector<std::thread> workers;
    BN_CTX* Ctx = BN_CTX_new();

    // Base 58 Encoding
    BN_set_word(g_Base, 58);

    EC_GROUP_get_order(g_CurveGroup, g_CurveOrder, Ctx);
    EC_GROUP_precompute_mult(g_CurveGroup, Ctx);

    if(pArgc != 3) {
        std::cout << "usage:   '" << pArgv[0] << " <Threads> <Prefix>'\n";
        std::cout << "\n" << pArgv[0] << " 4 rRob\n\n";
        exit(1);
    }

    // Get Parameters
    std::string PrefixPattern(pArgv[2]);
    int MaxThreads = atoi(pArgv[1]);

    // Ensure prefix starts with 'r'
    if(PrefixPattern[0] != 'r')
        PrefixPattern.insert(PrefixPattern.begin(), 'r');

    // Calculate AccountID High/Low Range
    get_prefix_ranges(0, &PrefixPattern[0], g_PrefixRanges, Ctx);

    // Ensure valid prefix pattern
    for (auto ch : PrefixPattern) {

        if (g_RippleAlphabet.find(ch, 0) == std::string::npos) {
            std::cout << "Impossible pattern; Character: '" << ch << "'\n";
            exit(1);
        }
    }

    std::cout << "xrp-vanity\n";
    std::cout << "Searching Prefix: " << PrefixPattern << " - Threads: " << MaxThreads << "\n\n";

    workers.reserve(MaxThreads);

    // Launch Threads
    for (int i = 0; i < MaxThreads; i++) {
        workers.emplace_back(findkey, PrefixPattern, i);
    }

    // Keys per second count
    for( ;; ) {
        auto start_time = std::chrono::high_resolution_clock::now();

        Sleep(1000);

        {
            std::lock_guard<std::mutex> lock(g_Lock);

            auto current_time = std::chrono::high_resolution_clock::now();
            auto elapsed_seconds = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time).count();

            std::cout << "[" << g_Count / elapsed_seconds << "/s]\r" << std::flush;
            g_Count = 0;
        }
    };

    return 1;
}
