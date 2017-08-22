/**
 * (c) Ripple
 * (c) https://github.com/samr7/vanitygen
 * (c) Bitcoin
 */

#include "stdafx.hpp"

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

EC_GROUP*       g_CurveGroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
BIGNUM*         g_CurveOrder = BN_new();
EC_POINT const* g_CurveGen = EC_GROUP_get0_generator(g_CurveGroup);

BIGNUM*  g_Base = BN_new();
BIGNUM*  g_Difficulty = BN_new();

BN_CTX*  g_Ctx = BN_CTX_new();
std::mutex  g_Lock;
std::mutex  g_RandLock;
std::atomic<std::uint64_t> g_Count;
std::atomic<bool>          g_FoundKey;
std::vector<sPrefix*>      g_Prefixes;
double g_Chance;

const std::string  g_RippleAlphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

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

void findkey( const size_t pThreadID ) {
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

            // Check for prefix matches
            for (auto& Range : g_Prefixes) {

                // Is the accound id within range?
                if (BN_cmp(Range->mRange1.mRangeLow, bnAccountID) <= 0) {
                    if (BN_cmp(Range->mRange1.mRangeHigh, bnAccountID) >= 0) {
                        
                        std::lock_guard<std::mutex> lock(g_Lock);

                        // Full AccountID
                        auto account = baseEncode(TOKEN_ACCOUNT_ID, &WorkBuffer[0], 21, Ctx);

                        auto t = std::time(nullptr);
                        auto tm = *std::localtime(&t);

                        std::cout << std::put_time(&tm, "[%Y-%m-%d %H:%M:%S] ");
                        std::cout << account << " => " << baseEncode(TOKEN_FAMILY_SEED, &SeedBuffer[0], 17, Ctx) << "\n";

                        g_FoundKey = true;
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

    auto start_time = std::chrono::high_resolution_clock::now();

    g_Chance = 0;

    // Base 58 Encoding
    BN_set_word(g_Base, 58);

    EC_GROUP_get_order(g_CurveGroup, g_CurveOrder, g_Ctx);
    EC_GROUP_precompute_mult(g_CurveGroup, g_Ctx);

    if(pArgc < 3) {
        std::cout << "usage:   '" << pArgv[0] << " <Threads> <Prefix> <Prefix>...'\n";
        std::cout << "\n" << pArgv[0] << " 4 rRob<\n\n";
        exit(1);
    }

    // Get Parameters
    int MaxThreads = atoi(pArgv[1]);

    // Some messages
    std::cout << "xrp-vanity\n";
    std::cout << "Search Threads: " << MaxThreads << "\n\n";

    for (int i = 2; i < pArgc; ++i) {
        std::string PrefixPattern(pArgv[i]);

        // Ensure prefix starts with 'r'
        if (PrefixPattern[0] != 'r')
            PrefixPattern.insert(PrefixPattern.begin(), 'r');

        // Calculate AccountID High/Low Range
        auto Prefix = get_prefix_ranges(0, &PrefixPattern[0], g_Ctx);
        if (!Prefix) {
            return 0;
        }

        g_Prefixes.push_back(Prefix);
    }

    calculate_range_difficulty();

    // Launch Threads
    workers.reserve(MaxThreads);

    for (int i = 0; i < MaxThreads; i++)
        workers.emplace_back(findkey, i);

    std::uint64_t TotalKeys = 0;

    size_t SinceLast = 0;

    // Keys per second count
    for( ;; ) {
        auto cycle_start_time = std::chrono::high_resolution_clock::now();

        Sleep(1000);

        if (g_FoundKey) {
            g_FoundKey = false;
            SinceLast = 0;
        }

        {
            std::lock_guard<std::mutex> lock(g_Lock);

            auto current_time = std::chrono::high_resolution_clock::now();
            auto elapsed_seconds = std::chrono::duration_cast<std::chrono::seconds>(current_time - cycle_start_time).count();

            //std::cout << "[" << g_Count / elapsed_seconds << "/s]\r" << std::flush;

            TotalKeys += g_Count;
            SinceLast += g_Count;
            vg_output_timing_console(SinceLast, g_Count, TotalKeys);
            g_Count = 0;
            
        }
    }

    return 1;
}
