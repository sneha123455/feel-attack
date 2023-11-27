#include <iostream>
#include <ctime>
#include <cstdlib>
#include <iomanip>

#define MAX_CHOSEN_PAIRS 10000

typedef unsigned long long ull;
typedef unsigned uint;
typedef unsigned char byt;

int num_plaintexts;
uint key[6];

ull plaintext0[MAX_CHOSEN_PAIRS];
ull ciphertext0[MAX_CHOSEN_PAIRS];
ull plaintext1[MAX_CHOSEN_PAIRS];
ull ciphertext1[MAX_CHOSEN_PAIRS];

inline uint getLeftHalf(ull x) {
    return static_cast<uint>(x >> 32);
}

inline uint getRightHalf(ull x) {
    return static_cast<uint>(x & 0xFFFFFFFFULL);
}

inline ull getCombinedHalves(uint a, uint b) {
    return (static_cast<ull>(a) << 32) | (static_cast<ull>(b) & 0xFFFFFFFFULL);
}

void createRandomKeys() {
    std::srand(static_cast<unsigned>(std::time(nullptr)));

    for (int i = 0; i < 6; ++i)
        key[i] = (std::rand() << 16) | (std::rand() & 0xFFFFU);
}

byt g(byt a, byt b, byt x) {
    byt tmp = a + b + x;
    return (tmp << 2) | (tmp >> 6);
}

uint f(uint input) {
    byt x[4], y[4];
    for (int i = 0; i < 4; ++i) {
        x[3 - i] = static_cast<byt>(input & 0xFF);
        input >>= 8;
    }

    y[1] = g(x[0] ^ x[1], x[2] ^ x[3], 1);
    y[0] = g(x[0], y[1], 0);
    y[2] = g(x[2] ^ x[3], y[1], 0);
    y[3] = g(x[3], y[2], 1);

    uint output = 0;
    for (int i = 0; i < 4; ++i)
        output += (static_cast<uint>(y[i]) << (8 * (3 - i)));

    return output;
}

ull encrypt(ull plaintext) {
    uint initialLeft = getLeftHalf(plaintext) ^ key[4];
    uint initialRight = getRightHalf(plaintext) ^ key[5];

    uint round1Left = initialLeft ^ initialRight;
    uint round1Right = initialLeft ^ f(round1Left ^ key[0]);

    uint round2Left = round1Right;
    uint round2Right = round1Left ^ f(round1Right ^ key[1]);

    uint round3Left = round2Right;
    uint round3Right = round2Left ^ f(round2Right ^ key[2]);

    uint round4Left = round3Left ^ f(round3Right ^ key[3]);
    uint round4Right = round4Left ^ round3Right;

    return getCombinedHalves(round4Left, round4Right);
}

void generatePlaintextCiphertextPairs(ull inputDiff) {
    std::cout << "Generating " << num_plaintexts << " plaintext-ciphertext pairs\n";
    std::cout << "Using input Linear 0x" << std::hex << inputDiff << std::dec << "\n";

    std::srand(static_cast<unsigned>(std::time(nullptr)));

    for (int i = 0; i < num_plaintexts; ++i) {
        plaintext0[i] = (static_cast<ull>(std::rand() & 0xFFFFULL) << 48) |
                        (static_cast<ull>(std::rand() & 0xFFFFULL) << 32) |
                        (static_cast<ull>(std::rand() & 0xFFFFULL) << 16) |
                        (std::rand() & 0xFFFFULL);

        ciphertext0[i] = encrypt(plaintext0[i]);
        plaintext1[i] = plaintext0[i] ^ inputDiff;
        ciphertext1[i] = encrypt(plaintext1[i]);
    }
}

void decryptLastOperation() {
    for (int i = 0; i < num_plaintexts; ++i) {
        uint cipherLeft0 = getLeftHalf(ciphertext0[i]);
        uint cipherRight0 = getRightHalf(ciphertext0[i]) ^ cipherLeft0;
        uint cipherLeft1 = getLeftHalf(ciphertext1[i]);
        uint cipherRight1 = getRightHalf(ciphertext1[i]) ^ cipherLeft1;

        ciphertext0[i] = getCombinedHalves(cipherLeft0, cipherRight0);
        ciphertext1[i] = getCombinedHalves(cipherLeft1, cipherRight1);
    }
}

uint crackHighestRound(uint differential) {
    std::cout << "  Using output Linear of 0x" << std::hex << differential << std::dec << "\n";
    std::cout << "  Processing...\n";

    for (uint tmpKey = 0x00000000U; tmpKey <= 0xFFFFFFFFU; ++tmpKey) {
        int score = 0;

        for (int i = 0; i < num_plaintexts; ++i) {
            uint cipherRight0 = getRightHalf(ciphertext0[i]);
            uint cipherLeft0 = getLeftHalf(ciphertext0[i]);
            uint cipherRight1 = getRightHalf(ciphertext1[i]);
            uint cipherLeft1 = getLeftHalf(ciphertext1[i]);

            uint cipherLeft = cipherLeft0 ^ cipherLeft1;
            uint fOutDiffActual = cipherLeft ^ differential;

            uint fInput0 = cipherRight0 ^ tmpKey;
            uint fInput1 = cipherRight1 ^ tmpKey;
            uint fOut0 = f(fInput0);
            uint fOut1 = f(fInput1);
            uint fOutDiffComputed = fOut0 ^ fOut1;

            if (fOutDiffActual == fOutDiffComputed)
                ++score;
            else
                break;
        }

        if (score == num_plaintexts) {
            std::cout << "found key : 0x" << std::hex << tmpKey << std::dec << "\n";
            std::cout << std::flush;
            return tmpKey;
        }
    }

    std::cout << "failed\n";
    return 0;
}

void decryptHighestRound(uint crackedKey) {
    for (int i = 0; i < num_plaintexts; ++i) {
        uint cipherLeft0 = getRightHalf(ciphertext0[i]);
        uint cipherLeft1 = getRightHalf(ciphertext1[i]);

        uint cipherRight0 = f(cipherLeft0 ^ crackedKey) ^ getLeftHalf(ciphertext0[i]);
        uint cipherRight1 = f(cipherLeft1 ^ crackedKey) ^ getLeftHalf(ciphertext1[i]);

        ciphertext0[i] = getCombinedHalves(cipherLeft0, cipherRight0);
        ciphertext1[i] = getCombinedHalves(cipherLeft1, cipherRight1);
    }
}

int main(int argc, char **argv) {
    std::cout << "Linear Cryptanalysis of FEAL-4\n\n\n";

    if (argc == 1)
        num_plaintexts = 12;
    else if (argc == 2)
        num_plaintexts = std::atoi(argv[1]);
    else {
        std::cout << "Usage: " << argv[0] << " [Number of chosen plaintexts]\n";
        return 0;
    }

    createRandomKeys();
    uint startTime = static_cast<uint>(std::time(nullptr));

    // Round 4
    std::cout << "Round 4: To find K3\n\n";
    generatePlaintextCiphertextPairs(0x8080000080800000ULL);
    decryptLastOperation();

    uint roundStartTime = static_cast<uint>(std::time(nullptr));
    uint crackedKey3 = crackHighestRound(0x02000000U);
    uint roundEndTime = static_cast<uint>(std::time(nullptr));
    std::cout << "  Time to crack round #4 = " << int(roundEndTime - roundStartTime) << " seconds\n\n";

    // Round 3
    std::cout << "Round 3: To find K2\n";
    generatePlaintextCiphertextPairs(0x0000000080800000ULL);
    decryptLastOperation();
    decryptHighestRound(crackedKey3);

    roundStartTime = static_cast<uint>(std::time(nullptr));
    uint crackedKey2 = crackHighestRound(0x02000000U);
    roundEndTime = static_cast<uint>(std::time(nullptr));
    std::cout << "  Time to crack round #3 = " << int(roundEndTime - roundStartTime) << " seconds\n\n";

    // Round 2
    std::cout << "Round 2: To find K1\n";
    generatePlaintextCiphertextPairs(0x207f5bc585764709);
    decryptLastOperation();
    decryptHighestRound(crackedKey3);
    decryptHighestRound(crackedKey2);

    roundStartTime = static_cast<uint>(std::time(nullptr));
    uint crackedKey1 = crackHighestRound(0x02000000U);
    roundEndTime = static_cast<uint>(std::time(nullptr));
    std::cout << "  Time to crack round #2 = " << int(roundEndTime - roundStartTime) << " seconds\n\n";

    // Round 1
    std::cout << "Round 1: To find K0\n";
    decryptHighestRound(crackedKey1);
    std::cout << "Processing... \n";

    roundStartTime = static_cast<uint>(std::time(nullptr));

    uint crackedKey0 = 0;
    uint crackedKey4 = 0;
    uint crackedKey5 = 0;

    for (uint tmpK0 = 0; tmpK0 < 0xFFFFFFFFL; ++tmpK0) {
        uint tmpK4 = 0;
        uint tmpK5 = 0;

        for (int i = 0; i < num_plaintexts; ++i) {
            uint plainLeft0 = getLeftHalf(plaintext0[i]);
            uint plainRight0 = getRightHalf(plaintext0[i]);
            uint cipherLeft0 = getLeftHalf(ciphertext0[i]);
            uint cipherRight0 = getRightHalf(ciphertext0[i]);

            uint temp = f(cipherRight0 ^ tmpK0) ^ cipherLeft0;
            if (tmpK4 == 0) {
                tmpK4 = temp ^ plainLeft0;
                tmpK5 = temp ^ cipherRight0 ^ plainRight0;
            } else if (((temp ^ plainLeft0) != tmpK4) || ((temp ^ cipherRight0 ^ plainRight0) != tmpK5)) {
                tmpK4 = 0;
                tmpK5 = 0;
                break;
            }
        }

        if (tmpK4 != 0) {
            crackedKey0 = tmpK0;
            crackedKey4 = tmpK4;
            crackedKey5 = tmpK5;
            break;
        }
    }

    std::cout << "found key K0: 0x" << std::hex << crackedKey0 << std::dec << "\n";
    std::cout << "found key K4: 0x" << std::hex << crackedKey4 << std::dec << "\n";
    std::cout << "found key K5: 0x" << std::hex << crackedKey5 << std::dec << "\n";
    uint endTime = static_cast<uint>(std::time(nullptr));
    std::cout << "Total time taken = " << int(endTime - startTime) << " seconds\n";

    std::cout << "\n\n\n";

    generatePlaintextCiphertextPairs(0xaea129c37cc07d12);

    key[0] = crackedKey0;
    key[1] = crackedKey1;
    key[2] = crackedKey2;
    key[3] = crackedKey3;
    key[4] = crackedKey4;
    key[5] = crackedKey5;

    for (int i = 0; i < num_plaintexts; ++i) {
        ull a = encrypt(plaintext0[i]);
        ull b = encrypt(plaintext1[i]);
        if (a != ciphertext0[i] || b != ciphertext1[i]) {
            std::cout << "Failed " << std::hex << a << " " << b << " " << ciphertext0[i] << " " << ciphertext1[i]
                      << std::dec;
            return 0;
        }
    }

    std::cout << "Each ciphertext generated using the keys obtained above matches the ciphertext generated by the actual encryption algorithm!\n";
    std::cout << "Finished successfully.\n";
    return 0;
}