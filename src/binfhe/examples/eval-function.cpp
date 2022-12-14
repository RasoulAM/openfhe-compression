//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Example for the FHEW scheme small precision arbitrary function evaluation
 */

#include "compbinfhecontext.h"
#include <iostream>
#include <ipcl/ipcl.hpp>

using namespace lbcrypto;




std::vector<std::string> debug(ipcl::PlainText pt){
    size_t n = pt.getSize();
    std::vector<std::string> bbs(n);
    for (size_t i=0;i<n;i++){
        BigNumber(pt[i]).num2hex(bbs[i]);
    }
    return bbs;
}
std::vector<std::string> debug(ipcl::CipherText ct, ipcl::PrivateKey * sk){
    return debug(sk->decrypt(ct));
}
long long hex_ll(const std::string & hex){
    long long val;
    std::stringstream ss;
    ss<<std::hex<<hex;
    ss>>val;
    return val;
}


int main() {
    // Sample Program: Step 1: Set CryptoContext
    auto cc = CompBinFHEContext();
    cc.GenerateBinFHEContext(STD128, true, 12);
    // Generate the secret key
    auto keys = cc.KeyGen();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(keys.Lwe);

    std::cout << "Completed the key generation." << std::endl;

    // Sample Program: Step 3: Create the to-be-evaluated funciton and obtain its corresponding LUT
    int p = cc.GetMaxPlaintextSpace().ConvertToInt();  // Obtain the maximum plaintext space

    // Initialize Function f(x) = x^3 % p
    auto fp = [](NativeInteger m, NativeInteger p1) -> NativeInteger {
        if (m < p1)
            return (m * m * m) % p1;
        else
            return ((m - p1 / 2) * (m - p1 / 2) * (m - p1 / 2)) % p1;
    };

    // Generate LUT from function f(x)
    auto lut = cc.GenerateLUTviaFunction(fp, p);
    std::cout << "Evaluate x^3%" << p << "." << std::endl;

    // Sample Program: Step 4: evalute f(x) homomorphically and decrypt
    // Note that we check for all the possible plaintexts.
    for (int i = 0; i < p; i++) {
        auto ct1 = cc.Encrypt(keys.Lwe, i % p, FRESH, p);

        auto ct_cube = cc.EvalFunc(ct1, lut);

        LWEPlaintext result;
        auto r_ct = cc.Compress(keys.CompressionKey, ct_cube);
        cc.DecryptCompressed(r_ct, keys.Pai.priv_key, ct_cube, &result, p);
        std::cout << "Input: " << i << ". Expected: " << fp(i, p) << ". Evaluated[CFHE] = " << result;
        cc.Decrypt(keys.Lwe, ct_cube, &result, p);
        std::cout << ". Evaluated[FHE] = " << result<<std::endl;
    }

    return 0;
}
