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
#include "binfhecontext-ser.h"

#include <iostream>
#include <ios>

using namespace lbcrypto;

std::vector<LWECiphertext> decompose(uint32_t val, BinFHEContext cc, LWEPrivateKey lwe){
    int p = cc.GetMaxPlaintextSpace().ConvertToInt();
    uint32_t bits = floor(log2(p));
    uint32_t mask = (1<<bits)-1;
    uint32_t ciphers = ceil(sizeof(uint32_t)*4.0/3.0);
    std::vector<LWECiphertext> res(ciphers);
    for(uint32_t i=0; i<ciphers; i++){
        res[i] = cc.Encrypt(lwe, val&mask,FRESH, p);
        val>>=bits;
    }
    return res;
}

void debug(LWECiphertext ct, LWEPrivateKey sk, BinFHEContext cc){
    LWEPlaintext result;
    int p = cc.GetMaxPlaintextSpace().ConvertToInt();
        cc.Decrypt(sk, ct, &result, p);
    std::cout << result;
}

LWECiphertext equality_protocol(std::vector<LWECiphertext> x, std::vector<LWECiphertext> y,
                                std::vector<NativeInteger> lut, BinFHEContext cc){
    auto ct_eq = cc.EvalBinGate(lbcrypto::XOR, x[0], y[0]);
    for (uint32_t j=1; j<x.size(); j++){
        auto xor_ct = cc.EvalBinGate(lbcrypto::XOR, x[j], y[j]);
        ct_eq = cc.EvalBinGate(lbcrypto::OR, ct_eq, xor_ct);
    }
    ct_eq = cc.EvalFunc(ct_eq, lut);
    return ct_eq;
}

void serialize_paillier(ipcl::CipherText ct, std::string file_pre){
    const uint32_t nums = ct.getSize();
    for (uint32_t i=0; i<nums; i++){
        std::string fname = file_pre+ std::to_string(i)+".bin";
        if (!Serial::SerializeToFile(fname, ct.getElement(i), SerType::BINARY)) {
            std::cout << "Error serializing ct1" << std::endl;
        }
    }
}


int main() {
    // Step 1: Set CryptoContext
    auto cc = CompBinFHEContext();
    cc.GenerateBinFHEContext(STD128, true, 13);
    // Generate the keys
    auto keys = cc.KeyGen();
    std::cout << "Generating the bootstrapping keys..." << std::endl;
    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(keys.Lwe);
    std::cout << "Completed the key generation." << std::endl;

    // Sample Program: Step 3: Create the to-be-evaluated funciton and obtain its corresponding LUT
    int p = cc.GetMaxPlaintextSpace().ConvertToInt();  // Obtain the maximum plaintext space

    // Generating yours
    uint32_t n = 32;
    std::vector<uint32_t> yours(n);
    std::iota(yours.begin(), yours.end(), 0);
    // Generating mine (reverse)
    std::vector<uint32_t> mine(n);
    std::iota(mine.begin()+2, mine.end(), 2);
    std::vector<std::vector<LWECiphertext>> your_cts(n);

    for (uint32_t i = 0; i < n ; ++i) {
        your_cts[i] = decompose(yours[i], cc, keys.Lwe);
    }

    // Initialize Function f(x) = x==0
    auto fp = [](NativeInteger m, NativeInteger p1) -> NativeInteger {
        return uint32_t(m%p1==0);
    };

    // Generate LUT from function f(x)
    auto lut = cc.GenerateLUTviaFunction(fp, p);
    std::cout << "Evaluate n-bit equality (up to 32bits)." << std::endl;
    LWEPlaintext result;

    // Sample Program: Step 4: evalute f(x) homomorphically and decrypt
    // Note that we check for all the possible plaintexts.
    for (uint32_t i = 0; i < n; i++) {
        auto my_ct = decompose(mine[i], cc, keys.Lwe);
        auto ct_eq  = equality_protocol(my_ct, your_cts[i], lut, cc);

        auto r_ct = cc.Compress(keys.CompressionKey, ct_eq);
        cc.DecryptCompressed(r_ct, keys.Pai.priv_key, ct_eq, &result, p);

        auto compressed_size = r_ct.getSize()*sizeof(BigNumber);
        auto compressed_theory = 2*2048*(r_ct.getSize())/sizeof(char);
        auto original_size = (ct_eq->GetA().GetLength()+1)*sizeof(NativeInteger);
        auto original_theory = (ct_eq->GetA().GetLength()+1)*ct_eq->GetModulus().GetLengthForBase(2);

        if (!Serial::SerializeToFile(std::to_string(i)+"LWE.bin", ct_eq, SerType::BINARY)) {
            std::cout << "Error serializing ct1" << std::endl;
            return 1;
        }
        serialize_paillier(r_ct, std::to_string(i)+"Paillier");


        std::cout << "Input: " << mine[i]<<"| "<< yours[i] << ". Expected: " << (mine[i]==yours[i]) << ". Evaluated[CFHE] = " << result;
        cc.Decrypt(keys.Lwe, ct_eq, &result, p);
        std::cout << ". Evaluated[FHE] = " << result<<std::endl;
        std::cout << "comp_theo: "<< compressed_theory<<". comp_sz: "<<compressed_size<<std::endl;
        std::cout<< "origin_theo: "<< original_theory<<". origin_sz: "<<original_size<<std::endl;

    }

    return 0;
}
