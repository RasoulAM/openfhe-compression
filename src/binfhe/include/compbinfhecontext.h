//
// Created by r5akhava on 12/14/22.
//

#ifndef OPENFHE_COMPBINFHECONTEXT_H
#define OPENFHE_COMPBINFHECONTEXT_H

#include "binfhe-base-scheme.h"
#include "binfhecontext.h"
#include "utils/serializable.h"
#include "lattice/stdlatticeparms.h"

#include <memory>
#include <string>
#include <vector>
#include <map>
#include <ipcl/ipcl.hpp>

namespace lbcrypto {

class KeySet{
public:
    LWEPrivateKey Lwe;
    ipcl::keyPair Pai;
    ipcl::CipherText CompressionKey;
};

/**
 * @brief BinFHEContext
 *
 * The wrapper class for Boolean circuit FHE
 */
class CompBinFHEContext : public BinFHEContext {
public:
    /**
   * Generates a secret key for the main LWE scheme
   *
   * @param DiffQ Keygen according to DiffQ instead of m_q if DiffQ != 0
   * @return a shared pointer to the secret key
   */
    KeySet KeyGen() const;

    /**
   * Generates a secret key used in bootstrapping
   * @return a shared pointer to the secret key
   */
    KeySet KeyGenN() const;

    /**
   * Decrypts a ciphertext using a secret key
   *
   * @param sk the secret key
   * @param ct the ciphertext
   * @param *result plaintext result
   * @param p - plaintext modulus
   * @param DiffQ Decrypt according to DiffQ instead of m_q if DiffQ != 0
   */
    static void DecryptCompressed(const ipcl::CipherText& r_ct, ipcl::PrivateKey*  a_sk, ConstLWECiphertext& ct,
                           LWEPlaintext* result, const LWEPlaintextModulus& p) ;

    static ipcl::CipherText Compress(const ipcl::CipherText& s, ConstLWECiphertext& ct) ;

    std::string SerializedObjectName() const {
        return "CompBinFHEContext";
    }

};

void CompBinFHEContext::DecryptCompressed(const ipcl::CipherText& r_ct, ipcl::PrivateKey*  a_sk, ConstLWECiphertext& ct,
                                LWEPlaintext* result, const LWEPlaintextModulus& p) {
    auto q = ct->GetModulus();
    ipcl::PlainText r_pt = a_sk->decrypt(r_ct);
    std::string bb;
    BigNumber(r_pt).num2hex(bb);
    NativeInteger r (bb);
    r.ModEq(q);
    r.ModAddFastEq((q / (p * 2)), q);
    *result = ((NativeInteger(p) * r) / q).ConvertToInt();
}
KeySet CompBinFHEContext::KeyGenN() const {
    //TODO: check which q or Q
    auto lwe_sk            =  BinFHEContext::KeyGenN();
    ipcl::keyPair pai_keys = ipcl::generateKeypair(2048, true);
    NativeInteger q = GetParams()->GetLWEParams()->Getq();
    NativeVector ske = lwe_sk->GetElement();
    ske.SwitchModulus(q);
    ipcl::PlainText sk_pt(ske.ConvertToInt());
    ipcl::CipherText comp = pai_keys.pub_key->encrypt(sk_pt);
    return KeySet{lwe_sk, pai_keys, comp};
}
KeySet CompBinFHEContext::KeyGen() const {
    auto lwe_sk            =  BinFHEContext::KeyGen();
    ipcl::keyPair pai_keys = ipcl::generateKeypair(2048, true);
    NativeInteger q = GetParams()->GetLWEParams()->Getq();
    NativeVector ske = lwe_sk->GetElement();
    ske.SwitchModulus(q);
    ipcl::PlainText sk_pt(ske.ConvertToInt());
    ipcl::CipherText comp = pai_keys.pub_key->encrypt(sk_pt);
    return KeySet{lwe_sk, pai_keys, comp};

}
ipcl::CipherText CompBinFHEContext::Compress(const ipcl::CipherText& s, ConstLWECiphertext& ct) {
    const ipcl::PublicKey* a_pk = s.getPubKey();
    auto _a = (-(ct->GetA())).ConvertToInt();
    auto a = (ct->GetA()).ConvertToInt();
    ipcl::PlainText _a_pt(_a);
    ipcl::PlainText a_pt(a);
    uint32_t n       = _a_pt.getSize();
    ipcl::CipherText prod = _a_pt *s;
    const BigNumber& sq = a_pk->getNSQ();
    auto sum = prod[0]; // sum of prod
    for (size_t i = 1; i < n; ++i) {
        sum = sum*prod[i] %sq; // paillier for addition
    }
    auto ret = ipcl::CipherText(a_pk,sum)+ipcl::PlainText(ct->GetB().ConvertToInt());
    return ret;
}

}  // namespace lbcrypto

#endif //OPENFHE_COMPBINFHECONTEXT_H
