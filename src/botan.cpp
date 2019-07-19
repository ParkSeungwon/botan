#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include <iostream>
using namespace std;

int main()
   {
   Botan::AutoSeeded_RNG rng;

   const std::string plaintext("Your great-grandfather gave this watch to your granddad for good luck. Unfortunately, Dane's luck wasn't as good as his old man's.");
   const std::vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");

   std::unique_ptr<Botan::Cipher_Mode> enc(Botan::get_cipher_mode("AES-128/CBC/PKCS11", Botan::ENCRYPTION));
   std::unique_ptr<Botan::Cipher_Mode> enc2(Botan::get_cipher_mode("AES-128/CBC", Botan::ENCRYPTION));
   enc->set_key(key);
   enc2->set_key(key);

   Botan::secure_vector<uint8_t> pt;//(plaintext.data(), plaintext.data()+plaintext.length());
	auto pt2 = pt;
   //generate fresh nonce (IV)
   auto iv = rng.random_vec(16);
   enc->start(iv);
   enc->finish(pt);
   enc2->start(iv);
   enc2->finish(pt2);

   for(auto c : pt) cout << hex << +c;
   cout << endl;
   for(auto c : pt2) cout << hex << +c;
   cout << endl;
   std::cout << enc->name() << " with iv " << Botan::hex_encode(iv) << " " << Botan::hex_encode(pt) << "\n";

   std::unique_ptr<Botan::Cipher_Mode> dec(Botan::get_cipher_mode("AES-128/CBC/PKCS7", Botan::DECRYPTION));
   dec->set_key(key);
   dec->start(iv);
   dec->finish(pt);
   for(auto c : pt) cout << c;

   return 0;
   }
