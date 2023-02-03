using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace UsingBouncyCastle
{
    class Program
    {
        private const int KeySize1 = 192;
        private const int KeySize2 = 239;
        private const int KeySize3 = 256;

        static void Main(string[] args)
        {
            ECDSASample(KeySize1);
            ECDSASample(KeySize2);
            ECDSASample(KeySize3);

            Console.ReadLine();
        }

        private static void ECDSASample(int keySize)
        {
            Console.WriteLine(string.Format("======= Key Size: {0} =======", keySize));
            string s = "Hello World";
            try
            {
                var key = GenerateKeys(keySize);
                var signature = GetSignature(s, key);
                var signatureOK = VerifySignature(key, s, signature);

                //Show it to me
                var pubicKey = (ECPublicKeyParameters)(key.Public);
                var privateKey = (ECPrivateKeyParameters)(key.Private);
                Console.WriteLine("Input Text: " + s);
                Console.WriteLine("Key ({0} bytes): {1}", privateKey.D.BitLength, privateKey.D);
                Console.WriteLine("Signature ({0} bytes): {1}", signature.Length, ToString(signature));
                Console.WriteLine("Signature verified: {0}", signatureOK);
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }


        private static AsymmetricCipherKeyPair GenerateKeys(int keySize)
        {
            var gen = new ECKeyPairGenerator();
            var secureRandom = new SecureRandom();
            var keyGenParam = new KeyGenerationParameters(secureRandom, keySize);
            gen.Init(keyGenParam);

            return gen.GenerateKeyPair();
        }

        private static byte[] GetSignature(string plainText, AsymmetricCipherKeyPair key)
        {
            var encoder = new ASCIIEncoding();
            var inputData = encoder.GetBytes(plainText);

            var signer = SignerUtilities.GetSigner("ECDSA");
            signer.Init(true, key.Private);
            signer.BlockUpdate(inputData, 0, inputData.Length);

            return signer.GenerateSignature();
        }

        private static bool VerifySignature(AsymmetricCipherKeyPair key, string plainText, byte[] signature)
        {
            var encoder = new ASCIIEncoding();
            var inputData = encoder.GetBytes(plainText);

            var signer = SignerUtilities.GetSigner("ECDSA");
            signer.Init(false, key.Public);
            signer.BlockUpdate(inputData, 0, inputData.Length);

            return signer.VerifySignature(signature);
        }

        private static string ToString(IEnumerable<byte> b)
        {
            string o = string.Empty;
            foreach (byte b1 in b)
            {
                o += b1.ToString("X2");
            }
            return o;
        }
    }
}