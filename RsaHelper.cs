using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;

namespace ECorredores.Servicio.Seguridad
{
    public static class RsaHelper
    {
        public static void GenerateRsaKeyPair(String privateKeyFilePath, String publicKeyFilePath)
        {
            RsaKeyPairGenerator rsaGenerator = new RsaKeyPairGenerator();
            rsaGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var keyPair = rsaGenerator.GenerateKeyPair();


            using (TextWriter privateKeyTextWriter = new StringWriter())
            {

                PemWriter pemWriter = new PemWriter(privateKeyTextWriter);
                pemWriter.WriteObject(keyPair.Private);
                pemWriter.Writer.Flush();
                File.WriteAllText(privateKeyFilePath, privateKeyTextWriter.ToString());
            }


            using (TextWriter publicKeyTextWriter = new StringWriter())
            {

                PemWriter pemWriter = new PemWriter(publicKeyTextWriter);
                pemWriter.WriteObject(keyPair.Public);
                pemWriter.Writer.Flush();

                File.WriteAllText(publicKeyFilePath, publicKeyTextWriter.ToString());
            }
        }


        public static RSACryptoServiceProvider PrivateKeyFromString(String privateKey)
        {
            using (TextReader privateKeyTextReader = new StringReader(privateKey))
            {
                AsymmetricCipherKeyPair readKeyPair = (AsymmetricCipherKeyPair)new PemReader(privateKeyTextReader).ReadObject();


                RsaPrivateCrtKeyParameters privateKeyParams = ((RsaPrivateCrtKeyParameters)readKeyPair.Private);
                RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider();
                RSAParameters parms = new RSAParameters();

                parms.Modulus = privateKeyParams.Modulus.ToByteArrayUnsigned();
                parms.P = privateKeyParams.P.ToByteArrayUnsigned();
                parms.Q = privateKeyParams.Q.ToByteArrayUnsigned();
                parms.DP = privateKeyParams.DP.ToByteArrayUnsigned();
                parms.DQ = privateKeyParams.DQ.ToByteArrayUnsigned();
                parms.InverseQ = privateKeyParams.QInv.ToByteArrayUnsigned();
                parms.D = privateKeyParams.Exponent.ToByteArrayUnsigned();
                parms.Exponent = privateKeyParams.PublicExponent.ToByteArrayUnsigned();

                cryptoServiceProvider.ImportParameters(parms);

                return cryptoServiceProvider;
            }
        }

        public static RSACryptoServiceProvider PublicKeyFromString(String publicKey)
        {
            using (TextReader publicKeyTextReader = new StringReader(publicKey))
            {
                RsaKeyParameters publicKeyParam = (RsaKeyParameters)new PemReader(publicKeyTextReader).ReadObject();

                RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider();
                RSAParameters parms = new RSAParameters();

                parms.Modulus = publicKeyParam.Modulus.ToByteArrayUnsigned();
                parms.Exponent = publicKeyParam.Exponent.ToByteArrayUnsigned();

                cryptoServiceProvider.ImportParameters(parms);

                return cryptoServiceProvider;
            }
        }

    }
}
