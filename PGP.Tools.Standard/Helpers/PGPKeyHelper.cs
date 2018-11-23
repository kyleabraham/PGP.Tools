using Org.BouncyCastle.Bcpg.OpenPgp;
using System;

namespace PGP.Tools.Standard.Helpers
{
    public class PGPKeyHelper
    {
        /// <summary>
        /// A simple routine that opens a key ring file and loads the first available key suitable for encryption.
        /// </summary>
        /// <param name="inputStream"></param>
        /// <returns></returns>
        public static PgpPublicKey ReadPublicKey(System.IO.Stream inputStream)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            // iterate through the key rings.
            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey k in kRing.GetPublicKeys())
                {
                    if (k.IsEncryptionKey)
                        return k;
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        /// <summary>
        /// Search a secret key ring collection for a secret key corresponding to keyId if it exists.
        /// </summary>
        /// <param name="pgpSec"></param>
        /// <param name="keyId"></param>
        /// <param name="pass"></param>
        /// <returns></returns>
        public static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);

            if (pgpSecKey == null)
                return null;

            return pgpSecKey.ExtractPrivateKey(pass);
        }
    }
}
