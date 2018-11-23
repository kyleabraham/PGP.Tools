namespace PGP.Tools.Standard.Extensions
{
    public static class StringExtensions
    {
        public static System.IO.Stream ToStream(this string str, System.Text.Encoding enc = null)
        {
            enc = enc ?? System.Text.Encoding.UTF8;
            return new System.IO.MemoryStream(enc.GetBytes(str ?? ""));
        }
    }
}
