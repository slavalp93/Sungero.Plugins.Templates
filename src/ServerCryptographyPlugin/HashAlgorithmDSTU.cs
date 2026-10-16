using System;
using System.IO;
using System.Security.Cryptography;
using EUSignCP;

namespace CryptographyPlugin
{
    /// <summary>
    /// DSTU GOST 34.311-95 hashing through the IIT EUSignCP provider.
    /// </summary>
    public sealed class HashAlgorithmDSTU : System.Security.Cryptography.HashAlgorithm
    {
        internal const string AlgorithmId = "1.2.804.2.1.1.1.1.2.1";

        private MemoryStream dataStream;
        private bool disposed;

        public HashAlgorithmDSTU()
        {
            HashSizeValue = 256;
            Initialize();
        }

        public static new HashAlgorithmDSTU Create()
        {
            return new HashAlgorithmDSTU();
        }

        public override void Initialize()
        {
            ThrowIfDisposed();

            // HashAlgorithm can call Initialize after each ComputeHash.
            dataStream?.Dispose();
            dataStream = new MemoryStream();
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            ThrowIfDisposed();
            dataStream.Write(array, ibStart, cbSize);
        }

        protected override byte[] HashFinal()
        {
            ThrowIfDisposed();

            // Empty data must be hashed as an empty byte array, not as { 0 }.
            byte[] data = dataStream.ToArray();
            CryptographyPlugin.LibraryLoader.Instance.LoadLibraryIfNeed();

            IntPtr context = IntPtr.Zero;
            try
            {
                int error = IEUSignCP.CtxCreate(out context);
                if (error != IEUSignCP.EU_ERROR_NONE)
                    throw CreateIitException("CtxCreate", error);

                byte[] result;
                error = IEUSignCP.CtxHashData(
                    context,
                    IEUSignCP.EU_CTX_HASH_ALGO_GOST34311,
                    null,
                    data,
                    out result);

                if (error != IEUSignCP.EU_ERROR_NONE)
                    throw CreateIitException("CtxHashData", error);

                if (result == null || result.Length != 32)
                    throw new CryptographicException(
                        "IIT returned an invalid GOST 34.311 hash (expected 32 bytes).");

                return result;
            }
            finally
            {
                if (context != IntPtr.Zero)
                    IEUSignCP.CtxFree(context);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && !disposed)
            {
                dataStream?.Dispose();
                dataStream = null;
            }

            disposed = true;
            base.Dispose(disposing);
        }

        private void ThrowIfDisposed()
        {
            if (disposed)
                throw new ObjectDisposedException(nameof(HashAlgorithmDSTU));
        }

        private static CryptographicException CreateIitException(string operation, int error)
        {
            string description;
            try
            {
                description = IEUSignCP.GetErrorLangDesc(error, IEUSignCP.EU_LANG.UA);
            }
            catch
            {
                description = "IIT error description is unavailable";
            }

            return new CryptographicException(
                string.Format("IIT {0} failed. Code: {1}. Description: {2}",
                    operation, error, description));
        }
    }
}
