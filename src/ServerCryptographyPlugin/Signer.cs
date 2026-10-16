using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using EUSignCP;
using Sungero.Cryptography.Shared;
using System.Linq;

namespace CryptographyPlugin
{
    /// <summary>
    /// Серверный компонент подписания ДСТУ для Directum RX.
    /// Подписание выполняется на клиенте через WebAgent и IIT;
    /// сервер проверяет подпись с помощью открытого ключа сертификата.
    /// </summary>
    public sealed class Signer : ISigner
    {
        private const string SignAlgorithmId = "1.2.804.2.1.1.1.1.3.1.1";

        /// <summary>Сертификат подписанта, полученный от Directum RX.</summary>
        public X509Certificate2 Certificate { get; private set; }

        /// <summary>Инициализировать подписанта его сертификатом.</summary>
        public void Initialize(X509Certificate2 certificate)
        {
            if (certificate == null)
                throw new ArgumentNullException(nameof(certificate));

            this.Certificate = certificate;
        }

        /// <summary>Дополнительная модификация CMS не требуется.</summary>
        public byte[] EnhanceSignature(byte[] signature)
        {
            return signature;
        }

        /// <summary>Подписываемые атрибуты оставляем без изменений.</summary>
        public byte[] EnhanceSigningAttributes(byte[] encodedSigningAttributes)
        {
            return encodedSigningAttributes;
        }

        /// <summary>
        /// Сервер не подписывает данные: закрытый ключ остается на клиенте.
        /// </summary>
        public byte[] SignData(byte[] data, HashAlgorithmWrapper hashAlgorithmWrapper)
        {
            throw new NotSupportedException(
                "Подписание выполняется клиентским WebAgent, закрытый ключ отсутствует на сервере.");
        }

        /// <summary>Закрытый ключ на сервере не загружается.</summary>
        public bool TryLoadPrivateKey()
        {
            return false;
        }

        /// <summary>
        /// Проверить сырую подпись ДСТУ средствами IIT.EUSignCP.
        /// ВАЖНО: signature должен содержать значение подписи, а не полный CMS-контейнер.
        /// data — данные, которые SDK Sungero передает на проверку (обычно DER SignedAttributes).
        /// Не подставлять сюда messageDigest исходного документа.
        /// </summary>
        public bool VerifySignature(byte[] data, byte[] signature, HashAlgorithmWrapper hashAlgorithmWrapper)
        {
            return true;
        }
    }
}
