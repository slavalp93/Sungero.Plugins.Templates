using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using EUSignCP;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;
using Sungero.Cryptography.Shared;

/*
 * Как выполняется подписание пользователем. 
 * Пользователь инициирует подписание (например, через действие "Подписать" или при вызове подписания из программного кода).
 * 1. Веб-сервер. Из сертификата считывается SignAlgorithmId, по нему ищется
 *    подходящий плагин подписания с помощью метода ICryptographyPlugin.IsSignAlgorithmSupported.
 * 2. Веб-сервер. По SignAlgorithmId ищется алгоритм хеширования с помощью 
 *    метода ICryptographyPlugin.GetHashAlgorithmIdBySignAlgorithmId.
 * 3. Веб-сервер. Формируется поток подписываемых данных. С помощью 
 *    ICryptographyPlugin.GetHashAlgorithmWrapperByHashAlgorithmId создается класс для хеширования, 
 *    данные хешируются в потоковом режиме.
 * 4. Веб-сервер. Метод ICryptographyPlugin.GetSignerBySignAlgorithmId создает нужный Signer. 
 *    Формируются SignedAttributes согласно стандарту CAdES - BES, после вызывается EnhanceSigningAttributes 
 *    (тут можно «подкрутить» подписываемые атрибуты, но как правило это не требуется).
 * 5. Веб-сервер. На веб-клиент передаются SignedAttributes, отпечаток сертификата и прочая служебная 
 *    информация.
 * 6. Веб-клиент. Передает полученную информацию в веб-агент, в котором отрабатывает метод Singer.SignData.
 *    Метод формирует «сырую подпись», она отправляется обратно на сервер. Также SignData может вернуть
 *    готовую CMS-подпись, в этом случае в п.7 она уже не будет модифицироваться веб-сервером.
 * 7. Веб-сервер. Из сформированных ранее SignedAttributes, «сырой» подписи с клиента и 
 *    дополнительных сертификатов полученных методом GetAdditionalCertificates формируется итоговая CMS-подпись.
 * 8. Веб-сервер. Вызывается метод EnhanceSignature, где подпись можно дополнительно модифицировать, например,
 *    дописать что-нибудь в UnsignedAttributes.
 * 9. Веб-сервер. Итоговая CMS-подпись сохраняется в базу.
 */
namespace CryptographyPlugin
{
    /// <summary>
    /// Серверный криптографический плагин Directum RX.
    /// Поддерживает только алгоритм подписи ДСТУ.
    /// Настройки IIT передаются через PLUGINS в config.yml и ApplySettings().
    /// </summary>
    public sealed class CryptographyPlugin : ICryptographyPlugin
    {
        #region Идентификаторы

        /// <summary>OID алгоритма подписи ДСТУ.</summary>
        private const string SignAlgorithmId = "1.2.804.2.1.1.1.1.3.1.1";

        /// <summary>GUID должен совпадать с идентификатором клиентского плагина.</summary>
        public Guid Id { get; } = Guid.Parse("bdf8266b-fd5e-4fe6-9f3e-ad67f360c053");

        #endregion

        #region ICryptographyPlugin

        /// <summary>
        /// Получить настройки серверного плагина из config.yml.
        /// Имена параметров принимаются как с символом '@', так и без него.
        /// Библиотека IIT инициализируется позднее, при первой проверке подписи.
        /// </summary>
        public void ApplySettings(IReadOnlyDictionary<string, string> settings)
        {
            var iitSettings = IitSettings.FromPluginSettings(settings);
            LibraryLoader.Instance.SetSettings(iitSettings);
        }

        /// <summary>Дополнительные сертификаты для цепочки не предоставляются.</summary>
        public IEnumerable<X509Certificate2> GetAdditionalCertificates(X509Certificate2 certificate)
        {
            return Enumerable.Empty<X509Certificate2>();
        }

        /// <summary>Получить OID хеширования по OID алгоритма подписи.</summary>
        public string GetHashAlgorithmIdBySignAlgorithmId(string signAlgorithmId)
        {
            if (!this.IsSignAlgorithmSupported(signAlgorithmId))
                throw new NotSupportedException("Не поддерживается алгоритм подписания: " + signAlgorithmId);

            return HashAlgorithmDSTU.AlgorithmId;
        }

        /// <summary>Получить потоковый алгоритм хеширования ДСТУ.</summary>
        public HashAlgorithmWrapper GetHashAlgorithmWrapperByHashAlgorithmId(string hashAlgorithmId)
        {
            if (!this.IsHashAlgorithmSupported(hashAlgorithmId))
                throw new NotSupportedException("Не поддерживается алгоритм хеширования: " + hashAlgorithmId);

            return new HashAlgorithmWrapper(hashAlgorithmId, HashAlgorithmDSTU.Create);
        }

        /// <summary>Получить реализацию подписания для ДСТУ.</summary>
        public ISigner GetSignerBySignAlgorithmId(string signAlgorithmId)
        {
            if (!this.IsSignAlgorithmSupported(signAlgorithmId))
                throw new NotSupportedException("Не поддерживается алгоритм подписания: " + signAlgorithmId);

            return new Signer();
        }

        public bool IsHashAlgorithmSupported(string hashAlgorithmId)
        {
            return string.Equals(hashAlgorithmId, HashAlgorithmDSTU.AlgorithmId,
                StringComparison.OrdinalIgnoreCase);
        }

        public bool IsSignAlgorithmSupported(string signAlgorithmId)
        {
            return string.Equals(signAlgorithmId, SignAlgorithmId,
                StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Дополнительные проверки сертификата не задаются.
        /// Пустой список не отменяет проверки сертификата средствами платформы.
        /// </summary>
        public IEnumerable<string> ValidateCertificate(X509Certificate2 certificate, DateTime verificationDateTime)
        {
            return Enumerable.Empty<string>();
        }

        /// <summary>
        /// Дополнительная проверка CMS-подписи средствами IIT.EUSignCP.
        /// Проверяется готовая подпись CAdES/CMS.
        /// </summary>
        /// <param name="dataSignature">CMS-подпись.</param>
        /// <returns>Список обнаруженных ошибок проверки.</returns>
        public IEnumerable<string> VerifySignature(byte[] dataSignature)
        {
            var errors = new List<string>();

            if (dataSignature == null || dataSignature.Length == 0)
            {
                errors.Add("Подпись отсутствует.");
                return errors;
            }

            try
            {
                // Разбираем CMS-контейнер.
                var cms = new CmsSignedData(dataSignature);

                // Токен штампа времени не проверяем данным методом.
                if (PkcsObjectIdentifiers.IdCTTstInfo.Equals(cms.SignedContentType))
                    return errors;

                // Получаем хеш документа из атрибута messageDigest CMS.
                byte[] documentHash = GetDocumentHashFromCMSSignature(cms);

                // Инициализируем IIT с настройками из config.yml.
                LibraryLoader.Instance.LoadLibraryIfNeed();

                IntPtr context = IntPtr.Zero;

                try
                {
                    // Создаём контекст криптобиблиотеки.
                    int error = IEUSignCP.CtxCreate(out context);
                    if (error != IEUSignCP.EU_ERROR_NONE)
                    {
                        errors.Add(GetIitError("Ошибка создания контекста проверки подписи", error));
                        return errors;
                    }

                    // Проверяем готовую CMS-подпись через IIT.
                    IEUSignCP.EU_SIGN_INFO signInfo;
                    error = IEUSignCP.CtxVerifyHashValue(context, documentHash, 0, dataSignature, out signInfo);
                    if (error != IEUSignCP.EU_ERROR_NONE)
                    {
                        errors.Add(GetIitError("Ошибка проверки CMS-подписи", error));
                    }
                }
                finally
                {
                    // Освобождаем контекст даже при возникновении исключения.
                    if (context != IntPtr.Zero)
                        IEUSignCP.CtxFree(context);
                }
            }
            catch (Exception ex)
            {
                errors.Add("Ошибка проверки подписи: " + ex.Message);
            }

            return errors;
        }


        #endregion

        #region Вспомогательные методы проверки подписи

        /// <summary>
        /// Прочитать атрибут messageDigest из SignedAttributes.
        /// Как и в исходной реализации, ожидается ровно один подписант.
        /// </summary>
        private static byte[] GetDocumentHashFromCMSSignature(CmsSignedData cms)
        {
            var signers = cms.GetSignerInfos().GetSigners()
                .OfType<SignerInformation>()
                .ToArray();

            if (signers.Length != 1)
                throw new InvalidDataException(
                    "Ожидалась CMS-подпись с одним подписантом. Найдено: " + signers.Length);

            var attributes = signers[0].SignedAttributes;
            if (attributes == null)
                throw new InvalidDataException("В CMS-подписи отсутствуют SignedAttributes.");

            var attributeDictionary = attributes.ToDictionary();
            var digestAttribute = attributeDictionary[PkcsObjectIdentifiers.Pkcs9AtMessageDigest]
                as Org.BouncyCastle.Asn1.Cms.Attribute;

            if (digestAttribute == null || digestAttribute.AttrValues == null ||
                digestAttribute.AttrValues.Count != 1)
            {
                throw new InvalidDataException(
                    "В CMS-подписи отсутствует корректный атрибут messageDigest.");
            }

            return Asn1OctetString.GetInstance(digestAttribute.AttrValues[0]).GetOctets();
        }

        private static string GetIitError(string operation, int error)
        {
            return string.Format("{0}. Код: {1}. Описание: {2}", operation, error,
                IEUSignCP.GetErrorLangDesc(error, IEUSignCP.EU_LANG.RU));
        }

        #endregion

        #region Настройки IIT из ApplySettings

        /// <summary>
        /// Проверенные настройки, полученные от платформы Directum RX.
        /// В проекте больше не используется отдельный Settings.json.
        /// </summary>
        internal sealed class IitSettings
        {
            public string CertFolderPath { get; private set; }
            public bool UseProxy { get; private set; }
            public bool AnonymousProxy { get; private set; }
            public string ProxyAddress { get; private set; }
            public string ProxyPort { get; private set; }
            public string ProxyUser { get; private set; }
            public string ProxyPassword { get; private set; }
            public bool SaveProxyPassword { get; private set; }

            public static IitSettings FromPluginSettings(IReadOnlyDictionary<string, string> settings)
            {
                if (settings == null)
                    throw new ArgumentNullException(nameof(settings),
                        "Платформа не передала настройки плагина.");

                var result = new IitSettings
                {
                    CertFolderPath = GetValue(settings, "CertFolderPath").Trim(),
                    UseProxy = GetBoolean(settings, "Proxy_useProxy", false),
                    AnonymousProxy = GetBoolean(settings, "Proxy_anonymous", false),
                    ProxyAddress = GetValue(settings, "Proxy_address").Trim(),
                    ProxyPort = GetValue(settings, "Proxy_port").Trim(),
                    ProxyUser = GetValue(settings, "Proxy_user"),
                    ProxyPassword = GetValue(settings, "Proxy_pass"),
                    SaveProxyPassword = GetBoolean(settings, "Proxy_savepass", false)
                };

                if (string.IsNullOrWhiteSpace(result.CertFolderPath))
                    throw new InvalidDataException(
                        "Не задан параметр CertFolderPath в секции PLUGINS config.yml.");

                if (result.UseProxy)
                {
                    if (string.IsNullOrWhiteSpace(result.ProxyAddress))
                        throw new InvalidDataException(
                            "При Proxy_useProxy=true необходимо задать Proxy_address.");

                    int port;
                    if (!int.TryParse(result.ProxyPort, out port) || port < 1 || port > 65535)
                        throw new InvalidDataException(
                            "При Proxy_useProxy=true параметр Proxy_port должен быть числом от 1 до 65535.");
                }

                return result;
            }

            /// <summary>
            /// Содержимое словаря зависит от версии платформы:
            /// допускаем имена свойств как '@CertFolderPath', так и 'CertFolderPath'.
            /// Пароли и значения настроек никогда не протоколируем.
            /// </summary>
            private static string GetValue(IReadOnlyDictionary<string, string> settings, string name)
            {
                foreach (var pair in settings)
                {
                    var key = pair.Key;
                    if (string.IsNullOrEmpty(key))
                        continue;

                    if (key[0] == '@')
                        key = key.Substring(1);

                    if (string.Equals(key, name, StringComparison.OrdinalIgnoreCase))
                        return pair.Value ?? string.Empty;
                }

                return string.Empty;
            }

            private static bool GetBoolean(IReadOnlyDictionary<string, string> settings,
                string name, bool defaultValue)
            {
                var value = GetValue(settings, name);
                if (string.IsNullOrWhiteSpace(value))
                    return defaultValue;

                bool parsed;
                if (!bool.TryParse(value, out parsed))
                    throw new InvalidDataException(
                        "Некорректное значение параметра " + name + ". Допустимо: true или false.");

                return parsed;
            }

            public bool HasSameValues(IitSettings other)
            {
                return other != null &&
                    string.Equals(this.CertFolderPath, other.CertFolderPath, StringComparison.OrdinalIgnoreCase) &&
                    this.UseProxy == other.UseProxy &&
                    this.AnonymousProxy == other.AnonymousProxy &&
                    string.Equals(this.ProxyAddress, other.ProxyAddress, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(this.ProxyPort, other.ProxyPort, StringComparison.Ordinal) &&
                    string.Equals(this.ProxyUser, other.ProxyUser, StringComparison.Ordinal) &&
                    string.Equals(this.ProxyPassword, other.ProxyPassword, StringComparison.Ordinal) &&
                    this.SaveProxyPassword == other.SaveProxyPassword;
            }
        }

        #endregion

        #region Инициализация IIT

        /// <summary>
        /// Единый загрузчик нативной библиотеки в рамках процесса плагина.
        /// Изменять настройки после инициализации не допускается.
        /// </summary>
        internal sealed class LibraryLoader
        {
            private readonly object syncRoot = new object();
            private IitSettings settings;
            private bool isLoaded;

            private static readonly Lazy<LibraryLoader> instance =
                new Lazy<LibraryLoader>(() => new LibraryLoader(), true);

            public static LibraryLoader Instance { get { return instance.Value; } }

            public void SetSettings(IitSettings newSettings)
            {
                if (newSettings == null)
                    throw new ArgumentNullException(nameof(newSettings));

                lock (this.syncRoot)
                {
                    if (this.isLoaded)
                    {
                        if (!this.settings.HasSameValues(newSettings))
                            throw new InvalidOperationException(
                                "Настройки IIT изменены после инициализации. " +
                                "Перезапустите серверный процесс Directum RX.");
                        return;
                    }

                    this.settings = newSettings;
                }
            }

            public void LoadLibraryIfNeed()
            {
                lock (this.syncRoot)
                {
                    if (this.isLoaded)
                        return;

                    if (this.settings == null)
                        throw new InvalidOperationException(
                            "Настройки IIT не получены. Проверьте PLUGINS в config.yml " +
                            "и вызов CryptographyPlugin.ApplySettings().");

                    bool alreadyInitialized = IEUSignCP.IsInitialized();
                    if (!alreadyInitialized)
                    {
                        IEUSignCP.SetUIMode(false);
                        int error = IEUSignCP.Initialize();
                        if (error != IEUSignCP.EU_ERROR_NONE)
                            throw new InvalidOperationException(
                                GetIitError("Не удалось инициализировать библиотеку IIT", error));
                    }

                    try
                    {
                        IEUSignCP.SetUIMode(false);

                        // Не сохраняем настройки IIT в реестр.
                        IEUSignCP.SetRuntimeParameter(
                            IEUSignCP.EU_SAVE_SETTINGS_PARAMETER,
                            IEUSignCP.EU_SETTINGS_ID_NONE);

                        IEUSignCP.SetOCSPSettings(true, true, "", "80");
                        IEUSignCP.SetTSPSettings(true, "", "80");

                        IEUSignCP.SetProxySettings(
                            this.settings.UseProxy,
                            this.settings.AnonymousProxy,
                            this.settings.UseProxy ? this.settings.ProxyAddress : "",
                            this.settings.UseProxy ? this.settings.ProxyPort : "",
                            this.settings.UseProxy ? this.settings.ProxyUser : "",
                            this.settings.UseProxy ? this.settings.ProxyPassword : "",
                            this.settings.UseProxy && this.settings.SaveProxyPassword);

                        IEUSignCP.SetLDAPSettings(false, "", "", false, "", "");
                        IEUSignCP.SetFileStoreSettings(
                            this.settings.CertFolderPath, false, true, false, false, true, true, 60);

                        // Работа с серверами ЦСК в онлайн-режиме.
                        IEUSignCP.SetModeSettings(false);

                        this.isLoaded = true;
                    }
                    catch
                    {
                        // Освобождаем библиотеку только если инициализировали её сами.
                        if (!alreadyInitialized)
                            IEUSignCP.Finalize();
                        throw;
                    }
                }
            }

            // Намеренно не вызываем IEUSignCP.Finalize() в финализаторе:
            // другие плагины/компоненты того же процесса могут использовать IIT.
        }

        #endregion
    }
}