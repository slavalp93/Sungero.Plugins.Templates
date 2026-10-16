using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using EUSignCP;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;

namespace Library
{
    /// <summary>
    /// Клиентское подписание ДСТУ через IIT.EUSignCP для Sungero WebAgent.
    /// Совместимо с контрактом Signer из Sungero.Plugins.Templates (25.1+).
    /// </summary>
    public static class Signer
    {
        private static readonly object SyncRoot = new object();
        private static bool iitConfigured;
        private static string loadedKeyThumbprint;
        private static IitSettings activeSettings;

        /// <summary>
        /// JSON со свойствами сертификата, передаваемый WebAgent (Sungero 25.1+).
        /// Не используется для выбора носителя IIT: его выбирает пользователь в диалоге IIT.
        /// </summary>
        public static string certificateParameters = string.Empty;

        public static void SetCertificateParameters(string parameters)
        {
            lock (SyncRoot)
                certificateParameters = parameters ?? string.Empty;
        }

        /// <summary>
        /// Подписание документа. signingData содержит DER-кодированные SignedAttributes
        /// в Base64. На выходе -- готовая CMS-подпись IIT в Base64.
        /// </summary>
        public static int SignData(string pluginName, string certificateThumbprint,
            string signingData, string userLanguage, out string result)
        {
            result = null;
            Logger.Info($"IIT: начало подписания. Plugin={pluginName}, CertificateThumbprint={certificateThumbprint}.");
            
            try
            {
                if (string.IsNullOrWhiteSpace(certificateThumbprint))
                    throw new SigningException(SignDataResult.IllegalCertificateID,
                        "Не указан отпечаток сертификата подписания.");
                if (string.IsNullOrWhiteSpace(signingData))
                    throw new InvalidOperationException("Не переданы данные для подписания.");

                // Directum передает SignedAttributes, а не сам документ.
                // Берем хеш документа из messageDigest и передаем его в IIT.SignHash(), который возвращает готовую CMS.
                var signedAttributes = Convert.FromBase64String(signingData);
                var documentHash = GetDocumentHashFromSigningAttributes(signedAttributes);
                if (documentHash.Length != 32)
                    throw new InvalidOperationException(
                        $"Неверный размер хеша ДСТУ: {documentHash.Length} байт (ожидается 32).");

                lock (SyncRoot)
                {
                    var language = GetIitLanguage(userLanguage);
                    InitializeIit(language);
                    var selectedThumbprint = EnsurePrivateKeyLoaded(language);

                    if (!ThumbprintsEqual(selectedThumbprint, certificateThumbprint))
                    {
                        ResetPrivateKey();
                        throw new SigningException(SignDataResult.IllegalCertificateID,
                            "Выбранный ключ IIT не соответствует сертификату, указанному в Directum RX. " +
                            $"Сертификат ключа: {selectedThumbprint}; сертификат Directum: {certificateThumbprint}.");
                    }

                    ApplyProxySettings(activeSettings);

                    byte[] cmsSignature;
                    var error = IEUSignCP.SignHash(Convert.ToBase64String(documentHash), out cmsSignature);
                    ThrowIfIitError(error, "Подписание хеша", language);
                    if (cmsSignature == null || cmsSignature.Length == 0)
                        throw new InvalidOperationException("IIT вернул пустую CMS-подпись.");

                    result = Convert.ToBase64String(cmsSignature);
                }

                Logger.Info("IIT: подписание завершено успешно (CMS).");
                return (int)SignDataResult.Success;
            }
            catch (SigningException ex)
            {
                result = ex.Message;
                Logger.Error("IIT: подписание отклонено. " + ex.Message);
                return (int)ex.ResultCode;
            }
            catch (Exception ex)
            {
                result = "Ошибка подписания IIT: " + ex.Message;
                Logger.Error("IIT: ошибка подписания. " + ex);
                return (int)SignDataResult.UnknownError;
            }
        }

        /// <summary>
        /// Подписание данных при двухфакторной аутентификации (Sungero 25.1+).
        /// В этом сценарии поступает challenge, а не SignedAttributes.
        /// Возврат CMS, созданной по messageDigest, нельзя считать эквивалентом
        /// сырой подписи challenge. До согласования протокола проверки с Directum
        /// аутентификацию намеренно не выполняем.
        /// </summary>
        public static int SignData(string pluginName, string[] certificatesThumbprints,
            string signingData, string[] certificatesProperties, string userLanguage,
            out string result)
        {
            result = "Аутентификация по сертификату через IIT в этом плагине пока не поддерживается.";
            Logger.Error("IIT: вызов SignData для аутентификации (2FA) не поддерживается.");
            return (int)SignDataResult.UnknownError;
        }

        /// <summary>Извлечь хеш документа из SignedAttributes (CMS messageDigest).</summary>
        private static byte[] GetDocumentHashFromSigningAttributes(byte[] encodedSignedAttributes)
        {
            var attributesSet = Asn1Object.FromByteArray(encodedSignedAttributes) as Asn1Set;
            if (attributesSet == null)
                throw new InvalidOperationException("Получены некорректные SignedAttributes.");

            return GetMessageDigest(new AttributeTable(attributesSet));
        }

        private static byte[] GetMessageDigest(AttributeTable attributes)
        {
            var digestAttribute = attributes.Get(PkcsObjectIdentifiers.Pkcs9AtMessageDigest);
            if (digestAttribute == null || digestAttribute.AttrValues.Count != 1)
                throw new InvalidOperationException("В SignedAttributes отсутствует messageDigest.");

            var digest = digestAttribute.AttrValues[0] as Asn1OctetString;
            if (digest == null)
                throw new InvalidOperationException("В SignedAttributes некорректный messageDigest.");

            return digest.GetOctets();
        }

        /// <summary>Инициализация IIT и применение настроек один раз на процесс WebAgent.</summary>
        private static void InitializeIit(IEUSignCP.EU_LANG language)
        {
            // Все вызовы находятся под SyncRoot: IIT использует глобальное состояние.
            if (!IEUSignCP.IsInitialized())
            {
                IEUSignCP.SetUIMode(true);
                ThrowIfIitError(IEUSignCP.Initialize(), "Инициализация IIT", language);
                iitConfigured = false;
                loadedKeyThumbprint = null;
            }

            IEUSignCP.SetUIMode(true);
            if (iitConfigured)
                return;

            var settings = IitSettings.Load();

            IEUSignCP.SetOCSPSettings(true, false, settings.OcspAddress, "80");
            IEUSignCP.SetTSPSettings(true, settings.TspAddress, "80");
            IEUSignCP.SetCMPSettings(settings.UseCmp, settings.CmpAddress, settings.CmpPort, "");
            ApplyProxySettings(settings);
            IEUSignCP.SetLDAPSettings(false, "", "", false, "", "");
            IEUSignCP.SetFileStoreSettings(settings.CertFolderPath,
                false, true, false, false, true, true, 3600);
            IEUSignCP.SetRuntimeParameter(IEUSignCP.EU_FS_CALCULATE_FINGERPRINT, true);
            IEUSignCP.SetModeSettings(settings.IsOfflineMode);

            activeSettings = settings;
            iitConfigured = true;
            Logger.Info("IIT: инициализация настроек завершена. " +
                $"Режим offline={settings.IsOfflineMode}, Proxy={settings.UseProxy}.");
        }

        /// <summary>Запросить ключ через диалог IIT или использовать ранее выбранный.</summary>
        private static string EnsurePrivateKeyLoaded(IEUSignCP.EU_LANG language)
        {
            if (IEUSignCP.IsPrivateKeyReaded() && !string.IsNullOrWhiteSpace(loadedKeyThumbprint))
                return loadedKeyThumbprint;

            // Ключ мог быть загружен другим компонентом: без подтверждения отпечатка
            // использовать его нельзя.
            if (IEUSignCP.IsPrivateKeyReaded())
                ResetPrivateKey();

            IEUSignCP.EU_KEY_MEDIA media;
            var error = IEUSignCP.GetPrivatekeyMedia(out media);
            ThrowIfIitError(error, "Выбор носителя закрытого ключа", language);

            IEUSignCP.EU_CERT_OWNER_INFO owner;
            IEUSignCP.SetUIMode(false);
            try
            {
                error = IEUSignCP.ReadPrivateKey(media, out owner);
            }
            finally
            {
                IEUSignCP.SetUIMode(true);
            }

            if (error != IEUSignCP.EU_ERROR_NONE)
            {
                ResetPrivateKey();
                ThrowIfIitError(error, "Чтение закрытого ключа", language);
            }

            IEUSignCP.EU_CERT_INFO_EX certInfo;
            error = IEUSignCP.GetCertificateInfoEx(owner.issuer, owner.serial, out certInfo);
            if (error != IEUSignCP.EU_ERROR_NONE)
            {
                ResetPrivateKey();
                ThrowIfIitError(error, "Чтение сертификата выбранного ключа", language);
            }

            if (string.IsNullOrWhiteSpace(certInfo.fingerprint))
            {
                ResetPrivateKey();
                throw new InvalidOperationException("Не удалось получить отпечаток сертификата IIT.");
            }

            loadedKeyThumbprint = certInfo.fingerprint;
            Logger.Info("IIT: закрытый ключ загружен, сертификат: " + loadedKeyThumbprint);
            return loadedKeyThumbprint;
        }

        private static void ResetPrivateKey()
        {
            IEUSignCP.ResetPrivateKey();
            loadedKeyThumbprint = null;
        }

        private static void ApplyProxySettings(IitSettings settings)
        {
            if (settings.UseProxy)
                IEUSignCP.SetProxySettings(true, settings.ProxyAnonymous,
                    settings.ProxyAddress, settings.ProxyPort,
                    settings.ProxyUser, settings.ProxyPassword, settings.ProxySavePassword);
            else
                IEUSignCP.SetProxySettings(false, false, "", "", "", "", false);
        }

        private static IEUSignCP.EU_LANG GetIitLanguage(string userLanguage)
        {
            switch (userLanguage)
            {
                case "uk-UA": return IEUSignCP.EU_LANG.UA;
                case "ru-RU": return IEUSignCP.EU_LANG.RU;
                case "en-US": return IEUSignCP.EU_LANG.EN;
                case "en-GB": return IEUSignCP.EU_LANG.EN;
                default: return IEUSignCP.EU_LANG.DEFAULT;
            }
        }

        private static void ThrowIfIitError(int error, string operation, IEUSignCP.EU_LANG language)
        {
            if (error == IEUSignCP.EU_ERROR_NONE)
                return;

            string message;
            try { message = IEUSignCP.GetErrorLangDesc(error, language); }
            catch { message = "Описание ошибки IIT недоступно"; }
            throw new InvalidOperationException($"{operation}: код {error}. {message}");
        }

        private static bool ThumbprintsEqual(string a, string b)
        {
            return string.Equals(NormalizeThumbprint(a), NormalizeThumbprint(b),
                StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizeThumbprint(string thumbprint)
        {
            if (thumbprint == null)
                return string.Empty;
            return new string(thumbprint.Where(c => !char.IsWhiteSpace(c) &&
                c != ':' && c != '-' && c != '\u200e' && c != '\u200f').ToArray());
        }

        private sealed class SigningException : Exception
        {
            public SignDataResult ResultCode { get; }
            public SigningException(SignDataResult resultCode, string message) : base(message)
            {
                ResultCode = resultCode;
            }
        }

        /// <summary>
        /// Настройки из Settings.json, расположенного рядом с DLL клиентского плагина.
        /// В отличие от серверного плагина, WebAgent не вызывает ApplySettings(config.yml).
        /// </summary>
        private sealed class IitSettings
        {
            public string CertFolderPath { get; private set; }
            public bool UseProxy { get; private set; }
            public bool ProxyAnonymous { get; private set; }
            public string ProxyAddress { get; private set; }
            public string ProxyPort { get; private set; }
            public string ProxyUser { get; private set; }
            public string ProxyPassword { get; private set; }
            public bool ProxySavePassword { get; private set; }
            public string OcspAddress { get; private set; }
            public string TspAddress { get; private set; }
            public bool UseCmp { get; private set; }
            public string CmpAddress { get; private set; }
            public string CmpPort { get; private set; }
            public bool IsOfflineMode { get; private set; }

            public static IitSettings Load()
            {
                var dllFolder = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                var settingsPath = Path.Combine(dllFolder, "Settings.json");
                if (!File.Exists(settingsPath))
                    throw new FileNotFoundException(
                        "Не найден клиентский Settings.json для IIT. " + settingsPath, settingsPath);

                var root = JObject.Parse(File.ReadAllText(settingsPath));
                var config = new IitSettings
                {
                    CertFolderPath = Value(root, "CertFolderPath"),
                    UseProxy = Bool(root, "Proxy_useProxy"),
                    ProxyAnonymous = Bool(root, "Proxy_anonymous"),
                    ProxyAddress = Value(root, "Proxy_address"),
                    ProxyPort = Value(root, "Proxy_port"),
                    ProxyUser = Value(root, "Proxy_user"),
                    ProxyPassword = Value(root, "Proxy_pass"),
                    ProxySavePassword = Bool(root, "Proxy_savepass"),
                    OcspAddress = Value(root, "OCSP_address"),
                    TspAddress = Value(root, "TSP_address"),
                    UseCmp = Bool(root, "CMP_useCMP"),
                    CmpAddress = Value(root, "CMP_address"),
                    CmpPort = Value(root, "CMP_port"),
                    IsOfflineMode = Bool(root, "IsOfflineMode")
                };

                if (string.IsNullOrWhiteSpace(config.CertFolderPath))
                    throw new InvalidOperationException("В Settings.json не заполнен CertFolderPath.");
                if (config.UseProxy && (string.IsNullOrWhiteSpace(config.ProxyAddress) ||
                                        string.IsNullOrWhiteSpace(config.ProxyPort)))
                    throw new InvalidOperationException(
                        "В Settings.json для включенного Proxy обязательны Proxy_address и Proxy_port.");
                if (config.UseCmp && (string.IsNullOrWhiteSpace(config.CmpAddress) ||
                                      string.IsNullOrWhiteSpace(config.CmpPort)))
                    throw new InvalidOperationException(
                        "В Settings.json для включенного CMP обязательны CMP_address и CMP_port.");

                return config;
            }

            private static string Value(JObject root, string name)
            {
                var token = root[name];
                return token == null || token.Type == JTokenType.Null ? string.Empty : token.ToString();
            }

            private static bool Bool(JObject root, string name)
            {
                var value = Value(root, name);
                if (string.IsNullOrWhiteSpace(value))
                    return false;
                bool parsed;
                if (!bool.TryParse(value, out parsed))
                    throw new InvalidOperationException(
                        $"Неверное значение {name} в Settings.json: ожидается true/false.");
                return parsed;
            }
        }
    }
}
