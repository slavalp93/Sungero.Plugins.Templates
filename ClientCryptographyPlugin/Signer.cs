using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Linq;
using System.Reflection;
using EUSignCP;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;

namespace Library
{
    /// <summary>
    /// Клиентское подписание через IIT для Directum RX 3.3.8.
    /// </summary>
    public static class Signer
    {
        private static readonly object SyncRoot = new object();

        private static string JSONSettings = File.ReadAllText(
            Path.Combine(
                Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location),
                @"Settings.json"));

        // Папка хранилища сертификатов.
        public static string CertFolderPath =
            JObject.Parse(JSONSettings)["CertFolderPath"].ToString();

        // Параметры Proxy.
        public static string proxy_useProxy =
            JObject.Parse(JSONSettings)["Proxy_useProxy"].ToString();

        public static string proxy_anonymous =
            JObject.Parse(JSONSettings)["Proxy_anonymous"].ToString();

        public static string proxy_address =
            JObject.Parse(JSONSettings)["Proxy_address"].ToString();

        public static string proxy_port =
            JObject.Parse(JSONSettings)["Proxy_port"].ToString();

        public static string proxy_user =
            JObject.Parse(JSONSettings)["Proxy_user"].ToString();

        public static string proxy_pass =
            JObject.Parse(JSONSettings)["Proxy_pass"].ToString();

        public static string proxy_savepass =
            JObject.Parse(JSONSettings)["Proxy_savepass"].ToString();

        // Параметры OCSP и TSP.
        public static string ocsp_address =
            JObject.Parse(JSONSettings)["OCSP_address"].ToString();

        public static string tsp_address =
            JObject.Parse(JSONSettings)["TSP_address"].ToString();

        // Параметры CMP.
        public static string cmp_useCMP =
            JObject.Parse(JSONSettings)["CMP_useCMP"].ToString();

        public static string cmp_address =
            JObject.Parse(JSONSettings)["CMP_address"].ToString();

        public static string cmp_port =
            JObject.Parse(JSONSettings)["CMP_port"].ToString();

        // false — работа с серверами ЦСК в онлайн-режиме.
        public static string isOfflineMode =
            JObject.Parse(JSONSettings)["IsOfflineMode"].ToString();

        // Ответ клиентскому приложению.
        private static Response response = new Response();

        // Язык клиентского приложения.
        public static string clientLanguage;

        // Отпечаток сертификата загруженного ключа.
        public static string certFingerprint;

        [System.Runtime.InteropServices.DllImport(
            "user32.dll",
            EntryPoint = "MessageBoxW",
            CharSet = System.Runtime.InteropServices.CharSet.Unicode,
            ExactSpelling = true,
            SetLastError = true)]
        private static extern int ShowNativeMessageBox(
            IntPtr hWnd,
            string text,
            string caption,
            uint type);

        /// <summary>
        /// Вычисление хеша.
        /// </summary>
        private static int HashData(
            byte[] data,
            int certKeyType,
            out byte[] hash)
        {
            byte[] certificate = null;
            IntPtr context = IntPtr.Zero;
            int hashAlgo = IEUSignCP.EU_CTX_HASH_ALGO_GOST34311;
            int error;

            hash = null;

            error = IEUSignCP.CtxCreate(out context);
            if (error != IEUSignCP.EU_ERROR_NONE)
                return error;

            error = IEUSignCP.CtxHashData(
                context, hashAlgo, certificate, data, out hash);

            if (error != IEUSignCP.EU_ERROR_NONE)
            {
                IEUSignCP.CtxFree(context);
                return error;
            }

            IEUSignCP.CtxFree(context);
            return IEUSignCP.EU_ERROR_NONE;
        }

        /// <summary>
        /// Получить "сырую" подпись из подписи формата CMS.
        /// </summary>
        private static byte[] GetRawSignatureFromCMSSignature(
            byte[] cmsSignature)
        {
            return new CmsSignedData(cmsSignature)
                .GetSignerInfos()
                .GetSigners()
                .OfType<SignerInformation>()
                .Single(si => si.SignedAttributes != null)
                .GetSignature();
        }

        /// <summary>
        /// Получить хеш документа из сериализованных SigningAttributes.
        /// </summary>
        private static byte[] GetDocumentHashFromSigningAttributes(
            byte[] encodedSigningAttributes)
        {
            var attributesSet =
                (Asn1Set)Asn1Object.FromByteArray(encodedSigningAttributes);

            var attributeTable = new AttributeTable(attributesSet);
            var attributeDictionary = attributeTable.ToDictionary();

            return ((DerOctetString)
                ((Org.BouncyCastle.Asn1.Cms.Attribute)
                    attributeDictionary[PkcsObjectIdentifiers.Pkcs9AtMessageDigest])
                .AttrValues[0]).GetOctets();
        }

        /// <summary>
        /// Установка параметров прокси.
        /// </summary>
        private static void SetProxySettings()
        {
            bool proxySettingsIsCorrect = true;

            if (!Boolean.TryParse(proxy_useProxy, out bool useProxy))
            {
                Logger.Error(
                    "Неверный параметр в settings.json: Proxy_useProxy. " +
                    "Доступные значения: true, false");

                proxySettingsIsCorrect = false;
            }

            if (useProxy)
            {
                if (!Boolean.TryParse(proxy_anonymous, out bool anonymous))
                {
                    Logger.Error(
                        "Неверный параметр в settings.json: Proxy_anonymous. " +
                        "Доступные значения: true, false");

                    proxySettingsIsCorrect = false;
                }

                if (string.IsNullOrEmpty(proxy_address))
                {
                    Logger.Error(
                        "Неверный параметр в settings.json: Proxy_address");

                    proxySettingsIsCorrect = false;
                }

                if (string.IsNullOrEmpty(proxy_port))
                {
                    Logger.Error(
                        "Неверный параметр в settings.json: Proxy_port");

                    proxySettingsIsCorrect = false;
                }

                if (!Boolean.TryParse(proxy_savepass, out bool savepass))
                {
                    Logger.Error(
                        "Неверный параметр в settings.json: Proxy_savepass. " +
                        "Доступные значения: true, false");

                    proxySettingsIsCorrect = false;
                }

                if (proxySettingsIsCorrect)
                {
                    IEUSignCP.SetProxySettings(
                        useProxy,
                        anonymous,
                        proxy_address,
                        proxy_port,
                        proxy_user,
                        proxy_pass,
                        savepass);
                }
                else
                {
                    IEUSignCP.SetProxySettings(
                        false, false, "", "", "", "", false);
                }
            }
            else
            {
                IEUSignCP.SetProxySettings(
                    false, false, "", "", "", "", false);
            }
        }

        /// <summary>
        /// Подписание IIT.
        /// </summary>
        /// <param name="documentHash">Хеш для подписи в Base64.</param>
        /// <param name="fingerprint">Отпечаток сертификата из системы.</param>
        private static void IITSigning(string documentHash, string fingerprint)
        {
            Logger.Info("Подписываем ИИТ-ом");

            var currentLanguage = GetIitLanguage(clientLanguage);

            int error;

            if (!IEUSignCP.IsInitialized())
            {
                certFingerprint = string.Empty;

                IEUSignCP.SetUIMode(true);
                error = IEUSignCP.Initialize();

                if (error != IEUSignCP.EU_ERROR_NONE)
                {
                    SetIitError(error, "Ошибка при инициализации библиотеки", currentLanguage);
                    return;
                }

                IEUSignCP.SetUIMode(true);

                Logger.Info("Устанавливаем значения параметров библиотеки ИИТ.");

                // Параметры OCSP.
                IEUSignCP.SetOCSPSettings(
                    true, false, ocsp_address, "80");

                // Параметры TSP.
                IEUSignCP.SetTSPSettings(
                    true, tsp_address, "80");

                // Параметры CMP.
                if (!Boolean.TryParse(cmp_useCMP, out bool useCMP))
                {
                    Logger.Error(
                        "Неверный параметр в settings.json: CMP_useCMP. " +
                        "Доступные значения: true, false");
                }

                IEUSignCP.SetCMPSettings(
                    useCMP, cmp_address, cmp_port, "");

                SetProxySettings();

                // Параметры LDAP.
                IEUSignCP.SetLDAPSettings(
                    false, "", "", false, "", "");

                // Параметры файлового хранилища.
                IEUSignCP.SetFileStoreSettings(
                    CertFolderPath,
                    false,
                    true,
                    false,
                    false,
                    true,
                    true,
                    3600);

                // Возможность получения отпечатка сертификата.
                IEUSignCP.SetRuntimeParameter(
                    IEUSignCP.EU_FS_CALCULATE_FINGERPRINT,
                    true);

                // Проверка параметров хранилища сертификатов.
                error = IEUSignCP.GetFileStoreSettings(
                    out string path,
                    out bool checkCRLs,
                    out bool autoRefresh,
                    out bool ownCRLsOnly,
                    out bool fullAndDeltaCRLs,
                    out bool autoDownloadCRLs,
                    out bool saveLoadedCerts,
                    out int expireTime);

                if (error != IEUSignCP.EU_ERROR_NONE)
                {
                    Logger.Error(string.Format(
                        "Ошибка при получении параметров хранилища сертификатов: " +
                        "Код:{0}. Описание:{1}",
                        error,
                        IEUSignCP.GetErrorLangDesc(error, currentLanguage)));
                }
                else
                {
                    Logger.Info(string.Format(
                        "Папка хранилища сертификатов: {0}", path));
                }

                // Проверка параметров Proxy.
                error = IEUSignCP.GetProxySettings(
                    out bool useProxy_,
                    out bool anonymous_,
                    out string address_,
                    out string port_,
                    out string user_,
                    out string password_,
                    out bool savePassword_);

                if (error != IEUSignCP.EU_ERROR_NONE)
                {
                    Logger.Error(string.Format(
                        "Ошибка при получении параметров использования Proxy: " +
                        "Код:{0}. Описание:{1}",
                        error,
                        IEUSignCP.GetErrorLangDesc(error, currentLanguage)));
                }
                else
                {
                    Logger.Info(string.Format(
                        "Параметры Proxy: useProxy:{0}, anonymous:{1}, " +
                        "address:{2}, port:{3}, user:{4}, savePassword:{5}",
                        useProxy_,
                        anonymous_,
                        address_,
                        port_,
                        user_,
                        savePassword_));
                }

                // Проверка параметров OCSP.
                error = IEUSignCP.GetOCSPSettings(
                    out bool useOCSP_,
                    out bool ocsp_beforeStore_,
                    out string ocsp_address_,
                    out string ocsp_port_);

                if (error != IEUSignCP.EU_ERROR_NONE)
                {
                    Logger.Error(string.Format(
                        "Ошибка при получении параметров использования OCSP: " +
                        "Код:{0}. Описание:{1}",
                        error,
                        IEUSignCP.GetErrorLangDesc(error, currentLanguage)));
                }
                else
                {
                    Logger.Info(string.Format(
                        "Параметры OCSP: useOCSP:{0}, beforeStore:{1}, " +
                        "address:{2}, port:{3}",
                        useOCSP_,
                        ocsp_beforeStore_,
                        ocsp_address_,
                        ocsp_port_));
                }

                // Проверка параметров TSP.
                error = IEUSignCP.GetTSPSettings(
                    out bool getStamps_,
                    out string tsp_address_,
                    out string tsp_port_);

                if (error != IEUSignCP.EU_ERROR_NONE)
                {
                    Logger.Error(string.Format(
                        "Ошибка при получении параметров использования TSP: " +
                        "Код:{0}. Описание:{1}",
                        error,
                        IEUSignCP.GetErrorLangDesc(error, currentLanguage)));
                }
                else
                {
                    Logger.Info(string.Format(
                        "Параметры TSP: getStamps:{0}, address:{1}, port:{2}",
                        getStamps_,
                        tsp_address_,
                        tsp_port_));
                }

                // Проверка параметров CMP.
                error = IEUSignCP.GetCMPSettings(
                    out bool cmp_useCMP_,
                    out string cmp_adress_,
                    out string cmp_port_,
                    out string cmp_ommonName_);

                if (error != IEUSignCP.EU_ERROR_NONE)
                {
                    Logger.Error(string.Format(
                        "Ошибка при получении параметров использования CMP: " +
                        "Код:{0}. Описание:{1}",
                        error,
                        IEUSignCP.GetErrorLangDesc(error, currentLanguage)));
                }
                else
                {
                    Logger.Info(string.Format(
                        "Параметры CMP: useCMP:{0}, address:{1}, " +
                        "port:{2}, commonName:{3}",
                        cmp_useCMP_,
                        cmp_adress_,
                        cmp_port_,
                        cmp_ommonName_));
                }

                // Режим работы с серверами ЦСК.
                if (!Boolean.TryParse(isOfflineMode, out bool offlineMode))
                {
                    Logger.Error(
                        "Неверный параметр в settings.json: isOfflineMode. " +
                        "Доступные значения: true, false");

                    offlineMode = false;
                }

                Logger.Info(
                    offlineMode
                        ? "Режим работы с серверами ЦСК: off-line"
                        : "Режим работы с серверами ЦСК: on-line");

                IEUSignCP.SetModeSettings(offlineMode);

                Logger.Info("Инициализировано библиотеку...");
            }

            IEUSignCP.SetUIMode(true);

            // Подписание продолжается только после выбора подходящего ключа.
            if (!EnsurePrivateKeyMatchesCertificate(currentLanguage, fingerprint, clientLanguage))
            {
                return;
            }

            byte[] cmsSignature;

            // Повторно устанавливаем параметры прокси перед подписанием.
            SetProxySettings();

            error = IEUSignCP.SignHash(documentHash, out cmsSignature);

            if (error != IEUSignCP.EU_ERROR_NONE)
            {
                ResetPrivateKey();

                SetIitError(
                    error,
                    "Ошибка при подписании хеша",
                    currentLanguage);

                return;
            }

            if (cmsSignature == null || cmsSignature.Length == 0)
                throw new InvalidOperationException("IIT вернул пустую CMS-подпись.");

            Logger.Info("Хеш успешно подписан");
            Logger.Info("Возвращаем CMS подпись от ИИТ в директум");

            response.Result = CertificateLoadPrivateKeyResult.Success;
            response.Error = null;
            response.SetSignature(cmsSignature);
        }

        /// <summary>
        /// Запросить ключ, соответствующий сертификату из Directum RX.
        /// </summary>
        private static bool EnsurePrivateKeyMatchesCertificate(
            IEUSignCP.EU_LANG language,
            string expectedThumbprint,
            string userLanguage)
        {
            const uint MB_OK = 0x00000000;
            const uint MB_ICONWARNING = 0x00000030;
            const uint MB_SETFOREGROUND = 0x00010000;
            const uint MB_TOPMOST = 0x00040000;

            while (true)
            {
                if (!EnsurePrivateKeyLoaded(language))
                    return false;

                if (ThumbprintsEqual(certFingerprint, expectedThumbprint))
                    return true;

                Logger.Info(string.Format(
                    "Сертификат ключа не соответствует сертификату Directum RX. " +
                    "Сертификат ключа: {0}; сертификат Directum RX: {1}. " +
                    "Запрашивается другой ключ.",
                    certFingerprint,
                    expectedThumbprint));

                ResetPrivateKey();

                string message;
                string caption;
                string dialogError;

                GetCertificateMismatchTexts(
                    userLanguage,
                    out message,
                    out caption,
                    out dialogError);

                int dialogResult = ShowNativeMessageBox(
                    IntPtr.Zero,
                    message,
                    caption,
                    MB_OK | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);

                if (dialogResult == 0)
                {
                    throw new System.ComponentModel.Win32Exception(
                        System.Runtime.InteropServices.Marshal.GetLastWin32Error(),
                        dialogError);
                }
            }
        }

        /// <summary>
        /// Использовать ранее загруженный ключ или запросить новый через IIT.
        /// </summary>
        private static bool EnsurePrivateKeyLoaded(
            IEUSignCP.EU_LANG language)
        {
            if (IEUSignCP.IsPrivateKeyReaded() &&
                !string.IsNullOrWhiteSpace(certFingerprint))
            {
                return true;
            }

            // Не используем ключ, для которого неизвестен отпечаток.
            if (IEUSignCP.IsPrivateKeyReaded())
                ResetPrivateKey();

            certFingerprint = string.Empty;

            IEUSignCP.SetUIMode(true);

            IEUSignCP.EU_KEY_MEDIA keyMedia;
            int error = IEUSignCP.GetPrivatekeyMedia(out keyMedia);

            if (error != IEUSignCP.EU_ERROR_NONE)
            {
                SetIitError(
                    error,
                    "Ошибка при определении параметров приватного ключа",
                    language);

                return false;
            }

            IEUSignCP.EU_CERT_OWNER_INFO certOwnerInfo;

            // Чтение ключа с отключённым графическим модулем IIT.
            IEUSignCP.SetUIMode(false);

            try
            {
                error = IEUSignCP.ReadPrivateKey(
                    keyMedia, out certOwnerInfo);
            }
            finally
            {
                IEUSignCP.SetUIMode(true);
            }

            if (error != IEUSignCP.EU_ERROR_NONE)
            {
                ResetPrivateKey();

                SetIitError(
                    error,
                    "Ошибка при считывании приватного ключа",
                    language);

                return false;
            }

            Logger.Info("Приватный ключ успешно считан...");

            IEUSignCP.EU_CERT_INFO_EX certInfoEx;

            error = IEUSignCP.GetCertificateInfoEx(
                certOwnerInfo.issuer,
                certOwnerInfo.serial,
                out certInfoEx);

            if (error != IEUSignCP.EU_ERROR_NONE)
            {
                ResetPrivateKey();

                SetIitError(
                    error,
                    "Ошибка при получении расширенной информации о сертификате",
                    language);

                return false;
            }

            if (string.IsNullOrWhiteSpace(certInfoEx.fingerprint))
            {
                ResetPrivateKey();

                throw new InvalidOperationException(
                    "Не удалось получить отпечаток сертификата IIT.");
            }

            certFingerprint = certInfoEx.fingerprint;
            return true;
        }

        private static void ResetPrivateKey()
        {
            try
            {
                IEUSignCP.ResetPrivateKey();
            }
            finally
            {
                certFingerprint = string.Empty;
            }
        }

        private static void SetIitError(
            int error,
            string operation,
            IEUSignCP.EU_LANG language)
        {
            string message = IEUSignCP.GetErrorLangDesc(error, language);

            Logger.Error(string.Format(
                "{0}: Код:{1}. Описание:{2}",
                operation,
                error,
                message));

            response.Result = CertificateLoadPrivateKeyResult.UnknownError;
            response.Error = message;
        }

        private static IEUSignCP.EU_LANG GetIitLanguage(string userLanguage)
        {
            switch (userLanguage)
            {
                case "uk-UA":
                    return IEUSignCP.EU_LANG.UA;

                case "ru-RU":
                    return IEUSignCP.EU_LANG.RU;

                case "en-US":
                case "en-GB":
                    return IEUSignCP.EU_LANG.EN;

                default:
                    return IEUSignCP.EU_LANG.DEFAULT;
            }
        }

        private static bool ThumbprintsEqual(string a, string b)
        {
            return string.Equals(
                NormalizeThumbprint(a),
                NormalizeThumbprint(b),
                StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizeThumbprint(string thumbprint)
        {
            if (thumbprint == null)
                return string.Empty;

            return new string(
                thumbprint.Where(c =>
                    !char.IsWhiteSpace(c) &&
                    c != ':' &&
                    c != '-' &&
                    c != '\u200e' &&
                    c != '\u200f')
                .ToArray());
        }

        private static void GetCertificateMismatchTexts(
            string userLanguage,
            out string message,
            out string caption,
            out string dialogError)
        {
            var language = (userLanguage ?? string.Empty)
                .Trim()
                .Replace('_', '-')
                .Split('-')[0]
                .ToLowerInvariant();

            switch (language)
            {
                case "ru":
                    message =
                        "Сертификат ключа не соответствует сертификату, " +
                        "выбранному в Directum RX.\r\n\r\n" +
                        "В следующем окне выберите другой ключ.\r\n" +
                        "Чтобы прекратить подписание, отмените выбор ключа.";

                    caption = "Подписание Directum RX";

                    dialogError =
                        "Не удалось показать предупреждение о несовпадении сертификатов.";
                    break;

                case "uk":
                    message =
                        "Сертифікат ключа не відповідає сертифікату, " +
                        "обраному в Directum RX.\r\n\r\n" +
                        "У наступному вікні виберіть інший ключ.\r\n" +
                        "Щоб припинити підписання, скасуйте вибір ключа.";

                    caption = "Підписання Directum RX";

                    dialogError =
                        "Не вдалося показати попередження про невідповідність сертифікатів.";
                    break;

                default:
                    message =
                        "The certificate of the selected key does not match the certificate " +
                        "selected in Directum RX.\r\n\r\n" +
                        "Select a different key in the next window.\r\n" +
                        "To stop signing, cancel key selection.";

                    caption = "Directum RX signing";

                    dialogError =
                        "Unable to display the certificate mismatch warning.";
                    break;
            }
        }

        /// <summary>
        /// Подписать данные. Контракт клиентского плагина Directum RX 3.3.8.
        /// </summary>
        public static string SignData(string requestString)
        {
            // IIT и поля класса используют общее состояние.
            lock (SyncRoot)
            {
                // Исключаем перенос результата предыдущего подписания.
                response = new Response();
                clientLanguage = null;

                try
                {
                    var requestObj = JsonConvert.DeserializeObject<Request>(requestString);

                    if (requestObj == null)
                    {
                        throw new InvalidOperationException("Не передан запрос на подписание.");
                    }

                    Logger.Info(string.Format(
                        "Start signing. PluginName: {0} CertificateID: {1}. Language: {2}.",
                        requestObj.PluginName,
                        requestObj.CertificateID,
                        requestObj.Language));

                    clientLanguage = requestObj.Language;

                    if (string.IsNullOrWhiteSpace(NormalizeThumbprint(requestObj.CertificateID)))
                    {
                        response.Result = CertificateLoadPrivateKeyResult.IllegalCertificateID;

                        response.Error = "Не указан отпечаток сертификата подписания.";

                        Logger.Error(response.Error);

                        return JsonConvert.SerializeObject(
                            response, Formatting.None);
                    }

                    if (string.IsNullOrWhiteSpace(requestObj.Attributes))
                    {
                        throw new InvalidOperationException("Не переданы данные для подписания.");
                    }

                    var data = Convert.FromBase64String(requestObj.Attributes);

                    byte[] byteDocumentHash = GetDocumentHashFromSigningAttributes(data);

                    string documentHash = Convert.ToBase64String(byteDocumentHash);

                    IITSigning(documentHash, requestObj.CertificateID);
                }
                catch (Exception ex)
                {
                    // Создаём ответ без подписи даже при исключении
                    // во время формирования результата.
                    response = new Response
                    {
                        Result = CertificateLoadPrivateKeyResult.UnknownError,
                        Error = ex.Message
                    };

                    Logger.Error("Ошибка подписания IIT: " + ex);
                }

                return JsonConvert.SerializeObject(
                    response, Formatting.None);
            }
        }
    }
}