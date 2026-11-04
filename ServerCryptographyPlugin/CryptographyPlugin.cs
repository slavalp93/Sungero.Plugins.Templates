using Sungero.Cryptography.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using EUSignCP;
using Org.BouncyCastle.Cms;

using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.IO;
//using System.Reflection;
//using NLog;

namespace CryptographyPlugin
{
    /// <summary>
    /// Плагин криптографии.
    /// </summary>
    public sealed class CryptographyPlugin : ICryptographyPlugin
    {
        #region Поля и свойства

        /// <summary>
        /// Идентификатор алгоритма подписания.
        /// </summary>
        private const string SignAlgorithmId = "1.2.804.2.1.1.1.1.3.1.1";
        private const string KyivstarSignAlgorithmId = "1.2.840.10045.2.1";


        /// <summary>
        /// Файл Settings.json с настройками плагина.
        /// </summary>        
        // В серверной части так не работает
        //private readonly string jsonSettings = File.ReadAllText(Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), @"Settings.json"));
        private static readonly string jsonSettings = File.ReadAllText(@"C:\inetpub\wwwroot\DrxPlugins\LitikoServerCryptographyPluginSettings.json");

        /// <summary>
        /// Папка хранилища сертификатов.
        /// </summary>         
        public static readonly string certFolderPath = JObject.Parse(jsonSettings)["CertFolderPath"].ToString();

        // Параметры Proxy:
        // Признак необхідності підключення до ЦСК через proxy-сервер
        public static string proxy_useProxy = JObject.Parse(jsonSettings)["Proxy_useProxy"].ToString();
        // Признак анонімного proxy-сервера
        public static string proxy_anonymous = JObject.Parse(jsonSettings)["Proxy_anonymous"].ToString();
        // ІР-адреса або DNS-ім’я proxy-сервера
        public static string proxy_address = JObject.Parse(jsonSettings)["Proxy_address"].ToString();
        // TCP-порт proxy-сервера
        public static string proxy_port = JObject.Parse(jsonSettings)["Proxy_port"].ToString();
        // Ім’я користувача proxy-сервера
        public static string proxy_user = JObject.Parse(jsonSettings)["Proxy_user"].ToString();
        // Пароль доступу користувача до proxy-сервера
        public static string proxy_pass = JObject.Parse(jsonSettings)["Proxy_pass"].ToString();
        // Признак зберігання пароля доступу до proxy-сервера
        public static string proxy_savepass = JObject.Parse(jsonSettings)["Proxy_savepass"].ToString();

        #endregion

        #region ICryptographyPlugin

        /// <summary>
        /// Идентификатор плагина (GUID).
        /// </summary>
        // TODO: Для каждого плагина подписания должен быть свой уникальный GUID. Данный идентификатор указан для примера и его следует поменять.
        // TODO: Идентификаторы серверного и клиентского плагинов должны совпадать, идентификатор клиентского плагина задается в файле ClientPlugin.targets.
        public Guid Id { get; } = Guid.Parse("bdf8266b-fd5e-4fe6-9f3e-ad67f360c053");

        /// <summary>
        /// Инициализация логирования.
        /// </summary>
        //public static Logger logger = LogManager.GetCurrentClassLogger();

        /// <summary>
        /// Применить настройки.
        /// </summary>
        /// <param name="settings">Настройки плагина.</param>
        public void ApplySettings(IReadOnlyDictionary<string, string> settings) { }

        /// <summary>
        /// Получить список дополнительных сертификатов для построения цепочки сертификатов.
        /// </summary>
        /// <param name="certificate">Сертификат.</param>
        /// <returns>Список дополнительных сертификатов для построения цепочки сертификатов.</returns>
        public IEnumerable<X509Certificate2> GetAdditionalCertificates(X509Certificate2 certificate)
        {
            return Enumerable.Empty<X509Certificate2>();
        }

        /// <summary>
        /// Получить идентификатор алгоритма хеширования по идентификатору алгоритма подписания.
        /// </summary>
        /// <param name="signAlgorithmId">Идентификатор алгоритма подписания.</param>
        /// <returns>Идентификатор алгоритма хеширования.</returns>
        public string GetHashAlgorithmIdBySignAlgorithmId(string signAlgorithmId)
        {
            if (!this.IsSignAlgorithmSupported(signAlgorithmId))
                throw new NotSupportedException();
            if (signAlgorithmId.Equals(SignAlgorithmId, StringComparison.OrdinalIgnoreCase))
                return HashAlgorithmDSTU.AlgorithmId;
            else if (signAlgorithmId.Equals(KyivstarSignAlgorithmId, StringComparison.OrdinalIgnoreCase))
                return HashAlgorithmKyivstar.AlgorithmId;
            else
                throw new NotSupportedException();
        }

        /// <summary>
        /// Получить обертку над алгоритмом хеширования.
        /// </summary>
        /// <param name="hashAlgorithmId">Идентификатор алгоритма хеширования.</param>
        /// <returns>Обертка над алгоритмом хеширования.</returns>
        public HashAlgorithmWrapper GetHashAlgorithmWrapperByHashAlgorithmId(string hashAlgorithmId)
        {
            if (!this.IsHashAlgorithmSupported(hashAlgorithmId))
                throw new NotSupportedException();

            if (hashAlgorithmId.Equals(HashAlgorithmDSTU.AlgorithmId, StringComparison.OrdinalIgnoreCase))
                return new HashAlgorithmWrapper(hashAlgorithmId, HashAlgorithmDSTU.Create);
            else if (hashAlgorithmId.Equals(HashAlgorithmKyivstar.AlgorithmId, StringComparison.OrdinalIgnoreCase))
                return new HashAlgorithmWrapper(hashAlgorithmId, HashAlgorithmKyivstar.Create);
            else
                throw new NotSupportedException();
        }

        /// <summary>
        /// Получить класс для подписания по идентификатору алгоритма подписания.
        /// </summary>
        /// <param name="signAlgorithmId">Идентификатор алгоритма подписания.</param>
        /// <returns>Класс для подписания.</returns>
        public ISigner GetSignerBySignAlgorithmId(string signAlgorithmId)
        {
            if (!this.IsSignAlgorithmSupported(signAlgorithmId))
                throw new NotSupportedException();

            return new Signer();
        }

        /// <summary>
        /// Проверить, поддерживается ли плагином данный алгоритм хеширования.
        /// </summary>
        /// <param name="hashAlgorithmId">Идентификатор алгоритма хеширования.</param>
        /// <returns>True, если алгоритм хеширования поддерживается плагином.</returns>
        public bool IsHashAlgorithmSupported(string hashAlgorithmId)
        {
            //System.IO.File.AppendAllText(@"C:\inetpub\logs\ServerPluginLog.log", string.Format("{0} IsHashAlgorithmSupported (hashAlgorithmId = {1})", DateTime.Now, hashAlgorithmId));
            return hashAlgorithmId.Equals(HashAlgorithmDSTU.AlgorithmId, StringComparison.OrdinalIgnoreCase) || 
                hashAlgorithmId.Equals(HashAlgorithmKyivstar.AlgorithmId, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Проверить, поддерживается ли плагином данный алгоритм подписания.
        /// </summary>
        /// <param name="signAlgorithmId">Идентификатор алгоритма подписания.</param>
        /// <returns>True, если алгоритм подписания поддерживается плагином.</returns>
        public bool IsSignAlgorithmSupported(string signAlgorithmId)
        {
            //System.IO.File.AppendAllText(@"C:\inetpub\logs\ServerPluginLog.log", string.Format("{0} IsSignAlgorithmSupported (signAlgorithmId = {1})", DateTime.Now, signAlgorithmId));
            return signAlgorithmId.Equals(SignAlgorithmId, StringComparison.OrdinalIgnoreCase) || signAlgorithmId.Equals(KyivstarSignAlgorithmId, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Выполнить проверку сертификата.
        /// </summary>
        /// <param name="certificate">Сертификат.</param>
        /// <returns>Список ошибок по итогам проверки сертификата.</returns>
        /// <remarks>Метод, реализующий дополнительную проверку сертификата.</remarks>
        public IEnumerable<string> ValidateCertificate(X509Certificate2 certificate)
        {
            return Enumerable.Empty<string>();
        }

        /// <summary>
        /// Получить хеш документа из CMS подписи (см. https://tools.ietf.org/html/rfc5652#section-5.3).
        /// </summary>
        /// <param name="dataSignature">CMS подпись.</param>
        /// <returns>Хеш документа.</returns>
        private static byte[] GetDocumentHashFromCMSSignature(byte[] dataSignature)
        {
            var signedAttributes = new CmsSignedData(dataSignature)
                .GetSignerInfos()
                .GetSigners()
                .OfType<SignerInformation>()
                .Single(si => si.SignedAttributes != null)
                .SignedAttributes;
            var attributeDictionary = signedAttributes.ToDictionary();
            return ((DerOctetString)((Org.BouncyCastle.Asn1.Cms.Attribute)attributeDictionary[PkcsObjectIdentifiers.Pkcs9AtMessageDigest]).AttrValues[0]).GetOctets();

        }

        /// <summary>
        /// Выполнить проверку подписи.
        /// </summary>
        /// <param name="dataSignature">Подпись.</param>
        /// <returns>Список ошибок по итогам проверки подписи.</returns>
        /// <remarks>Метод, реализующий дополнительную проверку подписи в формате CMS.</remarks>
        public IEnumerable<string> VerifySignature(byte[] dataSignature)
        {
            var errorList = new List<string>();

            var signedData = new CmsSignedData(dataSignature);
            if (signedData.SignedContentType.Equals(PkcsObjectIdentifiers.IdCTTstInfo))
            {
                return Enumerable.Empty<string>();
            }

            byte[] documentHash = GetDocumentHashFromCMSSignature(dataSignature);

            // Инициализация библиотек
            LibraryLoader.Instance.LoadLibraryIfNeed();

            IntPtr context = IntPtr.Zero;
            int error;

            // Создаем контекст
            error = IEUSignCP.CtxCreate(out context);
            if (error != IEUSignCP.EU_ERROR_NONE)
            {
                errorList.Add(string.Format("Ошибка проверки подписи (создание контекста криптобиблиотеки): Код:{0}. Описание:{1}", error, IEUSignCP.GetErrorLangDesc(error, IEUSignCP.EU_LANG.RU)));
            }
            else
            {
                error = IEUSignCP.CtxVerifyHashValue(context, documentHash, 0, dataSignature, out IEUSignCP.EU_SIGN_INFO signInfo);
                if (error != IEUSignCP.EU_ERROR_NONE)
                {
                    errorList.Add(string.Format("Ошибка проверки подписи: Код:{0}. Описание:{1}", error, IEUSignCP.GetErrorLangDesc(error, IEUSignCP.EU_LANG.RU)));
                }
                else
                {
                    // errorList.Add("Вроде ошибок нет...");
                }
                IEUSignCP.CtxFree(context);
            }

            // error = IEUSignCP.VerifyHash(documentHash, dataSignature, out IEUSignCP.EU_SIGN_INFO signInfo);            

            return errorList;
        }

        public IEnumerable<string> ValidateCertificate(X509Certificate2 certificate, DateTime verificationDateTime)
        {
            return Enumerable.Empty<string>();
        }

        /// <summary>
        /// Инициализация/выгрузка библиотек криптопровайдера.
        /// </summary>
        internal class LibraryLoader
        {
            private object lockObject = new object();

            private bool isLoaded;

            private static readonly Lazy<LibraryLoader> instance = new Lazy<LibraryLoader>(() => new LibraryLoader(), true);

            public static LibraryLoader Instance => instance.Value;

            public void LoadLibraryIfNeed()
            {
                if (!this.isLoaded)
                    lock (this.lockObject)
                    {
                        if (!this.isLoaded)
                        {
                            int error;
                            // Инициализация библиотеки
                            if (!IEUSignCP.IsInitialized())
                            {
                                IEUSignCP.SetUIMode(false);
                                error = IEUSignCP.Initialize();
                                if (error != IEUSignCP.EU_ERROR_NONE)
                                {
                                    //logger.Error(string.Format("Ошибка при инициализации библиотеки: Код:{0}. Описание:{1}", error, IEUSignCP.GetErrorLangDesc(error, IEUSignCP.EU_LANG.RU)));
                                }
                                else
                                {
                                    //logger.Debug("Инициализировано библиотеку");
                                }

                                // Отключение работы с GUI
                                IEUSignCP.SetUIMode(false);

                                // Вимкнення збереження налаштувань до реєстру
                                IEUSignCP.SetRuntimeParameter(IEUSignCP.EU_SAVE_SETTINGS_PARAMETER, IEUSignCP.EU_SETTINGS_ID_NONE);

                                // Встановлення параметрів OCSP-сервера                                
                                IEUSignCP.SetOCSPSettings(true, true, "", "80");

                                // Встановлення параметрів TSP-сервера
                                IEUSignCP.SetTSPSettings(true, "", "80");

                                // Встановлення параметрів Proxy-сервера
                                //IEUSignCP.SetProxySettings(false, false, "", "", "", "", false);
                                //IEUSignCP.SetProxySettings(true, true, "serverproxy.basf.net", "8080", "FinanceU", "Basfkiev2020", true);
                                //IEUSignCP.SetProxySettings(true, true, "192.168.254.49", "31281", "", "", false);

                                // Встановлення параметрів Proxy-сервера                        
                                bool proxySettingsIsCorrent = true;
                                if (!Boolean.TryParse(proxy_useProxy, out bool useProxy))
                                {
                                    //Logger.Error("Неверный параметр в settings.json: Proxy_useProxy. Доступные занчения: true, false");
                                    proxySettingsIsCorrent = false;
                                }

                                if (!Boolean.TryParse(proxy_anonymous, out bool anonymous))
                                {
                                    //Logger.Error("Неверный параметр в settings.json: Proxy_anonymous. Доступные занчения: true, false");
                                    proxySettingsIsCorrent = false;
                                }

                                if (string.IsNullOrEmpty(proxy_address))
                                {
                                    //Logger.Error("Неверный параметр в settings.json: Proxy_address");
                                    proxySettingsIsCorrent = false;
                                }

                                if (string.IsNullOrEmpty(proxy_port))
                                {
                                    //Logger.Error("Неверный параметр в settings.json: Proxy_port");
                                    proxySettingsIsCorrent = false;
                                }

                                if (!Boolean.TryParse(proxy_savepass, out bool savepass))
                                {
                                    //Logger.Error("Неверный параметр в settings.json: Proxy_savepass. Доступные занчения: true, false");
                                    proxySettingsIsCorrent = false;
                                }

                                if (proxySettingsIsCorrent)
                                    IEUSignCP.SetProxySettings(useProxy, anonymous, proxy_address, proxy_port, proxy_user, proxy_pass, savepass);
                                else
                                    IEUSignCP.SetProxySettings(false, false, "", "", "", "", false);

                                // Встановлення параметрів LDAP-сервера
                                IEUSignCP.SetLDAPSettings(false, "", "", false, "", "");

                                // Встановлення параметрів файлового сховища
                                IEUSignCP.SetFileStoreSettings(certFolderPath, false, true, false, false, true, true, 60);
                                //IEUSignCP.SetFileStoreSettings(@"C:\My Certificates and CRLs 13", false, true, false, false, true, true, 600);

                                // Режим работы с серверами ЦСК (false - значит работаем в онлайн режиме)
                                IEUSignCP.SetModeSettings(false);

                                this.isLoaded = true;

                                //System.IO.File.WriteAllText(@"C:\inetpub\logs\ServerPluginLog.log", "Инициализировано библиотеку");
                            }

                            // Проверка параметров Proxy - !!! Удалить !!!
                            error = IEUSignCP.GetProxySettings(out bool useProxy_, out bool anonymous_, out string address_, out string port_, out string user_, out string password_, out bool savePassword_);
                            if (error != IEUSignCP.EU_ERROR_NONE)
                            {
                                //Logger.Error(string.Format("Ошибка при получении параметров использования Proxy: Код:{0}. Описание:{1}", error, IEUSignCP.GetErrorLangDesc(error, IEUSignCP.EU_LANG.RU)));
                                System.IO.File.AppendAllText(@"C:\inetpub\logs\ServerPluginLog.log", string.Format("{2} Ошибка при получении параметров использования Proxy: Код:{0}. Описание:{1}", error, IEUSignCP.GetErrorLangDesc(error, IEUSignCP.EU_LANG.RU), DateTime.Now));
                            }
                            else
                            {
                                //Logger.Info(string.Format("Параметры Proxy: useProxy:{0}, anonymous:{1}, address:{2}, port:{3}, user:{4}, password:{5}, savePassword:{6}", useProxy_, anonymous_, address_, port_, user_, password_, savePassword_));
                                    
                            }
                        }
                    }
            }

            ~LibraryLoader()
            {
                if (this.isLoaded)
                {
                    IEUSignCP.Finalize();
                    //logger.Debug("Выгружено библиотеку");
                    //System.IO.File.WriteAllText(@"C:\inetpub\logs\ServerPluginLog.log", "Выгружено библиотеку");
                }
            }
        }
        #endregion
    }
}
