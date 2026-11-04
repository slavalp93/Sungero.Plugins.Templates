using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using EUSignCP;
//using NLog;

namespace CryptographyPlugin
{
    /// <summary>
    /// Алгоритм хеширования.
    /// </summary>
    public sealed class HashAlgorithmDSTU : HashAlgorithm
    {
        #region Поля и свойства
        
        /// <summary>
        /// Идентификатор алгоритма хеширования.
        /// </summary>
        /// IEUSignCP.EU_CTX_HASH_ALGO_GOST34311        
        internal const string AlgorithmId = "1.2.804.2.1.1.1.1.2.1";

        private MemoryStream dataStream;
        private bool isInitialized;
        private int error;
        private int hashAlgo = IEUSignCP.EU_CTX_HASH_ALGO_GOST34311;
        private byte[] hash;
        private IntPtr context = IntPtr.Zero;
        private byte[] certificate = null;

        //private static Logger logger = LogManager.GetCurrentClassLogger();

        #endregion

        /// <summary>
        /// Создать экземпляр класса алгоритма хеширования.
        /// </summary>
        public static new HashAlgorithmDSTU Create()
        {            
            return new HashAlgorithmDSTU();
        }

        /// <summary>
        /// Сбросить алгоритм хеширования в исходное состояние.
        /// </summary>
        public override void Initialize()
        {
            this.dataStream = new MemoryStream();
            this.isInitialized = true;                        
        }

        protected override void Dispose(bool disposing)
        {
            if (!disposing)
                return;

            this.dataStream?.Dispose();
            base.Dispose(true);
        }

        /// <summary>
        /// Хеширование ИИТ.
        /// </summary>
        /// <param name="data">Входные данные, для которых вычисляется хеш-код.</param>       
        private int HashData(byte[] data, out byte[] hash)
        {            
            hash = null;

            //logger.Debug("HashData_Начало...");
            //System.IO.File.WriteAllText(@"C:\inetpub\logs\ServerPluginLog.log", "HashData_Начало...");

            // Инициализация библиотек
            CryptographyPlugin.LibraryLoader.Instance.LoadLibraryIfNeed();

            error = IEUSignCP.CtxCreate(out context);
            if (error != IEUSignCP.EU_ERROR_NONE)
                return error;

            error = IEUSignCP.CtxHashData(context, hashAlgo, certificate, data, out hash);
            if (error != IEUSignCP.EU_ERROR_NONE)
            {
                IEUSignCP.CtxFree(context);
                return error;
            }

            IEUSignCP.CtxFree(context);
            return IEUSignCP.EU_ERROR_NONE;
        }

        /// <summary>
        /// Поблочное вычисление хеша.
        /// </summary>
        /// <param name="array">Входные данные, для которых вычисляется хеш-код.</param>
        /// <param name="ibStart">Смещение в массиве байтов, начиная с которого следует использовать данные.</param>
        /// <param name="cbSize">Размер блока.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {           
            if (!this.isInitialized)
                this.Initialize();

            this.dataStream.Write(array, ibStart, cbSize);

            /*
            if (!this.isInitialized)
                this.Initialize();

            error = IEUSignCP.CtxHashDataContinue(hashContext, array);
            if (error != IEUSignCP.EU_ERROR_NONE)
            {
                IEUSignCP.CtxFreeHash(hashContext);
                IEUSignCP.Finalize();
                System.IO.File.WriteAllText(debugFileName, string.Format("Ошибка в CtxHashDataContinue: Код:{0}. Описание:{1}", error, IEUSignCP.GetErrorLangDesc(error, IEUSignCP.EU_LANG.RU)));
                //throw new NotImplementedException();
            }
            */
        }

        /// <summary>
        /// Завершить вычисление хеша.
        /// </summary>
        /// <returns>Вычисляемый хеш-код.</returns>
        /// <remarks>Этот метод завершает все частичные вычисления и возвращает правильное значение хеша для данных.</remarks>
        protected override byte[] HashFinal()
        {            
            // Получаем хеш                        
            var data = this.dataStream.Position > 0 ? this.dataStream.ToArray() : new byte[1];
            
            error = HashData(data, out hash);
            if (error != IEUSignCP.EU_ERROR_NONE)
            {                
                //logger.Error(string.Format("Ошибка при получении хеша: Код:{0}. Описание:{1}", error, IEUSignCP.GetErrorLangDesc(error, IEUSignCP.EU_LANG.RU)));
            }                                            

            return hash;                                   
        }        
    }
}
