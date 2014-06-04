using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace UserDefworks
{
    public class UserDefworks
    {
        [ComImport]
        [Guid("0000000d-0000-0000-C000-000000000046")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        interface IEnumSTATSTG
        {
            // The user needs to allocate an STATSTG array whose size is celt.
            [PreserveSig]
            uint Next(
                uint celt,
                [MarshalAs(UnmanagedType.LPArray), Out]
			System.Runtime.InteropServices.ComTypes.STATSTG[] rgelt,
                out uint pceltFetched
            );
            void Skip(uint celt);
            void Reset();
            [return: MarshalAs(UnmanagedType.Interface)]
            IEnumSTATSTG Clone();
        }

        [ComImport]
        [Guid("0000000b-0000-0000-C000-000000000046")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        interface IStorage
        {
            void CreateStream(
                /* [string][in] */ string pwcsName,
                /* [in] */ uint grfMode,
                /* [in] */ uint reserved1,
                /* [in] */ uint reserved2,
                /* [out] */ out IStream ppstm);

            void OpenStream(
                /* [string][in] */ string pwcsName,
                /* [unique][in] */ IntPtr reserved1,
                /* [in] */ uint grfMode,
                /* [in] */ uint reserved2,
                /* [out] */ out IStream ppstm);

            void CreateStorage(
                /* [string][in] */ string pwcsName,
                /* [in] */ uint grfMode,
                /* [in] */ uint reserved1,
                /* [in] */ uint reserved2,
                /* [out] */ out IStorage ppstg);

            void OpenStorage(
                /* [string][unique][in] */ string pwcsName,
                /* [unique][in] */ IStorage pstgPriority,
                /* [in] */ uint grfMode,
                /* [unique][in] */ IntPtr snbExclude,
                /* [in] */ uint reserved,
                /* [out] */ out IStorage ppstg);

            void CopyTo(
                /* [in] */ uint ciidExclude,
                /* [size_is][unique][in] */ Guid rgiidExclude, // should this be an array?
                /* [unique][in] */ IntPtr snbExclude,
                /* [unique][in] */ IStorage pstgDest);

            void MoveElementTo(
                /* [string][in] */ string pwcsName,
                /* [unique][in] */ IStorage pstgDest,
                /* [string][in] */ string pwcsNewName,
                /* [in] */ uint grfFlags);

            void Commit(
                /* [in] */ uint grfCommitFlags);

            void Revert();

            //void Release();

            void EnumElements(
                /* [in] */ uint reserved1,
                /* [size_is][unique][in] */ IntPtr reserved2,
                /* [in] */ uint reserved3,
                /* [out] */ out IEnumSTATSTG ppenum);

            void DestroyElement(
                /* [string][in] */ string pwcsName);

            void RenameElement(
                /* [string][in] */ string pwcsOldName,
                /* [string][in] */ string pwcsNewName);

            void SetElementTimes(
                /* [string][unique][in] */ string pwcsName,
                /* [unique][in] */ System.Runtime.InteropServices.ComTypes.FILETIME pctime,
                /* [unique][in] */ System.Runtime.InteropServices.ComTypes.FILETIME patime,
                /* [unique][in] */ System.Runtime.InteropServices.ComTypes.FILETIME pmtime);

            void SetClass(
                /* [in] */ Guid clsid);

            void SetStateBits(
                /* [in] */ uint grfStateBits,
                /* [in] */ uint grfMask);

            void Stat(
                /* [out] */ out System.Runtime.InteropServices.ComTypes.STATSTG pstatstg,
                /* [in] */ uint grfStatFlag);

        }

        [Flags]
        private enum STGC : int
        {
            DEFAULT = 0,
            OVERWRITE = 1,
            ONLYIFCURRENT = 2,
            DANGEROUSLYCOMMITMERELYTODISKCACHE = 4,
            CONSOLIDATE = 8
        }

        [Flags]
        private enum STGM : int
        {
            DIRECT = 0x00000000,
            TRANSACTED = 0x00010000,
            SIMPLE = 0x08000000,
            READ = 0x00000000,
            WRITE = 0x00000001,
            READWRITE = 0x00000002,
            SHARE_DENY_NONE = 0x00000040,
            SHARE_DENY_READ = 0x00000030,
            SHARE_DENY_WRITE = 0x00000020,
            SHARE_EXCLUSIVE = 0x00000010,
            PRIORITY = 0x00040000,
            DELETEONRELEASE = 0x04000000,
            NOSCRATCH = 0x00100000,
            CREATE = 0x00001000,
            CONVERT = 0x00020000,
            FAILIFTHERE = 0x00000000,
            NOSNAPSHOT = 0x00200000,
            DIRECT_SWMR = 0x00400000,
        }

        [Flags]
        private enum STATFLAG : uint
        {
            STATFLAG_DEFAULT = 0,
            STATFLAG_NONAME = 1,
            STATFLAG_NOOPEN = 2
        }

        [Flags]
        private enum STGTY : int
        {
            STGTY_STORAGE = 1,
            STGTY_STREAM = 2,
            STGTY_LOCKBYTES = 3,
            STGTY_PROPERTY = 4
        }

        [DllImport("ole32.dll")]
        static extern int StgIsStorageFile(
            [MarshalAs(UnmanagedType.LPWStr)] string pwcsName);

        [DllImport("ole32.dll")]
        static extern int StgOpenStorage(
            [MarshalAs(UnmanagedType.LPWStr)] string pwcsName,
            IStorage pstgPriority,
            STGM grfMode,
            IntPtr snbExclude,
            uint reserved,
            out IStorage ppstgOpen);

        [DllImport("ole32.dll")]
        static extern int StgCreateDocfile(
            [MarshalAs(UnmanagedType.LPWStr)]string pwcsName,
            STGM grfMode,
            uint reserved,
            out IStorage ppstgOpen);

        public static string GetStringHash(string instr)
        {
            if (instr.Length == 0)
                return "233"; //1С воспринимает это как хэш пустой строки
            string strHash = string.Empty;
            //для 
            foreach (byte b in new MD5CryptoServiceProvider().ComputeHash(Encoding.Default.GetBytes(instr.ToUpper())))
            {
                strHash += b.ToString("X2");
            }
            return strHash;
        }

        enum UserParameters
        {
            spacer = 0,
            DontCheckRights,
            PasswordHash,
            FullName,
            UserCatalog,
            RightsEnabled,
            UserInterface,
            UserRights
        }

        enum UserParamNames
        {
            Заголовок = 0,
            ОтключитьКонтрольПрав,
            ХэшПароля,
            ПолноеИмя,
            КаталогПользователя,
            ЗаданыПрава,
            Интерфейс,
            НаборПрав
        }

        //Возвращаяет позицию параметра указаного параметра в массиве байт потока пользователя
        // 0 - пустой параметр, заголовк записи. всегда = 1
        // 1 - контролировать права число 1/0
        // 2 - хэш пароля, длина всегда либо 32 либо 3 если пароль не задан
        // 3 - Полное имя пользователя
        // 4 - каталог
        // 5 - флаг наличия прав, число 1/0
        // 6 - интерфейс
        // 7 - набор прав
        static int GetPos(byte[] data, int Param)
        {
            int StartPosition = 0;
            int Count = 0;
            while (Count != (int)Param)
            {
                if (StartPosition >= data.Length)
                    return 0;

                if (data[StartPosition] < 2 && (Count == 0 || Count == 1 || Count == 5)) //численные параметры длина = 4
                {
                    StartPosition += 4;
                }
                else //строковые параметры длина в первом байте
                {
                    StartPosition += data[StartPosition] + 1;
                }
                Count++;
            }
            return StartPosition;
        }

        //Возвращает значение переданного параметра из массива байт
        static object GetParam(byte[] data, UserParameters paramNuber)
        {
            object param = string.Empty;

            int paramstart = GetPos(data, (int)paramNuber);
            switch (paramNuber)
            {
                case UserParameters.RightsEnabled:
                case UserParameters.spacer:
                    {
                        param = (int)(data[paramstart]);
                        break;
                    }
                case UserParameters.DontCheckRights:
                    {
                        param = (int)(1 - data[paramstart]);
                        break;
                    }
                default:
                    {
                        param = Encoding.Default.GetString(data, paramstart + 1, data[paramstart]);
                        break;
                    }
            }
            return param;
        }

        // алгоритм подсчета CheckSum - представить файл в виде массива DWORD и сложить все элементы.
        public static string CheckSum(string USRfileName)
        {
            byte[] Users_usr = { 0 };
            try
            {
                Users_usr = File.ReadAllBytes(USRfileName);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Файл {0} заблокирован. Невозможно вычислить \"Checksum\" {1}", USRfileName,ex.Message);
                return "0";
            }
            UInt32 crc = 0;
            UInt32 x = 0;
            int k = Users_usr.Length % 4;

            if (k > 0)
            {
                Array.Resize(ref Users_usr, Users_usr.Length + k);
            }

            for (int i = 0; i < Users_usr.Length; i += 4)
            {
                x = BitConverter.ToUInt32(Users_usr, i);
                if (Math.Abs(crc + x) > Int32.MaxValue)
                    crc += (UInt32)(x - Math.Sign(crc + x) * 4294967296);
                else
                    crc += x;
            }
            return string.Format("\"{0}\"", Convert.ToString(crc, 16));
        }

        //Расксорить 1cv7.DBA и вернуть строку с параметрами подключения к БД
        public static string ReadDBA(string DBAfileName)
        {
            byte[] ByteBuffer = File.ReadAllBytes(DBAfileName);
            byte[] SQLKey = Encoding.ASCII.GetBytes("19465912879oiuxc ensdfaiuo3i73798kjl");
            for (int i = 0; i < ByteBuffer.Length; i++)
            {
                ByteBuffer[i] = (byte)(ByteBuffer[i] ^ SQLKey[i % 36]);
            }
            return Encoding.ASCII.GetString(ByteBuffer);
        }

        //Заксорить и записать параметры подключения к БД в 1cv7.DBA
        public static bool WriteDBA(string DBAfileName, string Connect)
        {
            byte[] ByteBuffer = Encoding.ASCII.GetBytes(Connect);
            byte[] SQLKey = Encoding.ASCII.GetBytes("19465912879oiuxc ensdfaiuo3i73798kjl");

            for (int i = 0; i < ByteBuffer.Length; i++)
            {
                ByteBuffer[i] = (byte)(ByteBuffer[i] ^ SQLKey[i % 36]);
            }
            try
            {
                File.WriteAllBytes(DBAfileName, ByteBuffer);
                return true;
            }
            catch
            {
                return false;
            }
        }

        //Читает IStream в массив байт
        private static byte[] ReadIStream(IStream pIStream)
        {
            System.Runtime.InteropServices.ComTypes.STATSTG StreamInfo;
            pIStream.Stat(out StreamInfo, 0);
            byte[] data = new byte[StreamInfo.cbSize];
            pIStream.Read(data, (int)StreamInfo.cbSize, IntPtr.Zero);

            return data;
        }

        //Класс описвает объект потока пользователя UserItem
        public class UserItem
        {
            //Класс описывает строку в формате Pascal - массив байт в первом элементе длина, остальные - значение
            public class PascalString
            {
                public byte Length;
                public byte[] Value;

                //Создание из строки
                public PascalString(string InStr)
                {
                    Value = Encoding.Default.GetBytes(InStr);
                    Length = (byte)Value.Length;
                }

                // Для удобства зададим неявное преобразование из строки (используется при присваиваниии)
                public static implicit operator PascalString(string InStr)
                {
                    return new PascalString(InStr);
                }

                // Заполнение из строки
                public void FromString(string InStr)
                {
                    Value = Encoding.Default.GetBytes(InStr);
                    Length = (byte)(Value.Length - 1);
                }

                // для удобства - преобразование в обычную строку
                override public string ToString()
                {
                    return Encoding.Default.GetString(Value);
                }

                // возвращает массив байт в нужном формате
                public byte[] Serialyse()
                {
                    byte[] ByteBuffer = new byte[Length + 1];
                    ByteBuffer[0] = Length;
                    for (int i = 1; i < ByteBuffer.Length; i++)
                        ByteBuffer[i] = Value[i - 1];

                    return ByteBuffer;
                }
            }

            public string Name;
            public string PageName;
            public static int CheckRights = 1;
            public PascalString HashCode;
            public PascalString FullName;
            public PascalString UserCatalog;
            public static int RightsEnabled = 1;
            public PascalString Interface;
            public PascalString Rights;

            //Созадает структуру из массива байт
            public UserItem(byte[] data, string Name = "", string PageName = "")
            {
                this.Name = Name;
                this.PageName = PageName;

                CheckRights = (int)GetParam(data, UserParameters.DontCheckRights);
                RightsEnabled = (int)GetParam(data, UserParameters.RightsEnabled);

                HashCode = (string)GetParam(data, UserParameters.PasswordHash);
                FullName = (string)GetParam(data, UserParameters.FullName);
                UserCatalog = (string)GetParam(data, UserParameters.UserCatalog);
                Interface = (string)GetParam(data, UserParameters.UserInterface);
                Rights = (string)GetParam(data, UserParameters.UserRights);
            }

            //создает структуру из массива байт при присваивании
            public static implicit operator UserItem(byte[] data)
            {
                return new UserItem(data);
            }
            //Созадает структуру из набора параметров
            public UserItem(string PageName,
                            int _CheckRights = 1,
                            string HashCode = "233",
                            string FullName = "",
                            string UserCatalog = "",
                            string Interface = "",
                            string Rights = "",
                            string Name = "")
            {
                CheckRights = _CheckRights;
                RightsEnabled = 1;

                this.Name = Name;
                this.PageName = PageName;
                if (Name == "")
                    this.Name = PageName;
                this.HashCode = HashCode;
                this.FullName = FullName;
                this.UserCatalog = UserCatalog;
                this.Interface = Interface;
                this.Rights = Rights;
            }

            //Возвращает массив байт для записи в поток файла
            public byte[] Serialyse()
            {
                //посчитаем размер массива. 17 - числовые поля плюс по 1 байту на каждое строковое поле для хранения длины.
                int rawsize = 17 + HashCode.Length + FullName.Length + UserCatalog.Length + Interface.Length + Rights.Length;

                //1C отказывается принимать файлы у которых длина записи не кратна 128
                rawsize = (rawsize / 128 + 1) * 128;

                byte[] rawdata = new byte[rawsize];
                byte[] buffer;
                int lastCount = 0;

                //преобразуем каждое поле в массив байт и сложим в общий массив в нужном порядке
                buffer = BitConverter.GetBytes((int)1);
                Array.Copy(buffer, 0, rawdata, lastCount, buffer.Length);
                lastCount += buffer.Length;

                buffer = BitConverter.GetBytes(CheckRights);
                Array.Copy(buffer, 0, rawdata, lastCount, buffer.Length);
                lastCount += buffer.Length;

                buffer = HashCode.Serialyse();
                Array.Copy(buffer, 0, rawdata, lastCount, buffer.Length);
                lastCount += buffer.Length;

                buffer = FullName.Serialyse();
                Array.Copy(buffer, 0, rawdata, lastCount, buffer.Length);
                lastCount += buffer.Length;

                buffer = UserCatalog.Serialyse();
                Array.Copy(buffer, 0, rawdata, lastCount, buffer.Length);
                lastCount += buffer.Length;

                buffer = BitConverter.GetBytes(RightsEnabled);
                Array.Copy(buffer, 0, rawdata, lastCount, buffer.Length);
                lastCount += buffer.Length;

                buffer = Interface.Serialyse();
                Array.Copy(buffer, 0, rawdata, lastCount, buffer.Length);
                lastCount += buffer.Length;

                buffer = Rights.Serialyse();
                Array.Copy(buffer, 0, rawdata, lastCount, buffer.Length);
                lastCount += buffer.Length;
                ///
                return rawdata;
            }
        }

        //Класс описывает список элементов пользователей.
        public class UsersList : Dictionary<string, UserItem>
        {

            private Dictionary<string, string> Container;

            public UsersList()
                : base()
            {
                Container = new Dictionary<string, string>();
            }

            //разбирает строку Container.Contents в словарь
            private Dictionary<string, string> ParseContainer(string Container)
            {
                Dictionary<string, string> res = new Dictionary<string, string>();
                Container = Container.Replace("{\"Container.Contents\",{", "");
                Container = Container.Replace("}}", "");
                Container = Container.Replace("},{", ";");

                foreach (string UserItem in Container.Split(';'))
                {
                    string[] UserItemType = UserItem.Replace("\"", "").Split(',');
                    res.Add(UserItemType[1], UserItemType[2]);
                }
                return res;
            }

            //Собирает строку Container.Contents из словаря
            private string ConstructContainer()
            {
                string strContainer = "{\"Container.Contents\"";
                foreach (var item in Container)
                {
                    strContainer += string.Format(",{{\"UserItemType\",\"{0}\",\"{1}\",\"\"}}", item.Key, item.Value);
                }
                strContainer += "}";
                return strContainer;
            }

            public void Add(UserItem Item)
            {
                if (this.Keys.Contains(Item.Name))
                {
                    this.Remove(Item.Name);
                }

                if (Container.ContainsKey(Item.PageName))
                {
                    Container.Remove(Item.PageName);
                }

                base.Add(Item.Name, Item);
                Container.Add(Item.PageName, Item.Name);
            }

            new public void Remove(string Key)
            {
                if (this.Keys.Contains(Key))
                {
                    Container.Remove(this[Key].PageName);
                    base.Remove(Key);
                }

                if (Container.Values.Contains(Key))
                {
                    Container.Remove(Container.Keys.ElementAt(Container.Values.ToList().IndexOf(Key)));
                }

            }

            public UserItem GetValue(int Index)
            {
                return this.ElementAt(Index).Value;
            }

            public UserItem this[int Index]
            {
                get
                {
                    return GetValue(Index);
                }
                set
                {
                    string key = this.ElementAt(Index).Key;
                    this.Remove(key);
                    this.Add(key, value);
                }
            }

            new public UserItem this[string key]
            {
                get
                {
                    return base[key];
                }
                set
                {
                    this.Remove(key);
                    this.Add(key, value);
                }
            }

            public UsersList(string USRfileName)
                : this()
            {
                IStorage storage = null;
                uint fetched = 0;
                IStream pIStream = null;
                IEnumSTATSTG pIEnumStatStg = null;
                byte[] data;

                if (StgIsStorageFile(USRfileName) == 0)
                {
                    if (StgOpenStorage(USRfileName, null, STGM.DIRECT | STGM.READ | STGM.SHARE_EXCLUSIVE, IntPtr.Zero, 0, out storage) == 0)
                    {
                        //System.Runtime.InteropServices.ComTypes.STATSTG statstg = new System.Runtime.InteropServices.ComTypes.STATSTG();
                        System.Runtime.InteropServices.ComTypes.STATSTG[] regelt = { new System.Runtime.InteropServices.ComTypes.STATSTG() };

                        //Читаем содержимое "Container.Contents"
                        storage.OpenStream("Container.Contents", IntPtr.Zero, (uint)(STGM.READ | STGM.SHARE_EXCLUSIVE), 0, out pIStream);
                        data = ReadIStream(pIStream);

                        // ОБЯЗАТЕЛЬНО освобождть поток, иначе доступа к нему позже не будет
                        Marshal.ReleaseComObject(pIStream);
                        //

                        Container = ParseContainer(Encoding.Default.GetString(data, 0, data.Length));
                        //Console.WriteLine(Container);
                        //storage.Stat(out statstg, (uint)STATFLAG.STATFLAG_DEFAULT);

                        //Обойдем все элементы хранилища
                        storage.EnumElements(0, IntPtr.Zero, 0, out pIEnumStatStg);
                        while (pIEnumStatStg.Next(1, regelt, out fetched) == 0)
                        {
                            string filePage = regelt[0].pwcsName;
                            if (filePage == "Container.Contents")
                            {
                                break;
                            }
                            string UserName = Container[filePage];
                            //Console.WriteLine("{0} - {1}", ((STGTY)regelt[0].type).ToString(), filePage);

                            if ((STGTY)regelt[0].type == STGTY.STGTY_STREAM)
                            {
                                storage.OpenStream(filePage, IntPtr.Zero, (uint)(STGM.READ | STGM.SHARE_EXCLUSIVE), 0, out pIStream);

                                if (pIStream != null)
                                {
                                    data = ReadIStream(pIStream);
                                    Marshal.ReleaseComObject(pIStream);
                                    this.Add(new UserItem(data, UserName, filePage));
                                }
                            }
                        }
                    }
                    Marshal.ReleaseComObject(storage);
                    Marshal.FinalReleaseComObject(storage);
                    storage = null;
                    Marshal.ReleaseComObject(pIEnumStatStg);
                    pIEnumStatStg = null;

                    GC.Collect();
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                    //;
                }

                string ss = ConstructContainer();
            }

            public bool Save(string USRfileName)
            {
                IStorage ppstgOpen = null;
                IStream pIStream = null;
                IEnumSTATSTG pIEnumStatStg = null;
                System.Runtime.InteropServices.ComTypes.STATSTG[] regelt = { new System.Runtime.InteropServices.ComTypes.STATSTG() };
                uint fetched = 0;
                byte[] data;

                if (File.Exists(USRfileName))
                {
                    if (StgIsStorageFile(USRfileName) == 0)
                    {
                        if (StgOpenStorage(USRfileName, null, STGM.READWRITE | STGM.SHARE_EXCLUSIVE, IntPtr.Zero, 0, out ppstgOpen) == 0)
                        {
                            ppstgOpen.EnumElements(0, IntPtr.Zero, 0, out pIEnumStatStg);
                            while (pIEnumStatStg.Next(1, regelt, out fetched) == 0)
                            {
                                ppstgOpen.DestroyElement(regelt[0].pwcsName);
                            }
                        }
                        else
                        {
                            Console.WriteLine("Ошибка открытия файла {0}.", USRfileName);
                            return false;
                        }
                    }
                    else
                    {
                        Console.WriteLine("Файл {0} не является хранилищем списка пользователей.", USRfileName);
                        return false;
                    }
                }
                else
                {
                    StgCreateDocfile(USRfileName, STGM.CREATE | STGM.WRITE | STGM.SHARE_EXCLUSIVE, 0, out ppstgOpen);
                }
                if (ppstgOpen != null)
                {
                    ppstgOpen.Commit(0);
                    ppstgOpen.CreateStream("Container.Contents", (uint)(STGM.CREATE | STGM.WRITE | STGM.SHARE_EXCLUSIVE), 0, 0, out pIStream);
                    data = Encoding.Default.GetBytes(ConstructContainer());
                    pIStream.Write(data, data.Length, new IntPtr(fetched));
                    pIStream.Commit((int)STGC.OVERWRITE);
                    Marshal.ReleaseComObject(pIStream);
                    ppstgOpen.Commit(0);
                    foreach (var item in Container)
                    {
                        ppstgOpen.CreateStream(item.Key, (uint)(STGM.CREATE | STGM.WRITE | STGM.SHARE_EXCLUSIVE), 0, 0, out pIStream);
                        data = base[item.Value].Serialyse();
                        pIStream.Write(data, data.Length, new IntPtr(fetched));
                        pIStream.Commit((int)STGC.OVERWRITE);
                        Marshal.ReleaseComObject(pIStream);
                        ppstgOpen.Commit(0);
                    }
                }
                else
                {
                    Console.WriteLine("Ошибка записи файла {0}", USRfileName);
                    return false;
                }
                try
                {
                    ppstgOpen.Commit(0);
                    Marshal.ReleaseComObject(ppstgOpen);
                    Marshal.FinalReleaseComObject(ppstgOpen);
                    ppstgOpen = null;
                    Marshal.ReleaseComObject(pIEnumStatStg);
                    pIEnumStatStg = null;

                    GC.Collect();
                    GC.Collect();
                    GC.WaitForPendingFinalizers();

                    string DBAfileName = Path.GetDirectoryName(Path.GetDirectoryName(USRfileName)) + "\\1cv7.dba";
                    if (File.Exists(DBAfileName))
                    {
                        string Connect = ReadDBA(DBAfileName);
                        Console.WriteLine("New Checksum: {0}", CheckSum(USRfileName));
                        Connect = string.Format("{0}{1}}}}}", Connect.Substring(0, Connect.IndexOf("sum\",") + 5), CheckSum(USRfileName));
                        WriteDBA(DBAfileName, Connect);
                    }
                }
                catch
                {
                    Console.WriteLine("Ошибка записи файла {0}", USRfileName);
                    return false;
                }
                return true;
            }
        }

    }
}


namespace Program
{
    using UserDefworks;
    class Program
    {
        static void PrintHelp()
        {
            Console.WriteLine("Usage: " + Path.GetFileName(Application.ExecutablePath).ToLower() + " [/f|-f:<1CDatabasePath>\\usrdef\\users.usr] [-l|/l]\r\n   <1CDatabasePath> : full path to 1C database catalog.");
            Console.WriteLine("\r\n -l - list \"userdef.usr\" contents");
            Console.WriteLine("");
            Console.WriteLine("\r\n" + Path.GetFileName(Application.ExecutablePath).ToLower() + " [/h|-h|/?|-?] - for this screen ");
            Console.WriteLine("\r\nPress any key to exit...");
            Console.ReadKey();
        }
        static void Main(string[] args)
        {
            Console.WriteLine("Userdef Works utility (c) MadDAD 2014\r\n");

            string USRfileName = string.Empty;
            string Connect = string.Empty;
            if (args.Length != 0)
            {
                string parameter = string.Empty;
                for (int i = 0; i < args.Length; i++)
                {
                    parameter = args[i].ToLower();
                    switch (parameter.Substring(1, 1))
                    {
                        case "f":
                            USRfileName = parameter.Substring(3).Replace("\"", "").Replace("'", "");
                            break;
                        case "?":
                        case "h":
                            PrintHelp();
                            return;
                    }
                }
            }

            if (USRfileName == string.Empty)
            {

                PrintHelp();
                return;
            }

            if (!File.Exists(USRfileName))
            {
                Console.WriteLine("File \"" + USRfileName + "\" not exists. ");
                Console.WriteLine("\r\nPress any key to exit...");
                Console.ReadKey();
                return;
            }

            string DBCatalog = Path.GetDirectoryName(Path.GetDirectoryName(USRfileName)) + "\\";
            string DBAfileName = DBCatalog + "1cv7.dba";
            Console.WriteLine("Processing file: " + USRfileName);
            Console.WriteLine("Database catalog: " + DBCatalog);


            if (!File.Exists(DBAfileName))
            {
                Console.WriteLine("Database format: DBF");
                DBAfileName = string.Empty;
            }
            else
            {
                Console.WriteLine("Database format: SQL");
                Connect = UserDefworks.ReadDBA(DBAfileName);
                Console.WriteLine("Decrypted DBA: " + Connect);
                //вычислим Checksum 
                Console.WriteLine("Checksum: {0}", UserDefworks.CheckSum(USRfileName));
            }

            //Прочитаем список пользователей из переданного файла
            UserDefworks.UsersList Users = new UserDefworks.UsersList(USRfileName);

            string username = "z002y8yp";

            if (Users.ContainsKey(username)) //проверим наличие пользователя в списке.
            {
                //Заменим пароль пользователю
                Users[username].HashCode = UserDefworks.GetStringHash("qwerty");

                //Заменим пользователю полное имя
                Users[username].FullName = "Дмитрий Алексеевич Дрейцер";
            }

            //Добавим новго пользователя
            Users.Add(new UserDefworks.UserItem("z002y8yp-1", 1, UserDefworks.GetStringHash("123"), "Иван Иванович", "./", "Админ", "Администратор", "z002y8yp-1"));

            Users.Save(USRfileName);
            Console.WriteLine("\r\nPress any key to exit...");
            Console.ReadKey();
        }
    }
}