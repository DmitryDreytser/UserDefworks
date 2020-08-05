using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using System.Reflection;
using System.Xml;

using UserDef;
//namespace Example
//{
//    class Example
//    {
//        [STAThread]
//        static void Main(string[] args)
//        {
//            string USRfileName = @"C:\MyDB\userdef\users.usr";
//            string DatabaseCatalog = Path.GetDirectoryName(Path.GetDirectoryName(USRfileName));

//            //Загрузим текущий список пользователей
//            UserDefworks.UsersList Users = new UserDefworks.UsersList(USRfileName);

//            string UserName = "User1";
//            //Изменим параметры пользователя в списке.
//            if (Users.ContainsKey(UserName))
//            {
//                UserDefworks.UserItem User = Users[UserName];
//                User.FullName = "Владимир Владимироваич Путин";
//                User.UserInterface = "Президент";
//                User.UserRights = "IDDQD";
//                User.PasswordHash = UserDefworks.GetStringHash("sdlfhw342e8");
//            }

//            UserName = "User2";
//            //Создадим нового пользователя
//            UserDefworks.UserItem User2 = new UserDefworks.UserItem(
//                                                            UserName, //Имя потока 
//                                                            1,        //Контроль прав
//                                                            UserDefworks.GetStringHash("qwerty"), //Пароль
//                                                            "Зинаида Петровна", //Полное имя
//                                                            DatabaseCatalog, //Каталог пользователя
//                                                            "ИнтерфейсБухгалтера", //Интерфейс
//                                                            "ПраваБухгалтера", //Набор прав
//                                                            "Зинуля" //Имя пользователя
//                                                            );
//            //Добавим его в список
//            Users.Add(User2);
//            //Теперь он доступен по индексу "Зинуля"
//            Console.WriteLine(Users["Зинуля"].FullName);

//            //Удалим пользователя из списка
//            Users.Remove("User3");
//            try
//            {
//                if (Users.Save(USRfileName))
//                {
//                    Console.WriteLine("Усё пучком!");
//                }
//                else
//                {
//                    Console.WriteLine("Чегой-то не то!");
//                }
//            }
//            catch (Exception ex)
//            {
//                Console.WriteLine("Ошибка - {0}", ex.Message);
//            }
//        }
//    }
//}


namespace UserDef
{
    public class UserDefworks
    {
        public enum UserParameters
        {
            Header = 0,
            DontCheckRights,
            PasswordHash,
            FullName,
            UserCatalog,
            RightsEnabled,
            UserInterface,
            UserRights
        }

        public static string GetStringHash(string instr)
        {
            if (instr.Length == 0)
                return "233"; //1С воспринимает это как хэш пустой строки

            string strHash = string.Empty;

            //1C принимате только пароли не больше 10 симвлов длиной и в верхнем регистре.
            instr = instr.Substring(0, Math.Min(10, instr.Length)).ToUpper();

            foreach (byte b in new MD5CryptoServiceProvider().ComputeHash(Encoding.Default.GetBytes(instr)))
            {
                strHash += b.ToString("X2");
            }
            return strHash;
        }

        public static Dictionary<UserParameters, string> UserParamNames = new Dictionary<UserParameters, string>()
        {
            {UserParameters.Header,"Заголовок"},
            {UserParameters.DontCheckRights,"Отключить контроль прав"},
            {UserParameters.PasswordHash,"Хэш пароля"},
            {UserParameters.FullName,"Полное имя"},
            {UserParameters.UserCatalog,"Каталог пользователя"},
            {UserParameters.RightsEnabled,"Заданы права"},
            {UserParameters.UserInterface,"Интерфейс"},
            {UserParameters.UserRights,"Набор прав"}
        };

        // алгоритм подсчета CheckSum - представить файл в виде массива DWORD и сложить все элементы.
        public static string CheckSum(string USRfileName)
        {
            if (!File.Exists(USRfileName))
                return "00000000";
            byte[] Users_usr = { 0 };
            try
            {
                Users_usr = File.ReadAllBytes(USRfileName);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Файл {0} заблокирован. Невозможно вычислить \"Checksum\" {1}", USRfileName, ex.Message);
                return "00000000";
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

        //Класс описвает объект потока пользователя UserItem
        [Serializable]
        public class UserItem
        {
            //Класс описывает строку в формате Pascal - массив байт в первом элементе длина, остальные - значение
            [Serializable]
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

                //Создание из строки
                public PascalString(byte[] InStr, int SourceIndex = 0)
                {
                    if (SourceIndex >= InStr.Length)
                        return;
                    Length = InStr[SourceIndex];
                    if (SourceIndex + 1 + Length >= InStr.Length)
                        Length = (byte)(InStr.Length - 1 - SourceIndex);
                    Value = new byte[Length];
                    Array.Copy(InStr, SourceIndex + 1, Value, 0, Length);
                }

                // Для удобства зададим неявное преобразование из строки (используется при присваиваниии)
                public static implicit operator PascalString(string InStr)
                {
                    return new PascalString(InStr);
                }

                // Для удобства зададим неявное преобразование из массива байт (используется при присваиваниии)
                public static implicit operator PascalString(byte[] InStr)
                {
                    return new PascalString(InStr);
                }

                public static implicit operator byte[](PascalString InStr)
                {
                    return InStr.Serialize();
                }

                // для удобства - преобразование в обычную строку
                override public string ToString()
                {
                    return Encoding.Default.GetString(Value);
                }

                public static implicit operator string(PascalString InStr)
                {
                    return InStr.ToString();
                }

                // Заполнение из строки
                public void FromString(string InStr)
                {
                    Value = Encoding.Default.GetBytes(InStr);
                    Length = (byte)(Value.Length - 1);
                }

                // возвращает массив байт в нужном формате
                public byte[] Serialize()
                {
                    byte[] ByteBuffer = new byte[Length + 1];
                    ByteBuffer[0] = Length;
                    for (int i = 1; i < ByteBuffer.Length; i++)
                        ByteBuffer[i] = Value[i - 1];

                    return ByteBuffer;
                }

                public PascalString Deserialize(byte[] data)
                {
                    return data;
                }

                public byte[] GetObjectData()
                {
                    return Serialize();
                }
            }

            public string Name;
            public string PageName;
            public int CheckRights = 1;
            public PascalString PasswordHash;
            public PascalString FullName;
            public PascalString UserCatalog;
            public int RightsEnabled = 1;
            public PascalString UserInterface;
            public PascalString UserRights;
            public bool modified = false;

            //Возвращаяет позицию указаного параметра в массиве байт потока пользователя
            // 0 - пустой параметр, заголовк записи. всегда = 1
            // 1 - контролировать права число 1/0
            // 2 - хэш пароля, длина всегда либо 32 либо 3 если пароль не задан
            // 3 - Полное имя пользователя
            // 4 - каталог
            // 5 - флаг наличия прав, число 1/0
            // 6 - интерфейс
            // 7 - набор прав
            static int GetPos(byte[] data, UserParameters Param)
            {
                int StartPosition = 0;
                int Count = 0;
                while (Count != (int)Param)
                {
                    if (StartPosition >= data.Length)
                        return 0;

                    if (data[StartPosition] < 2 && (Count == 0 || Count == 1 || Count == 5)) //булевы параметры длина = 4
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
            static dynamic ParseByteArray(byte[] data, UserParameters paramNuber)
            {
                dynamic param = null;

                int paramstart = GetPos(data, paramNuber);
                switch (paramNuber)
                {
                    case UserParameters.RightsEnabled:
                    case UserParameters.Header:
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
                            param = new PascalString(data, paramstart);
                            break;
                        }
                }
                return param;
            }

            dynamic this[UserParameters param]
            {
                get
                {
                    switch (param)
                    {
                        case UserParameters.Header:
                            return 1;
                        case UserParameters.DontCheckRights:
                            return CheckRights;
                        case UserParameters.RightsEnabled:
                            return RightsEnabled;
                        case UserParameters.PasswordHash:
                            return PasswordHash;
                        case UserParameters.FullName:
                            return FullName;
                        case UserParameters.UserCatalog:
                            return UserCatalog;
                        case UserParameters.UserInterface:
                            return UserInterface;
                        case UserParameters.UserRights:
                            return UserRights;
                        default:
                            return null;
                    }
                }
                set
                {
                    modified = true;
                    switch (param)
                    {
                        case UserParameters.DontCheckRights:
                            { CheckRights = value; break; }
                        case UserParameters.RightsEnabled:
                            { RightsEnabled = value; break; }
                        case UserParameters.PasswordHash:
                            { PasswordHash = value; break; }
                        case UserParameters.FullName:
                            { FullName = value; break; }
                        case UserParameters.UserCatalog:
                            { UserCatalog = value; break; }
                        case UserParameters.UserInterface:
                            { UserInterface = value; break; }
                        case UserParameters.UserRights:
                            { UserRights = value; break; }
                        default:
                            break;
                    }

                }
            }

            public void SetParam(UserParameters param, dynamic value)
            {
                this[param] = value;

            }

            public dynamic GetParam(UserParameters param)
            {
                return this[param];
            }

            //Созадает структуру из массива байт
            public UserItem(byte[] data, string Name = "", string PageName = "")
            {
                this.Name = Name;
                this.PageName = PageName;
                for (UserParameters param = UserParameters.Header; param <= UserParameters.UserRights; param++)
                {
                    SetParam(param, ParseByteArray(data, param));
                }
                modified = false;
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

                this[UserParameters.PasswordHash] = HashCode;
                this[UserParameters.FullName] = FullName;
                this[UserParameters.UserCatalog] = UserCatalog;
                this[UserParameters.UserInterface] = Interface;
                this[UserParameters.UserRights] = Rights;
                modified = false;
            }

            //Возвращает массив байт для записи в поток файла
            public byte[] Serialyze()
            {
                //посчитаем размер массива. 17 = числовые поля плюс по 1 байту на каждое строковое поле для хранения длины. В конце должны быть Int(0)
                int rawsize = 17 + PasswordHash.Length + FullName.Length + UserCatalog.Length + UserInterface.Length + UserRights.Length + 4;

                byte[] rawdata = new byte[rawsize];
                byte[] buffer;
                int lastCount = 0;

                //преобразуем каждое поле в массив байт и сложим в общий массив в нужном порядке
                buffer = BitConverter.GetBytes((int)1);
                Array.Copy(buffer, 0, rawdata, lastCount, buffer.Length);
                lastCount += buffer.Length;

                for (UserParameters i = UserParameters.DontCheckRights; i <= UserParameters.UserRights; i++)
                {
                    dynamic param = GetParam(i);

                    if (param.GetType().Name == "Int32")
                        buffer = BitConverter.GetBytes(param);
                    else
                        buffer = param;

                    Array.Copy(buffer, 0, rawdata, lastCount, buffer.Length);
                    lastCount += buffer.Length;
                }
               return rawdata;
            }

            public byte[] GetObjectData()
            {
                return Serialyze();
            }
        }

        //Класс описывает список элементов пользователей.
        [Serializable]
        public class UsersList : Dictionary<string, UserItem>
        {
            private Dictionary<string, string> Container;
            public bool modified = false;

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
                    /* [in] */ STGC grfCommitFlags);

                void Revert();

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

            //Читает IStream в массив байт
            private static byte[] ReadIStream(IStream pIStream)
            {
                System.Runtime.InteropServices.ComTypes.STATSTG StreamInfo;
                pIStream.Stat(out StreamInfo, 0);
                byte[] data = new byte[StreamInfo.cbSize];
                pIStream.Read(data, (int)StreamInfo.cbSize, IntPtr.Zero);
                return data;
            }

            class NativeMethods
            {
                [DllImport("ole32.dll")]
                public static extern int StgIsStorageFile(
                    [MarshalAs(UnmanagedType.LPWStr)] string pwcsName);

                [DllImport("ole32.dll")]
                public static extern int StgOpenStorage(
                    [MarshalAs(UnmanagedType.LPWStr)] string pwcsName,
                    IStorage pstgPriority,
                    STGM grfMode,
                    IntPtr snbExclude,
                    uint reserved,
                    out IStorage ppstgOpen);

                [DllImport("ole32.dll")]
                public static extern int StgCreateDocfile(
                    [MarshalAs(UnmanagedType.LPWStr)]string pwcsName,
                    STGM grfMode,
                    uint reserved,
                    out IStorage ppstgOpen);
            }

            public UsersList()
                : base()
            {
                Container = new Dictionary<string, string>();
                modified = true;
            }

            //разбирает строку Container.Contents в словарь
            private Dictionary<string, string> ParseContainer(string Container)
            {
                Dictionary<string, string> res = new Dictionary<string, string>();
                string[] UserItemType;

                if (!Container.Contains("Container.Contents"))
                    return res;

                Container = Container.Replace("{\"Container.Contents\",{", "").Replace("}}", "").Replace("},{", ";");

                foreach (string UserItem in Container.Split(';'))
                {
                    UserItemType = UserItem.Replace("\"", "").Split(',');
                    res.Add(UserItemType[1], UserItemType[2]);
                }
                return res;
            }

            //Собирает строку Container.Contents из словаря
            private string ConstructContainer()
            {

                string strContainer = "{\"Container.Contents\"";
                Container = new Dictionary<string, string>();
                foreach (UserItem item in this.Values)
                {
                    strContainer += string.Format(",{{\"UserItemType\",\"{0}\",\"{1}\",\"\"}}", item.PageName, item.Name);
                    Container.Add(item.PageName, item.Name);
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
                modified = true;
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
                modified = true;

            }

            public UserItem GetValue(int Index)
            {
                return this[Index];
            }

            public UserItem this[int Index]
            {
                get
                {
                    return this.ElementAt(Index).Value;
                }
                set
                {
                    string key = this.ElementAt(Index).Key;
                    this.Remove(key);
                    this.Add(key, value);
                    modified = true;
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
                if (!File.Exists(USRfileName))
                    return;

                IStorage storage = null;
                uint fetched = 0;
                IStream pIStream = null;
                IEnumSTATSTG pIEnumStatStg = null;
                byte[] data = { 0 };

                if (NativeMethods.StgIsStorageFile(USRfileName) == 0)
                {
                    if (NativeMethods.StgOpenStorage(USRfileName, null, STGM.READ | STGM.TRANSACTED, IntPtr.Zero, 0, out storage) == 0)
                    {
                        //System.Runtime.InteropServices.ComTypes.STATSTG statstg = new System.Runtime.InteropServices.ComTypes.STATSTG();
                        System.Runtime.InteropServices.ComTypes.STATSTG[] regelt = { new System.Runtime.InteropServices.ComTypes.STATSTG() };

                        //Читаем содержимое "Container.Contents"
                        try
                        {
                            storage.OpenStream("Container.Contents", IntPtr.Zero, (uint)(STGM.READ | STGM.SHARE_EXCLUSIVE), 0, out pIStream);
                            data = ReadIStream(pIStream);
                            // ОБЯЗАТЕЛЬНО освобождть поток, иначе доступа к нему позже не будет
                            Marshal.FinalReleaseComObject(pIStream);
                        }
                        catch (Exception ex)
                        {
                            //if (ex.HResult == 0x80030002)
                            //{

                            //}
                        }



                        //Разберем список соответствия потоков и имен пользователей
                        Container = ParseContainer(Encoding.Default.GetString(data, 0, data.Length));
                        //Обойдем все элементы хранилища
                        storage.EnumElements(0, IntPtr.Zero, 0, out pIEnumStatStg);
                        while (pIEnumStatStg.Next(1, regelt, out fetched) == 0)
                        {
                            string filePage = regelt[0].pwcsName;
                            if (filePage != "Container.Contents")
                            {
                                string UserName = string.Empty;
                                if (Container.Keys.Contains(filePage))
                                    UserName = Container[filePage];
                                else
                                    UserName = filePage;

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
                    }
                    else
                    {
                        throw new Exception(string.Format("Файл {0} занят.", USRfileName));
                    }
                }
                else
                {
                    throw new Exception(string.Format("Файл {0} не является хранилищем списка пользователей.", USRfileName));
                }
                modified = false;
            }


            [DllImport("kernel32.dll", SetLastError = true)]
            static extern bool LockFile(IntPtr hFile, int dwFileOffsetLow, int dwFileOffsetHigh, int nNumberOfBytesToLockLow, int nNumberOfBytesToLockHigh);

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern bool UnlockFile(IntPtr hFile, int dwFileOffsetLow, int dwFileOffsetHigh, int nNumberOfBytesToLockLow, int nNumberOfBytesToLockHigh);

            public bool Save(string USRfileName)
            {
                bool IsSQL = false;
                string DBcatalog = Path.GetDirectoryName(USRfileName);
                if (DBcatalog != "")
                {
                    DBcatalog = Path.GetDirectoryName(DBcatalog) + "\\";
                }
                string DBAfileName = DBcatalog + "1cv7.dba";
                IsSQL = File.Exists(DBAfileName);


                // Для базы SQL нужно обновить 1cv7.dba. 
                // И если октрыт конфигуратор, он очистит параметры подключения к БД
                // проверим, не открыт ли конфигуратор
                if (IsSQL)
                {
                    // проверим, можно ли перезаписать users.usr
                    string fLockFile = Path.GetDirectoryName(Path.GetDirectoryName(USRfileName)) + "\\1cv7.lck";
                    if (File.Exists(fLockFile))
                    {
                        //Откроем 1cv7.lck в разделенном режиме
                        FileStream f = File.Open(fLockFile, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);

                        //Конфигуратор при открытии блокирует первые 10000 байт файла 1cv7.lck в корне базы.
                        //Если не удастся их заблокировать, значит конфигуратор запущен
                        bool IsConfigRunning = !LockFile(f.Handle, 0, 0, 10000000, 0);

                        //не забываем разблокировать и закрыть файл, иначе получим блокировку на запуск конфигуратора.
                        UnlockFile(f.Handle, 0, 0, 10000000, 0);
                        f.Close();
                        f.Dispose();

                        if (IsConfigRunning)
                            throw new Exception(string.Format("В базе {0} открыт конфигуратор. Нельзя сохранять список пользователей, иначе будут сброшены параметры подключения к SQL.", Path.GetDirectoryName(Path.GetDirectoryName(USRfileName))));
                    }
                }

                IStorage ppstgOpen = null;
                IStream pIStream = null;
                IEnumSTATSTG pIEnumStatStg = null;
                System.Runtime.InteropServices.ComTypes.STATSTG[] regelt = { new System.Runtime.InteropServices.ComTypes.STATSTG() };
                uint fetched = 0;
                byte[] data;

                if (File.Exists(USRfileName))
                {
                    if (NativeMethods.StgIsStorageFile(USRfileName) == 0)
                    {
                        if (NativeMethods.StgOpenStorage(USRfileName, null, STGM.READWRITE | STGM.TRANSACTED, IntPtr.Zero, 0, out ppstgOpen) == 0)
                        {
                            ppstgOpen.EnumElements(0, IntPtr.Zero, 0, out pIEnumStatStg);
                            while (pIEnumStatStg.Next(1, regelt, out fetched) == 0)
                            {
                                ppstgOpen.DestroyElement(regelt[0].pwcsName);
                            }
                            Marshal.ReleaseComObject(pIEnumStatStg);
                            pIEnumStatStg = null;
                        }
                        else
                        {
                            throw new Exception(string.Format("Ошибка открытия файла {0} для записи.", USRfileName));
                        }
                    }
                    else
                    {
                        throw new Exception(string.Format("Файл {0} не является хранилищем списка пользователей.", USRfileName));
                    }
                }
                else
                {
                    NativeMethods.StgCreateDocfile(USRfileName, STGM.CREATE | STGM.WRITE | STGM.SHARE_EXCLUSIVE, 0, out ppstgOpen);
                }
                if (ppstgOpen != null)
                {
                    ppstgOpen.Commit(STGC.OVERWRITE);

                    ppstgOpen.CreateStream("Container.Contents", (uint)(STGM.CREATE | STGM.WRITE | STGM.SHARE_EXCLUSIVE), 0, 0, out pIStream);
                    data = Encoding.Default.GetBytes(ConstructContainer());
                    pIStream.Write(data, data.Length, new IntPtr(fetched));
                    pIStream.Commit((int)STGC.OVERWRITE);
                    Marshal.ReleaseComObject(pIStream);
                    ppstgOpen.Commit(0);
                    foreach (UserItem item in this.Values)
                    {
                        ppstgOpen.CreateStream(item.PageName, (uint)(STGM.CREATE | STGM.WRITE | STGM.SHARE_EXCLUSIVE), 0, 0, out pIStream);
                        data = item.Serialyze();
                        pIStream.Write(data, data.Length, new IntPtr(fetched));
                        pIStream.Commit((int)STGC.OVERWRITE);
                        Marshal.ReleaseComObject(pIStream);
                        ppstgOpen.Commit(STGC.OVERWRITE);
                    }
                }
                else
                {
                    throw new Exception(string.Format("Ошибка записи файла {0}", USRfileName));
                }
                try
                {
                    ppstgOpen.Commit(STGC.OVERWRITE);
                    Marshal.ReleaseComObject(ppstgOpen);
                    Marshal.FinalReleaseComObject(ppstgOpen);
                    ppstgOpen = null;

                    GC.Collect();
                    GC.Collect();
                    GC.WaitForPendingFinalizers();


                    if (File.Exists(DBAfileName))
                    {
                        string Connect = ReadDBA(DBAfileName);
                        // Console.WriteLine("New Checksum: {0}", CheckSum(USRfileName));
                        Connect = string.Format("{0}{1}}}}}", Connect.Substring(0, Connect.IndexOf("sum\",") + 5), CheckSum(USRfileName));
                        WriteDBA(DBAfileName, Connect);
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception(string.Format("Ошибка записи файла {0} : {1}", USRfileName, ex.Message), ex);
                }
                return true;
            }
        }
    }
}


namespace Program
{
    class Program
    {
        static void PrintHelp()
        {
            Console.WriteLine("Usage: " + Path.GetFileName(Application.ExecutablePath).ToLower() + " [-f:<1CDatabasePath>\\usrdef\\users.usr] | [-d:<1CDatabasePath>] [options] [account options] [list options]\r\n   <1CDatabasePath> : full path to 1C database catalog.");
            Console.WriteLine("\r\n [options]");
            Console.WriteLine(" -w = wait for keypress when all is done");
            Console.WriteLine(" -l = list \"userdef.usr\" contents");
            Console.WriteLine(" -dba = show decrypted contents of \"1cv7.dba\" ");
            Console.WriteLine(" -add = add new user account, using account options. If users.usr not exists, it will be created.");
            Console.WriteLine(" -change = change existing user account, using account options");
            Console.WriteLine(" -delete = delete existing user account, using account option - UserName");
            Console.WriteLine(" -r = repair users.usr file. Recreates 'Container.Contents' using existing streams in file.");
            Console.WriteLine("\r\n [account options] (must be declared if using (-add) or (-change))");
            Console.WriteLine("     -UserName:\"Name\" = username. required");
            Console.WriteLine("     -UserPassword:\"password\" = user password, optional, default - empty.");
            Console.WriteLine("     -UserFullName:\"full name\" = user full name, optional, default - Name.");
            Console.WriteLine("     -UserRights:\"rights\" = user rights, optional, default - empty.");
            Console.WriteLine("     -UserInterface:\"interface\" = user interface, optional, default - empty.");
            Console.WriteLine("     -UserDirectory:\"path\" = path to user directory, optional, default - empty.");
            Console.WriteLine("\r\n [list options] ");
            Console.WriteLine("     -lf:csv|xml|txt|ssv = show list in CSV (comma separated), XML, plaintext or 'SSV' (semicolon separated) format, default - txt");
            Console.WriteLine("     -sm = show only list, suppress all service messages");
            Console.WriteLine("     -sh = show headers (for csv format)");
            Console.WriteLine("");
            Console.WriteLine(Path.GetFileName(Application.ExecutablePath).ToLower() + " [/h|-h|/?|-?] - for this screen ");
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        enum listOutputFormat
        { 
            TXT = 0,
            CSV,
            XML,
            SSV
        }

        enum databaseformat 
        { 
            DBF,
            SQL,
            Undefined
        }

        [STAThread]
        static void Main(string[] args) 
        {

            string USRfileName = string.Empty;
            string Connect = string.Empty;
            string DBCatalog = string.Empty;
            string DBAfileName = string.Empty;
            //Флаги
            bool bCreateNew = false;
            bool bShowlist = false;
            bool bShowDBA = false;
            bool bAddUser = false;
            bool bChangeUser = false;
            bool bDeleteUser = false;
            bool bRewriteFile = false;
            bool bSuppressMessages = false;
            bool bWaitKeyPress = false;
            bool bShowListHeader = false;
            bool bLoadFromXml = false;

            databaseformat DBFormat = databaseformat.Undefined;
            listOutputFormat lOutputFormat = listOutputFormat.TXT;

            //параметры учетной записи
            string userName = string.Empty;
            string userNewName = string.Empty;
            string userFullName = string.Empty;
            string userPassword = string.Empty;
            string userPasswordHash = string.Empty;
            string userRights = string.Empty;
            string userInterface = string.Empty;
            string userDirectory = string.Empty;
            string XmlFileNAme = string.Empty;
            
            if (args.Length != 0)
            {
                string parameter = string.Empty;
                for (int i = 0; i < args.Length; i++)
                {
                    parameter = args[i];

                    switch (parameter.Split(':')[0].Replace("/","-").ToLower())
                    {
                        case "-f":
                            {
                                USRfileName = parameter.Substring(3).Replace("\"", "").Replace("'", "");
                                break;
                            }
                        case "-d":
                            {
                                DBCatalog = parameter.Substring(3).Replace("\"", "").Replace("'", "");
                                break;
                            }
                        case "-l":
                        case "-list":
                            {
                                bShowlist = true;
                                break;
                            }
                        case "-w":
                            {
                                bWaitKeyPress = true;
                                break;
                            }
                        case "-lf":
                            { 
                                if (parameter.Split(':').Length > 1)
                                    switch(parameter.Split(':')[1].ToLower())
                                    { 
                                        case "csv":
                                            lOutputFormat = listOutputFormat.CSV;
                                            break;
                                        case "xml":
                                            lOutputFormat = listOutputFormat.XML;
                                            break;
                                        case "ssv":
                                            lOutputFormat = listOutputFormat.SSV;
                                            break;
                                        case "txt":
                                        default:
                                            break;

                                    }
                                break;
                            }
                        case "-sh":
                            {
                                bShowListHeader = true;
                                break;
                            }
                        case "-sm":
                            {
                                bSuppressMessages = true;
                                break;
                            }
                        case "-dba":
                            {
                                bShowDBA = true;
                                break;
                            }
                        case "-add":
                            {
                                bAddUser = true;
                                break;
                            }
                        case "-change":
                            {
                                bChangeUser = true;
                                break;
                            }
                        case "-delete":
                            {
                                bDeleteUser = true;
                                break;
                            }
                        case "-r":
                            {
                                bRewriteFile = true;
                                break;
                            }
                        case "-loadfromxml":
                            {
                                if (parameter.Split(':').Length < 2)
                                {
                                    Console.WriteLine("ERROR parsing parameter {0}. ", parameter);
                                    return;
                                }
                                XmlFileNAme = parameter.Split(':')[1].Replace("'", "").Replace("<", "").Replace(">", "");
                                if (File.Exists(XmlFileNAme))
                                {
                                    bLoadFromXml = true;
                                }
                                break;
                            }
                        case "-username":
                            {
                                if (parameter.Split(':').Length < 2)
                                {
                                    Console.WriteLine("ERROR parsing parameter {0}. ", parameter);
                                    return;
                                }
                                userName = parameter.Split(':')[1].Replace("'","").Replace("<","").Replace(">","");
                                break;
                            }
                        case "-usernewname":
                            {
                                if (parameter.Split(':').Length < 2)
                                {
                                    Console.WriteLine("ERROR parsing parameter {0}. ", parameter);
                                    return;
                                }
                                userNewName = parameter.Split(':')[1].Replace("'", "").Replace("<", "").Replace(">", "");
                                break;
                            }
                        case "-userfullname":
                            {
                                if (parameter.Split(':').Length < 2)
                                {
                                    Console.WriteLine("ERROR parsing parameter {0}. ", parameter);
                                    return;
                                }
                                userFullName = parameter.Split(':')[1].Replace("'", "").Replace("<", "").Replace(">", "");
                                break;
                            }
                        case "-userpassword":
                            {
                                if (parameter.Split(':').Length < 2)
                                {
                                    Console.WriteLine("ERROR parsing parameter {0}. ", parameter);
                                    return;
                                }
                                userPassword = parameter.Split(':')[1].Replace("'", "").Replace("<", "").Replace(">", "");
                                userPasswordHash = UserDefworks.GetStringHash(userPassword);
                                break;
                            }
                        case "-hash":
                            {
                                if (parameter.Split(':').Length < 2)
                                {
                                    Console.WriteLine("ERROR parsing parameter {0}. ", parameter);
                                    return;
                                }
                                userPasswordHash = parameter.Split(':')[1].Replace("'", "").Replace("<", "").Replace(">", "");
                                if (userPasswordHash.Length != 32 && userPasswordHash.Length != 3)
                                {
                                    Console.WriteLine("Не стоит задавать хэш напрямую, тем более неправильный.");
                                    return;
                                }
                                break;
                            }
                        case "-userrights":
                            {
                                if (parameter.Split(':').Length < 2)
                                {
                                    Console.WriteLine("ERROR parsing parameter {0}. ", parameter);
                                    return;
                                }
                                userRights = parameter.Split(':')[1].Replace("'", "").Replace("<", "").Replace(">", "");
                                break;
                            }
                        case "-userinterface":
                            {
                                if (parameter.Split(':').Length < 2)
                                {
                                    Console.WriteLine("ERROR parsing parameter {0}. ", parameter);
                                    return;
                                }
                                userInterface = parameter.Split(':')[1].Replace("'", "").Replace("<", "").Replace(">", "");
                                break;
                            }
                        case "-userdirectory":
                            {
                                if (parameter.Split(':').Length < 2)
                                {
                                    Console.WriteLine("ERROR parsing parameter {0}. ", parameter);
                                    return;
                                }
                                userDirectory = parameter.Split(':')[1].Replace("'", "").Replace("<", "").Replace(">", "");
                                break;
                            }
                        case "-?":
                        case "-h":
                            PrintHelp();
                            return;
                        default:
                            Console.WriteLine("ERROR: Unknown parameter {0}", parameter);
                            break;
                    }
                }
            }

            if (USRfileName == string.Empty)
            {
                PrintHelp();
                return;
            }
            if(!bSuppressMessages)
                Console.WriteLine("Userdef Utility (c) MadDAD 2014\r\n");

            if (USRfileName != string.Empty)
            {
                if (!File.Exists(USRfileName))
                {
                    if (!bSuppressMessages)
                    {
                        Console.WriteLine("File \"" + USRfileName + "\" not exists. ");
                        Console.WriteLine("\r\nWill be created...");
                    }
                    bCreateNew = true;
                }
                DBCatalog = Path.GetDirectoryName(USRfileName);
                if (DBCatalog != "")
                    DBCatalog = Path.GetDirectoryName(DBCatalog) + "\\";
                else
                {
                    
                    string lDBCatalog = Path.GetDirectoryName(Application.ExecutablePath);
                    if (lDBCatalog != "")
                        lDBCatalog = Path.GetDirectoryName(lDBCatalog) + "\\";
                    if (File.Exists(lDBCatalog + "1cv7.md"))
                    {
                        DBCatalog = lDBCatalog;
                        USRfileName = Path.GetDirectoryName(Application.ExecutablePath) + "\\" + USRfileName;
                    }
                }
            }
            else if (DBCatalog != string.Empty)
            { 
                if (DBCatalog.Substring(DBCatalog.Length)!="\\")
                    DBCatalog+="\\";

                USRfileName = DBCatalog + "userdef\\users.usr";
                if (!File.Exists(USRfileName))
                    bCreateNew = true;
            }
            
            DBAfileName = DBCatalog + "1cv7.dba";
            if (!bSuppressMessages)
                Console.WriteLine("Processing file: {0} ", USRfileName);
            
            if (File.Exists(DBCatalog + "1cv7.dd"))
            {
                if (!bSuppressMessages)
                {
                    Console.WriteLine("Database directory: {0}", DBCatalog);
                    Console.WriteLine("Database format: DBF");
                }
                DBAfileName = string.Empty;
                DBFormat = databaseformat.DBF;
            }
            else if (File.Exists(DBCatalog + "1cv7.dds"))
            {
                if (!bSuppressMessages)
                {
                    Console.WriteLine("Database directory: {0}", DBCatalog);
                    Console.WriteLine("Database format: SQL");
                }
                DBFormat = databaseformat.SQL;
                if (bShowDBA)
                    if (!bSuppressMessages)
                        Console.WriteLine("Decrypted DBA: {0}", UserDefworks.ReadDBA(DBAfileName));
            }
            else if (File.Exists(DBCatalog + "1cv7.md"))
            {
                DBFormat = databaseformat.Undefined;
                if (!bSuppressMessages)
                    Console.WriteLine("Database format: unknown (metdata dictionary is not found)");
            }
            else
            {
                if (!bSuppressMessages)
                    Console.WriteLine("Database directory is not found.");
                if (bShowDBA)
                    if (!bSuppressMessages)
                        Console.WriteLine("flag (-dba) ignored...");
            }
            
            UserDefworks.UsersList Users;

            if (!bCreateNew)
            {
                try
                {
                    //Прочитаем список пользователей из переданного файла
                    Users = new UserDefworks.UsersList(USRfileName);
                }
                catch (Exception ex)
                { 
                    Console.WriteLine(ex.Message);
                    return;
                }
            }
            else
            {
                //Создадим пустой список пользователей
                Users = new  UserDefworks.UsersList();
            }

            if (bLoadFromXml)
            {
                if (!bSuppressMessages)
                {
                    Console.WriteLine("Хитрец, нашел таки. Грузим список из XML {0}", XmlFileNAme);
                    Console.WriteLine("Файл users.usr будет пересоздан. Старый будет сохранен в users.usr.old.");
                }
                UserDefworks.UserItem User = null;
                UserDefworks.UserParameters Param = UserDefworks.UserParameters.Header;
                Dictionary<string, UserDefworks.UserParameters> Params = new Dictionary<string, UserDefworks.UserParameters>();

                for (UserDefworks.UserParameters i = UserDefworks.UserParameters.DontCheckRights; i <= UserDefworks.UserParameters.UserRights; i++)
                    Params.Add(i.ToString(), i);

                XmlTextReader reader = new XmlTextReader(XmlFileNAme);
                while (reader.Read())
                {
                    switch (reader.NodeType)
                    {
                        case XmlNodeType.Element:
                            switch (reader.Name)
                            {
                                case "UserdefList":
                                    Users = new UserDefworks.UsersList();
                                    if (File.Exists(USRfileName))
                                    {
                                        if (File.Exists(USRfileName + ".old"))
                                            File.Delete(USRfileName + ".old");
                                        File.Move(USRfileName, USRfileName + ".old");
                                    }
                                    break;
                                case "UserItemType":
                                    User = new UserDefworks.UserItem(Name:reader.GetAttribute("UserName"),PageName:reader.GetAttribute("StreamName"));
                                    break;
                                default:
                                    Param = Params[reader.Name];
                                    break;
                            }
                            break;
                        case XmlNodeType.Text: // Вывести текст в каждом элементе.
                            switch (Param)
                            {   case UserDefworks.UserParameters.DontCheckRights:
                                case UserDefworks.UserParameters.RightsEnabled:
                                     User.SetParam(Param, Int32.Parse(reader.Value));
                                     break;
                                default:
                                     User.SetParam(Param, reader.Value);
                                     break;
                            }
                            break;
                        case XmlNodeType.EndElement: // Вывести конец элемента.
                            switch (reader.Name)
                            {
                                case "UserItemType":
                                    Users.Add(User);
                                    break;
                                default:
                                    break;
                            }
                            break;
                    }
                }
            }

            if (bAddUser)
            {
                if (userName == string.Empty)
                {
                    if (!bSuppressMessages)
                        Console.WriteLine("UserName is empty. Flag (-add) ignored.");
                }
                else if (Users.ContainsKey(userName)) //проверим наличие пользователя в списке.
                {
                    if (!bSuppressMessages)
                        Console.WriteLine("User account '{0}' already exists in user list. Use flag (-change) instead (-add)", userName);
                }
                else
                {
                   // userPasswordHash = UserDefworks.GetStringHash(userPassword);
                    Users.Add(new UserDefworks.UserItem("UserItem."+userName.Replace(" ",""), 1, userPasswordHash, userFullName, userDirectory, userInterface, userRights, userName));
                }
            }
            else if (bChangeUser)
            {
                if (userName == string.Empty)
                {
                    if (!bSuppressMessages)
                        Console.WriteLine("UserName is empty. Flag (-change) ignored.");
                }
                else if (!Users.ContainsKey(userName)) //проверим наличие пользователя в списке.
                {
                    if (!bSuppressMessages)
                        Console.WriteLine("User account '{0}' not found in user list. Flag (-change) ignored.",userName);
                }
                else
                {
                    if (userNewName != string.Empty)
                        Users[userName].Name = userNewName;
                    //if (userPassword != string.Empty)
                    //    Users[userName].PasswordHash = UserDefworks.GetStringHash(userPassword);
                    if (userPasswordHash != string.Empty)
                        Users[userName].PasswordHash = userPasswordHash;
                    if (userFullName != string.Empty)
                        Users[userName].FullName = userFullName;
                    if (userDirectory != string.Empty)
                        Users[userName].UserCatalog = userDirectory;
                    if (userInterface != string.Empty)
                        Users[userName].UserInterface = userInterface;
                    if (userRights != string.Empty)
                        Users[userName].UserRights = userRights;
                    Users.modified = true;
                }
            }
            else if (bDeleteUser)
            { 
                if (userName == string.Empty)
                {
                    if (!bSuppressMessages)
                        Console.WriteLine("UserName is empty. Flag (-delete) ignored.");
                }
                else if (!Users.ContainsKey(userName)) //проверим наличие пользователя в списке.
                {
                    if (!bSuppressMessages)
                        Console.WriteLine("User account '{0}' not found in user list. Flag (-delete) ignored.", userName);
                }
                else
                {
                    Users.Remove(userName);
                }
            }

            if(bShowlist)
                    switch (lOutputFormat)
                    {
                        case listOutputFormat.TXT:
                            {
                                foreach (UserDefworks.UserItem User in Users.Values)
                                {
                                    Console.WriteLine("Учетная запись = {0}", User.Name);
                                    for (UserDefworks.UserParameters i = UserDefworks.UserParameters.Header; i <= UserDefworks.UserParameters.UserRights; i++)
                                    {
                                        Console.WriteLine("   {0} = {1} ", UserDefworks.UserParamNames[i], User.GetParam(i));
                                    }
                                }

                                break;
                            }
                        case listOutputFormat.SSV:
                            {
                                if (bShowListHeader)
                                {
                                    Console.Write("UserName");
                                    for (UserDefworks.UserParameters i = UserDefworks.UserParameters.DontCheckRights; i <= UserDefworks.UserParameters.UserRights; i++)
                                    {
                                        Console.Write(";{0}", i);
                                    }
                                }
                                foreach (UserDefworks.UserItem User in Users.Values)
                                {
                                    Console.Write("\r\n{0}", User.Name);
                                    for (UserDefworks.UserParameters i = UserDefworks.UserParameters.DontCheckRights; i <= UserDefworks.UserParameters.UserRights; i++)
                                    {
                                        Console.Write(";{0}", User.GetParam(i));
                                    }
                                }
                                break;
                            }
                        case listOutputFormat.CSV:
                            {
                                if (bShowListHeader)
                                {
                                    Console.Write("UserName");
                                    for (UserDefworks.UserParameters i = UserDefworks.UserParameters.DontCheckRights; i <= UserDefworks.UserParameters.UserRights; i++)
                                    {
                                        Console.Write(",{0}", i);
                                    }
                                }
                                foreach (UserDefworks.UserItem User in Users.Values)
                                {
                                    Console.Write("\r\n{0}", User.Name);
                                    for (UserDefworks.UserParameters i = UserDefworks.UserParameters.DontCheckRights; i <= UserDefworks.UserParameters.UserRights; i++)
                                    {
                                        Console.Write(",{0}", User.GetParam(i));
                                    }
                                }
                                break;
                            }

                        case listOutputFormat.XML:
                            {
                                Console.WriteLine("<?xml version=\"1.0\" encoding=\"cp866\"?>"); //, Encoding.GetEncoding(866).WebName
                                Console.WriteLine("<UserdefList Filename = \"{0}\" databaseformat=\"{1}\">", USRfileName, DBFormat);
                                foreach (UserDefworks.UserItem User in Users.Values)
                                {
                                    Console.WriteLine("     <UserItemType UserName = \"{0}\" StreamName=\"{1}\">", User.Name, User.PageName);
                                    for (UserDefworks.UserParameters i = UserDefworks.UserParameters.DontCheckRights; i <= UserDefworks.UserParameters.UserRights; i++)
                                    {
                                        Console.WriteLine("         <{0} description=\"{2}\">{1}</{0}>", i, User.GetParam(i), UserDefworks.UserParamNames[i]);
                                    }
                                    Console.WriteLine("     </UserItemType>");
                                }
                                Console.WriteLine("</UserdefList>");
                                break;
                            }
                    }
            if (bRewriteFile)
                Users.modified = true;

            try
            {
                if (Users.modified)
                     if (Users.Save(USRfileName))
                         if (!bSuppressMessages)
                            Console.WriteLine("File {0} written. New checksum = {1}", USRfileName, UserDefworks.CheckSum(USRfileName));
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            if (bWaitKeyPress)
            {
                if (!bSuppressMessages)
                    Console.WriteLine("\r\nPress any key to exit...");
                Console.ReadKey();
            }
        }
    }
}
