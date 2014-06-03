using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography;


namespace UserDefworks
{

    [ComImport]
    [Guid("0000000d-0000-0000-C000-000000000046")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IEnumSTATSTG
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
    public enum STGM : int
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

    public enum STATFLAG : uint
    {
        STATFLAG_DEFAULT = 0,
        STATFLAG_NONAME = 1,
        STATFLAG_NOOPEN = 2
    }

    public enum STGTY : int
    {
        STGTY_STORAGE = 1,
        STGTY_STREAM = 2,
        STGTY_LOCKBYTES = 3,
        STGTY_PROPERTY = 4
    }

    public enum tagSTGC :int
    { 
      STGC_DEFAULT                             = 0,
      STGC_OVERWRITE                           = 1,
      STGC_ONLYIFCURRENT                       = 2,
      STGC_DANGEROUSLYCOMMITMERELYTODISKCACHE  = 4,
      STGC_CONSOLIDATE                         = 8
    };
    
    class Program
    {

        [DllImport("ole32.dll")]
        private static extern int StgIsStorageFile(
            [MarshalAs(UnmanagedType.LPWStr)] string pwcsName);

        [DllImport("ole32.dll")]
        static extern int StgOpenStorage(
            [MarshalAs(UnmanagedType.LPWStr)] string pwcsName,
            IStorage pstgPriority,
            STGM grfMode,
            IntPtr snbExclude,
            uint reserved,
            out IStorage ppstgOpen);


        public static string GetStringHash(string instr)
        {
            if (instr.Length == 0)
                return "233";
            string strHash = string.Empty;
            foreach (byte b in new MD5CryptoServiceProvider().ComputeHash(Encoding.Default.GetBytes(instr)))
            {
                strHash += b.ToString("X2");
            }
            return strHash;
        }        
        
        enum UserParameters
        {
            n = 0,
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
            ПустойПараметр = 0,
            ОтключитьКонтрольПрав,
            ХэшПароля,
            ПолноеИмя,
            КаталогПользователя,
            ЗаданыПрава,
            Интерфейс,
            НаборПрав
        }

        //Возвращаяет позицию параметра указзаного номера в потоке 
        // 1 - контролировать права
        // 2 - хэш пароля
        // 3 - Полное имя пользователя
        // 4 - каталог
        // 5 - интерфейс
        // 6 - Набор прав

        static int GetPos(byte[] data, int Param)
        {
            int StartPosition = 0;
            int Count = 0;
            while (Count != (int)Param)
            {
                if (StartPosition >= data.Length)
                     return 0;
                if (StartPosition < 8)
                {
                    StartPosition += 4;
                    Count++;
                }
                else
                {
                    if (data[StartPosition] == 1 && Count == 5)
                    { 
                        StartPosition += 4; 
                    }
                    else
                    {
                        StartPosition = StartPosition + data[StartPosition] + 1;
                    }
                    
                    Count++;
                }
            }
            return StartPosition;
        }

        static object GetParam(byte[] data, UserParameters paramNuber)
        {
            object param = string.Empty;

            int paramstart = GetPos(data, (int) paramNuber);
            if (paramNuber == UserParameters.DontCheckRights)
            {
                param = (int)(1 - data[paramstart]);
            }
            else if (paramNuber == UserParameters.RightsEnabled)
            {
                param = (int)(data[paramstart]); 
            }
            else
                param = Encoding.Default.GetString(data).Substring(paramstart + 1, data[paramstart]);
            return param;
        }


        static void PrintHelp()
        {
            Console.WriteLine("Usage: "+ Path.GetFileName(Application.ExecutablePath).ToLower()  +" [/f|-f:<1CDatabasePath>\\usrdef\\users.usr] [-l|/l]\r\n   <1CDatabasePath> : full path to 1C database catalog.");
            Console.WriteLine("\r\n -l - list \"userdef.usr\" contents");
            Console.WriteLine("");
            Console.WriteLine("\r\n" + Path.GetFileName(Application.ExecutablePath).ToLower() + " [/h|-h|/?|-?] - for this screen ");
            Console.WriteLine("\r\nPress any key to exit...");
            Console.ReadKey();
        }



        static string CheckSum(string USRfileName)
        {
            byte[] Users_usr = File.ReadAllBytes(USRfileName);
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
            return Convert.ToString(crc, 16);
        }

        static string ReadDBA(string DBAfileName)
        {
            byte[] ByteBuffer = File.ReadAllBytes(DBAfileName);
            byte[] SQLKey = Encoding.ASCII.GetBytes("19465912879oiuxc ensdfaiuo3i73798kjl");
            for (int i = 0; i < ByteBuffer.Length; i++)
            {
                ByteBuffer[i] = (byte)(ByteBuffer[i] ^ SQLKey[i % 36]);
             //   Connect += (char)(encryptedDBA[i] ^ SQLKey[i % 36]);
            }
            string Connect = Encoding.ASCII.GetString(ByteBuffer);
            return Connect;
        }


        static bool WriteDBA(string DBAfileName, string Connect)
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


        static byte[] ReadIStream(IStream pIStream)
        {
            System.Runtime.InteropServices.ComTypes.STATSTG StreamInfo;
            pIStream.Stat(out StreamInfo, 0);
            byte[] data = new byte[StreamInfo.cbSize + 1];
            pIStream.Read(data, (int)StreamInfo.cbSize, IntPtr.Zero);

            return data;
        }
        
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct PascalString 
        {   
            public byte   Length;
            public byte[] Value;

            public PascalString(string InStr)
            {
                Value = Encoding.Default.GetBytes(InStr);
                Length = (byte)Value.Length;
            }

            public static implicit operator PascalString(string InStr) 
            {
                return new PascalString(InStr);
            }

            public void FromString(string InStr) 
            {
                Value = Encoding.Default.GetBytes(InStr);
                Length = (byte)(Value.Length-1);
            }


            override public string ToString()
            {
                return Encoding.Default.GetString(Value);
            }

            public byte[] Serialyse()
            {
                byte[] ByteBuffer = new byte[Length + 1];
                ByteBuffer[0] = Length;
                for (int i = 1; i < ByteBuffer.Length; i++)
                    ByteBuffer[i] = Value[i - 1];

                return ByteBuffer;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct UserItem 
        {
            public string Name;
            private static int Spacer = 1;
            public static int CheckRights = 1;
            public PascalString HashCode;
            public PascalString FullName;
            public PascalString UserCatalog;
            public static int RightsEnabled = 1;
            public PascalString Interface;
            public PascalString Rights;

            public UserItem(byte[] data)
            {
                Name = "";
                CheckRights = (int)GetParam(data, UserParameters.DontCheckRights);
                HashCode = new PascalString((string)GetParam(data , UserParameters.PasswordHash));
                FullName = new PascalString((string)GetParam(data, UserParameters.FullName));
                UserCatalog = new PascalString((string)GetParam(data, UserParameters.UserCatalog));
                RightsEnabled = (int)GetParam(data, UserParameters.RightsEnabled);
                Interface = new PascalString((string)GetParam(data, UserParameters.UserInterface));
                Rights = new PascalString((string)GetParam(data, UserParameters.UserRights));
            }

            public byte[] Serialyse()
            {
                int rawsize = 17 + HashCode.Length + FullName.Length + UserCatalog.Length + Interface.Length + Rights.Length;
                byte[] rawdata = new byte[rawsize];
                byte[] buffer;
                int lastCount = 0;

                buffer = BitConverter.GetBytes(Spacer);
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

                return rawdata;
            }
        }

        static void Main(string[] args)
        {
            Console.WriteLine("Userdef Works utility (c) MadDAD 2014\r\n");

            string USRfileName = string.Empty;
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

            bool IsSQL = false;
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
                IsSQL = true;
                string Connect = ReadDBA(DBAfileName);
                Console.WriteLine("Decrypted DBA: " + Connect);

                //вычислим Checksum 
                string crc = CheckSum(USRfileName);
                Console.WriteLine("Checksum: {0}", crc); 
            }


            if (StgIsStorageFile(USRfileName) == 0)
            {
                IStorage storage = null;
                if (StgOpenStorage(USRfileName,null,STGM.DIRECT | STGM.READ | STGM.SHARE_EXCLUSIVE,IntPtr.Zero,0,out storage) == 0)
                {
                    uint fetched = 0;
                    IStream pIStream = null;
                    IEnumSTATSTG pIEnumStatStg = null;
                    string Container = string.Empty;
                      System.Runtime.InteropServices.ComTypes.STATSTG statstg = new System.Runtime.InteropServices.ComTypes.STATSTG();
                    System.Runtime.InteropServices.ComTypes.STATSTG[] regelt = {statstg};


                    storage.Stat(out statstg, (uint)STATFLAG.STATFLAG_DEFAULT);
                    storage.EnumElements(0, IntPtr.Zero, 0, out pIEnumStatStg);
                    storage.OpenStream("Container.Contents", IntPtr.Zero, (uint)(STGM.READ | STGM.SHARE_EXCLUSIVE), 0, out pIStream);

                    byte[] data = ReadIStream(pIStream); 
                    Marshal.ReleaseComObject(pIStream);
                    Container = Encoding.Default.GetString(data, 0, data.Length);
                    Console.WriteLine(Container);

                    while (pIEnumStatStg.Next(1, regelt, out fetched) == 0)
                    {
                        string filePage = regelt[0].pwcsName;
                        string UserName = "";

                        if (filePage == "Container.Contents")
                        {
                            break;
                        }
                        Console.WriteLine("{0} - {1}", ((STGTY)regelt[0].type).ToString(), filePage);

                        if ((STGTY)regelt[0].type == STGTY.STGTY_STREAM)
                        {
                            //UserContainer = UserContainer.Replace("{\"Container.Contents\",{", "");
                            //UserContainer = UserContainer.Replace("}}", "");
                            //UserContainer = UserContainer.Replace("},{", ";");
                            //foreach (string UserItem in UserContainer.Split(';'))
                                //string UserName = (string)UserItem.Split(',').GetValue(2);
                                //UserName = UserName.Replace("\"", "");
                                //string UserPage = (string)UserItem.Split(',').GetValue(1);
                                    
                            storage.OpenStream(filePage,IntPtr.Zero,(uint)(STGM.READ | STGM.SHARE_EXCLUSIVE),0,out pIStream);
                            if (pIStream != null)
                            {
                                data = ReadIStream(pIStream);
                                Marshal.ReleaseComObject(pIStream);

                                Console.WriteLine("-----------{0}-----------", UserName);
                                for (int i = 0; i <= (int)UserParameters.UserRights; i++)
                                {
                                    Console.WriteLine(" {0} = {1}", (UserParamNames)i, GetParam(data, (UserParameters)i));
                                }
                                Console.WriteLine("-------------------------", UserName);

                                UserItem User = new UserItem();
                                User.Name = "test.bin";
                                User.FullName = "Иванов Иван Иванович";
                                User.HashCode = GetStringHash("123");
                                User.Interface = "Полный";
                                User.Rights = "Администратор";
                                User.UserCatalog = string.Empty;

                                byte[] ByteBuffer = User.Serialyse();

                                File.WriteAllBytes(User.Name, ByteBuffer);

                            }

                        }
                    }
                }
            }

            Console.WriteLine("\r\nPress any key to exit...");
            Console.ReadKey();
        }
    }
}
