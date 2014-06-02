using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;


namespace UserDefworks
{

    [ComImport]
    [Guid("0000000d-0000-0000-C000-000000000046")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IEnumSTATSTG
    {
        // The user needs to allocate an STATSTG array whose size is celt.
        [PreserveSig]
        uint Next(uint celt,
                    [MarshalAs(UnmanagedType.LPArray), Out]
    	        System.Runtime.InteropServices.ComTypes.STATSTG rgelt,
                    out uint pceltFetched);

        void Skip(uint celt);
        void Reset();

        [return: MarshalAs(UnmanagedType.Interface)]
        IEnumSTATSTG Clone();
    }
    public class StgStorage
    {

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


        [DllImport("ole32.dll")]
        public static extern int StgIsStorageFile([MarshalAs(UnmanagedType.LPWStr)]
    	                                        string pwcsName);

        [DllImport("ole32.dll")]
        public static extern int StgOpenStorage([MarshalAs(UnmanagedType.LPWStr)]
    	                                string pwcsName,
                                            IStorage pstgPriority,
                                            STGM grfMode,
                                            IntPtr snbExclude,
                                            uint reserved,
                                            out IStorage ppstgOpen);
    }
    
    [ComImport]
    [Guid("0000000b-0000-0000-C000-000000000046")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IStorage
    {
        void CreateStream(string pwcsName, uint grfMode, uint reserved1,
                            uint reserved2, out IStream ppstm);

        void OpenStream(string pwcsName, IntPtr reserved1, uint grfMode,
                        uint reserved2, out IStream ppstm);

        void CreateStorage(string pwcsName, uint grfMode, uint reserved1,
                            uint reserved2, out IStorage ppstg);

        void OpenStorage(string pwcsName, IStorage pstgPriority, uint grfMode,
                            IntPtr snbExclude, uint reserved, out IStorage ppstg);

        void CopyTo(uint ciidExclude, Guid rgiidExclude, IntPtr snbExclude,
                    IStorage pstgDest);

        void MoveElementTo(string pwcsName, IStorage pstgDest,
                            string pwcsNewName, uint grfFlags);

        void Commit(uint grfCommitFlags);

        void Revert();

        void EnumElements(uint reserved1, IntPtr reserved2, uint reserved3,
                            out IEnumSTATSTG ppenum);

        void DestroyElement(string pwcsName);

        void RenameElement(string pwcsOldName, string pwcsNewName);

        void SetElementTimes(string pwcsName,
                            System.Runtime.InteropServices.ComTypes.FILETIME pctime,
                                System.Runtime.InteropServices.ComTypes.FILETIME patime,
                                System.Runtime.InteropServices.ComTypes.FILETIME pmtime);

        void SetClass(Guid clsid);

        void SetStateBits(uint grfStateBits, uint grfMask);

        void Stat(out System.Runtime.InteropServices.ComTypes.STATSTG pstatstg,
                    uint grfStatFlag);
    }

    public class Lock
    {
        public IStorage OpenStorage(string fileName)
        {
            if (StgStorage.StgIsStorageFile(fileName) != 0)
            {
                return null;
            }

            IStorage storage = null;

            //
            // StgOpenStorage() locks file 'fileName'
            //
            // Set flags like:
            // [http://stackoverflow.com/questions/1086814/opening-ole-compound-documents-read-only-with-stgopenstorage]
            //
            int stgOpenStorage = StgStorage.StgOpenStorage(fileName, null,
                                                StgStorage.STGM.READ |
                                                StgStorage.STGM.SHARE_DENY_NONE |
                                                StgStorage.STGM.TRANSACTED,
                                                IntPtr.Zero, 0,
                                                out storage);

            //
            // Try to rename file (for testing purposes only)
            //
            try
            {
                File.Move(fileName, fileName + @".renamed");
            }
            catch (Exception ex)
            {		// exception: file alreay in use by another process
                throw;
            }

            if (stgOpenStorage != 0)
            {
                return null;
            }
            else
            {
                return storage;
            }
        }
    }

    class Program
    {
        static void PrintHelp()
        {
            Console.WriteLine("Usage: "+ Path.GetFileName(Application.ExecutablePath).ToLower()  +" [/f|-f:<1CDatabasePath>\\usrdef\\users.usr]\r\n Where:\r\n - <1CDatabasePath> : full path to 1C database catalog.");
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

        static string DecryptDBA(string DBAfileName)
        {
            byte[] encryptedDBA = File.ReadAllBytes(DBAfileName);
            byte[] SQLKey = Encoding.ASCII.GetBytes("19465912879oiuxc ensdfaiuo3i73798kjl");
            string Connect = string.Empty;
            for (int i = 0; i < encryptedDBA.Length; i++)
            {
                Connect += (char)(encryptedDBA[i] ^ SQLKey[i % 36]);
            }
            return Connect;
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
                string Connect = DecryptDBA(DBAfileName);
                Console.WriteLine("Decrypted DBA: " + Connect);

                //вычислим Checksum 
                string crc = CheckSum(USRfileName);
                Console.WriteLine("Checksum: {0}", crc); 

            }

            IStorage storage = null;
            IStorage Page_storage = null;
            IStorage Page1_storage = null;

            int IsStorage = StgStorage.StgIsStorageFile(USRfileName);

            if (IsStorage == 0)
            {
                int stgOpenStorage = StgStorage.StgOpenStorage(USRfileName, null,
                                                    StgStorage.STGM.READ |
                                                    StgStorage.STGM.SHARE_DENY_NONE |
                                                    StgStorage.STGM.TRANSACTED,
                                                    IntPtr.Zero, 0,
                                                    out storage);
                if (stgOpenStorage == 0)
                {


                    storage.OpenStorage("Container.Cotents", Page_storage, 0, IntPtr.Zero, 0, out Page1_storage);
                    IStream stt;
                    storage.OpenStream("Container.Cotents",IntPtr.Zero, 0, 0, out stt);

                    byte[] buf;
                    ulong read;
                    string str = stt.Read(buf, 255, ref read);

                    IEnumSTATSTG ppStgEnum = null;
                    System.Runtime.InteropServices.ComTypes.STATSTG Data = null;
                    storage.EnumElements(0, IntPtr.Zero, 0, out ppStgEnum);
                    uint i=0;

                    while (ppStgEnum.Next(1, Data, out i) != 0) 
                    {
                        Console.WriteLine("{0} = {1}", Data[0], Data[1]);
                    }
                }
                else
                    Console.WriteLine("\r\nError opening {0}", USRfileName);
            }

            Console.WriteLine("\r\nPress any key to exit...");
            Console.ReadKey();
        }
    }
}
