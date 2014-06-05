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
using UserDefworks;

namespace Program
{
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

        [STAThread]
        static void Main(string[] args) 
        {
            Console.WriteLine("Userdef Works utility (c) MadDAD 2014\r\n");
            
            string USRfileName = string.Empty;
            string Connect = string.Empty;
            string DBCatalog = string.Empty;
            string DBAfileName = string.Empty;
            bool CreateNew = false;
            bool list = false;

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
                        case "d":
                            DBCatalog = parameter.Substring(3).Replace("\"", "").Replace("'", "");
                            break;
                        case "l":
                            list = true;
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

            if (USRfileName != string.Empty)
            {
                if (!File.Exists(USRfileName))
                {
                    Console.WriteLine("File \"" + USRfileName + "\" not exists. ");
                    Console.WriteLine("\r\nWill be created...");
                    //Console.ReadKey();
                    CreateNew = true;
                }
                DBCatalog = Path.GetDirectoryName(Path.GetDirectoryName(USRfileName)) + "\\";
            }
            else if (DBCatalog != string.Empty)
            { 
                if (DBCatalog.Substring(DBCatalog.Length)!="\\")
                    DBCatalog+="\\";

                USRfileName = DBCatalog + "userdef\\users.usr";
                if (!File.Exists(USRfileName))
                    CreateNew = true;
            }
            
            DBAfileName = DBCatalog + "1cv7.dba";
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
                Connect = UserDefworks.UserDefworks.ReadDBA(DBAfileName);
                Console.WriteLine("Decrypted DBA: " + Connect);
                //вычислим Checksum 
                Console.WriteLine("Checksum: {0}", UserDefworks.UserDefworks.CheckSum(USRfileName));
            }

            
            UserDefworks.UserDefworks.UsersList Users;
            if (!CreateNew)
            {
                //Прочитаем список пользователей из переданного файла
                Users = new UserDefworks.UserDefworks.UsersList(USRfileName);
            }
            else
            {
                //Создадим пустой список пользователей
                Users = new  UserDefworks.UserDefworks.UsersList();
            }

            string username = "Пользователь";

            if (Users.ContainsKey(username)) //проверим наличие пользователя в списке.
            {
                //Заменим пароль пользователю
                Users[username].PasswordHash = UserDefworks.UserDefworks.GetStringHash("qwerty");

                //Заменим пользователю полное имя
                Users[username].FullName = "Иванов Иван Иванович";
            }
            else
            {
                Users.Add(new UserDefworks.UserDefworks.UserItem("User", 1, UserDefworks.UserDefworks.GetStringHash("123"), "Петр Петрович Петров", "./", "Админ", "Администратор", "Пользователь 1"));
            }

            //Добавим нового пользователя
            Users.Add(new UserDefworks.UserDefworks.UserItem("User-2", 1, UserDefworks.UserDefworks.GetStringHash("123"), "Иван Иванович Иванов", "./", "Админ", "Администратор","Пользователь 2"));

            if(list)
                foreach (UserDefworks.UserDefworks.UserItem User in Users.Values)
                {
                    Console.WriteLine("-----------{0}-----------", User.Name);
                    for (UserDefworks.UserDefworks.UserParameters i = UserDefworks.UserDefworks.UserParameters.Header; i <= UserDefworks.UserDefworks.UserParameters.UserRights; i++)
                    {
                        Console.WriteLine("{0} : {1} ", UserDefworks.UserDefworks.UserParamNames[i], User.GetParam(i));
                    }
                    Console.WriteLine("-------------------------");
                }

            try
            {
                Users.Save(USRfileName);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            Console.WriteLine("\r\nPress any key to exit...");
            Console.ReadKey();
        }
    }
}