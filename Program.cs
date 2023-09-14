using System;
using System.Threading;

/*
	BlitzWare C# example
	Please read our docs at https://docs.blitzware.xyz/
*/

namespace BlitzWare
{
    class Program
    {
        public static API BlitzWareAuth = new(
            apiUrl: "https://api.blitzware.xyz/api",
            appName: "NAME",
            appSecret: "SECRET",
            appVersion: "VERSION"
        );

        static void Main(string[] args)
        {
            Console.WriteLine("\n\nConnecting...");
            BlitzWareAuth.Initialize();
            Console.WriteLine("Connected!");

            Console.Write("\n[1] Login\n[2] Register\n[3] Upgrade\n[4] License key only \n\nChoose option: ");

            string username, email, password, twoFactorCode, key;

            int option = int.Parse(Console.ReadLine());
            switch (option)
            {
                case 1:
                    Console.Write("\n\nEnter username: ");
                    username = Console.ReadLine();
                    Console.Write("\n\nEnter password: ");
                    password = Console.ReadLine();
                    Console.Write("\n\nEnter 2FA (if enabled): ");
                    twoFactorCode = Console.ReadLine();
                    if (!BlitzWareAuth.Login(username, password, twoFactorCode))
                        Environment.Exit(0);
                    BlitzWareAuth.Log(username, "User logged in");
                    break;
                case 2:
                    Console.Write("\n\nEnter username: ");
                    username = Console.ReadLine();
                    Console.Write("\n\nEnter password: ");
                    password = Console.ReadLine();
                    Console.Write("\n\nEnter email: ");
                    email = Console.ReadLine();
                    Console.Write("\n\nEnter license: ");
                    key = Console.ReadLine();
                    if (!BlitzWareAuth.Register(username, password, email, key))
                        Environment.Exit(0);
                    BlitzWareAuth.Log(username, "User registered");
                    break;
                case 3:
                    Console.Write("\n\nEnter username: ");
                    username = Console.ReadLine();
                    Console.Write("\n\nEnter password: ");
                    password = Console.ReadLine();
                    Console.Write("\n\nEnter license: ");
                    key = Console.ReadLine();
                    if (!BlitzWareAuth.Extend(username, password, key))
                        Environment.Exit(0);
                    BlitzWareAuth.Log(username, "User extended");
                    break;
                case 4:
                    Console.Write("\n\nEnter license: ");
                    key = Console.ReadLine();
                    if (!BlitzWareAuth.LoginLicenseOnly(key))
                        Environment.Exit(0);
                    BlitzWareAuth.Log(key, "User login with license");
                    break;
                default:
                    Console.WriteLine("\n\nInvalid Selection");
                    Thread.Sleep(3000);
                    Environment.Exit(0);
                    break;
            }

            Console.WriteLine("\nUser data:");
            Console.WriteLine("Username: " + BlitzWareAuth.userData.Username);
            Console.WriteLine("Email: " + BlitzWareAuth.userData.Email);
            Console.WriteLine("IP-address: " + BlitzWareAuth.userData.LastIP);
            Console.WriteLine("Hardware-Id: " + BlitzWareAuth.userData.HWID);
            Console.WriteLine("Last login: " + BlitzWareAuth.userData.LastLogin);
            Console.WriteLine("Subscription expiry: " + BlitzWareAuth.userData.ExpiryDate);

            //BlitzWareAuth.DownloadFile("fdf07f63-af97-4813-b025-2cfc9638ce23");

            Console.WriteLine("\nClosing in five seconds...");
            Thread.Sleep(5000);
            Environment.Exit(0);
        }
    }
}