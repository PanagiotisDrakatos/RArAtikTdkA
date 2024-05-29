using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;


[assembly: System.Reflection.AssemblyCompanyAttribute("RArAtiTdkA")]
[assembly: System.Reflection.AssemblyConfigurationAttribute("Debug")]
[assembly: System.Reflection.AssemblyFileVersionAttribute("1.0.0.0")]
[assembly: System.Reflection.AssemblyInformationalVersionAttribute("1.0.0")]
[assembly: System.Reflection.AssemblyProductAttribute("RArAtiTdkA")]
[assembly: System.Reflection.AssemblyTitleAttribute("RArAtiTdkA")]
[assembly: System.Reflection.AssemblyVersionAttribute("1.0.0.0")]
[assembly: System.Runtime.InteropServices.Guid("f5847b1d-f1a3-4e05-9389-6f1d32de5432")]
namespace RArAtiTdkA
{
    
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new Form1());
        }
    }
}