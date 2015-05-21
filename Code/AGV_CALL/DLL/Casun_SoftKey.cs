using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
//公共函数说明

//***查找加密锁 
//int FindPort(int start, ref string OutKeyPath);

//查找指定的加密锁(使用普通算法一)
//int FindPort_2(int start, int in_data, int verf_data, ref string OutKeyPath);

//查找指定的加密锁(使用普通算法二)
//int FindPort_3(int start, int in_data, int verf_data, ref string OutKeyPath);

//***获到锁的版本
//int NT_GetIDVersion(ref short version,  string KeyPath);

//获到锁的扩展版本
//int NT_GetIDVersionEx(ref short version,  string KeyPath);

//***获到锁的ID
//int GetID(ref int id_1, ref int id_2, string KeyPath);

//***从加密锁中读取一批字节
//int YReadEx(byte[] OutData, short Address, short mylen, string HKey, string LKey, string KeyPath);

//***从加密锁中读取一个字节数据，一般不使用
//int YRead(ref byte OutData, short Address,string HKey, string LKey, string KeyPath);

//***写一批字节到加密锁中
//int YWriteEx(byte[] InData, short Address, short mylen, string HKey, string LKey, string KeyPath);

//***写一个字节的数据到加密锁中，一般不使用
//int YWrite(byte InData, short Address, string HKey, string LKey, string KeyPath);

//***从加密锁中读字符串
//int YReadString(ref string outstring, short Address, short mylen, string HKey, string LKey, string KeyPath);

//***写字符串到加密锁中
//int YWriteString(string InString, short Address, string HKey, string LKey, string KeyPath);

//***算法函数
//int sWriteEx_New(int in_data , ref int out_data , string KeyPath);
//int sWrite_2Ex_New(int in_data , ref int out_data ,string KeyPath);
//int sWriteEx(int in_data , ref int out_data , string KeyPath);
//int sWrite_2Ex(int in_data , ref int out_data ,string KeyPath);
//int sRead(ref int in_data, string KeyPath);
//int sWrite(int out_data, string KeyPath);
//int sWrite_2(int out_data, string KeyPath);

//***设置写密码
//int SetWritePassword(string W_HKey, string W_LKey, string new_HKey, string new_LKey, string KeyPath);

//***设置读密码
//int SetReadPassword(string W_HKey, string W_LKey, string new_HKey, string new_LKey, string KeyPath);

//'设置增强算法密钥一
//int SetCal_2(string Key , string KeyPath);

//使用增强算法一对字符串进行加密
//int EncString(string InString , ref string outstring , string KeyPath);

//使用增强算法一对二进制数据进行加密
// int Cal(byte[] InBuf, byte[] OutBuf, string KeyPath);

//'设置增强算法密钥二
//int SetCal_New(string Key , string KeyPath);

//使用增强算法二对字符串进行加密
//int EncString_New(string InString , ref string outstring , string KeyPath);

//使用增强算法二对二进制数据进行加密
// int Cal_New(byte[] InBuf, byte[] OutBuf, string KeyPath);

//***初始化加密锁函数
//int ReSet( string Path);

//***获取字符串长度
//int lstrlenA(string InString );
namespace Casun_SoftKey
{
    public struct GUID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Data1;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public byte[] Data2;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public byte[] Data3;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Data4;
    }

    public struct SP_INTERFACE_DEVICE_DATA
    {
        public int cbSize;
        public GUID InterfaceClassGuid;
        public int Flags;
        public int Reserved;
    }

    public struct SP_INTERFACE_DEVICE_DATA_64
    {
        public Int64 cbSize;
        public GUID InterfaceClassGuid;
        public int Flags;
        public int Reserved;
    }

    public struct SP_DEVINFO_DATA
    {
        public int cbSize;
        public GUID ClassGuid;
        public int DevInst;
        public int Reserved;
    }


    public struct SP_DEVICE_INTERFACE_DETAIL_DATA
    {
        public int cbSize;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 255)]
        public byte[] DevicePath;
    }


    public struct HIDD_ATTRIBUTES
    {
        public int Size;
        public ushort VendorID;
        public ushort ProductID;
        public ushort VersionNumber;
    }


    public struct HIDP_CAPS
    {
        public short Usage;
        public short UsagePage;
        public short InputReportByteLength;
        public short OutputReportByteLength;
        public short FeatureReportByteLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public short[] Reserved;
        public short NumberLinkCollectionNodes;
        public short NumberInputButtonCaps;
        public short NumberInputValueCaps;
        public short NumberInputDataIndices;
        public short NumberOutputButtonCaps;
        public short NumberOutputValueCaps;
        public short NumberOutputDataIndices;
        public short NumberFeatureButtonCaps;
        public short NumberFeatureValueCaps;
        public short NumberFeatureDataIndices;
    }
    class SoftKey
    {
        private const ushort VID = 0x3689;
        private const ushort PID = 0x8762;
        private const short DIGCF_PRESENT = 0x2;
        private const short DIGCF_DEVICEINTERFACE = 0x10;
        private const short INVALID_HANDLE_VALUE = (-1);
        private const short ERROR_NO_MORE_ITEMS = 259;

        private const uint GENERIC_READ = 0x80000000;
        private const int GENERIC_WRITE = 0x40000000;
        private const uint FILE_SHARE_READ = 0x1;
        private const uint FILE_SHARE_WRITE = 0x2;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        private const uint INFINITE = 0xFFFF;

        private const short MAX_LEN = 495;

        [DllImport("kernel32.dll")]
        public static extern int lstrlenA(string InString);
        [DllImport("kernel32.dll", EntryPoint = "RtlMoveMemory")]
        public static extern void CopyStringToByte(byte[] pDest, string pSourceg, int ByteLenr);
        [DllImport("kernel32.dll", EntryPoint = "RtlMoveMemory")]
        public static extern void CopyByteToString(StringBuilder pDest, byte[] pSource, int ByteLenr);

        [DllImport("HID.dll")]
        private static extern bool HidD_GetAttributes(int HidDeviceObject, ref HIDD_ATTRIBUTES Attributes);

        [DllImport("HID.dll")]
        private static extern int HidD_GetHidGuid(ref GUID HidGuid);

        [DllImport("HID.dll")]
        private static extern bool HidD_GetPreparsedData(int HidDeviceObject, ref int PreparsedData);

        [DllImport("HID.dll")]
        private static extern int HidP_GetCaps(int PreparsedData, ref HIDP_CAPS Capabilities);

        [DllImport("HID.dll")]
        private static extern bool HidD_FreePreparsedData(int PreparsedData);

        [DllImport("HID.dll")]
        private static extern bool HidD_SetFeature(int HidDeviceObject, byte[] ReportBuffer, int ReportBufferLength);

        [DllImport("HID.dll")]
        private static extern bool HidD_GetFeature(int HidDeviceObject, byte[] ReportBuffer, int ReportBufferLength);

        [DllImport("SetupApi.dll")]
        private static extern int SetupDiGetClassDevsA(ref GUID ClassGuid, int Enumerator, int hwndParent, int Flags);

        [DllImport("SetupApi.dll")]
        private static extern bool SetupDiDestroyDeviceInfoList(int DeviceInfoSet);

        [DllImport("SetupApi.dll")]
        private static extern bool SetupDiGetDeviceInterfaceDetailA(int DeviceInfoSet, ref  SP_INTERFACE_DEVICE_DATA DeviceInterfaceData, ref SP_DEVICE_INTERFACE_DETAIL_DATA DeviceInterfaceDetailData, int DeviceInterfaceDetailDataSize, ref int RequiredSize, int DeviceInfoData);

        [DllImport("SetupApi.dll", EntryPoint = "SetupDiGetDeviceInterfaceDetailA")]
        private static extern bool SetupDiGetDeviceInterfaceDetailA_64(int DeviceInfoSet, ref  SP_INTERFACE_DEVICE_DATA_64 DeviceInterfaceData, ref SP_DEVICE_INTERFACE_DETAIL_DATA DeviceInterfaceDetailData, int DeviceInterfaceDetailDataSize, ref int RequiredSize, int DeviceInfoData);

        [DllImport("SetupApi.dll")]
        private static extern bool SetupDiEnumDeviceInterfaces(int DeviceInfoSet, int DeviceInfoData, ref GUID InterfaceClassGuid, int MemberIndex, ref SP_INTERFACE_DEVICE_DATA DeviceInterfaceData);

        [DllImport("SetupApi.dll", EntryPoint = "SetupDiEnumDeviceInterfaces")]
        private static extern bool SetupDiEnumDeviceInterfaces_64(int DeviceInfoSet, int DeviceInfoData, ref GUID InterfaceClassGuid, int MemberIndex, ref SP_INTERFACE_DEVICE_DATA_64 DeviceInterfaceData);

        [DllImport("kernel32.dll", EntryPoint = "CreateFileA")]
        private static extern int CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, uint lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, uint hTemplateFile);

        [DllImport("kernel32.dll")]
        private static extern int CloseHandle(int hObject);

        [DllImport("kernel32.dll")]
        private static extern int GetLastError();


        [DllImport("kernel32.dll", EntryPoint = "CreateSemaphoreA")]
        private static extern int CreateSemaphore(int lpSemaphoreAttributes, int lInitialCount, int lMaximumCount, string lpName);

        [DllImport("kernel32.dll")]
        private static extern int WaitForSingleObject(int hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        private static extern int ReleaseSemaphore(int hSemaphore, int lReleaseCount, int lpPreviousCount);

        Boolean Is32;

        public SoftKey()
        {
            Is32 = (System.IntPtr.Size == 4);
        }

        //以下函数用于将字节数组转化为宽字符串
        private static string ByteConvertString(byte[] buffer)
        {
            char[] null_string = { '\0', '\0' };
            System.Text.Encoding encoding = System.Text.Encoding.Default;
            return encoding.GetString(buffer).TrimEnd(null_string);
        }

        //以下用于将16进制字符串转化为无符号长整型
        private uint HexToInt(string s)
        {
            string[] hexch = { "0", "1", "2", "3", "4", "5", "6", "7",
								       "8", "9", "A", "B", "C", "D", "E", "F"};
            s = s.ToUpper();
            int i, j;
            int r, n, k;
            string ch;

            k = 1; r = 0;
            for (i = s.Length; i > 0; i--)
            {
                ch = s.Substring(i - 1, 1);
                n = 0;
                for (j = 0; j < 16; j++)
                    if (ch == hexch[j])
                        n = j;
                r += (n * k);
                k *= 16;
            }
            return unchecked((uint)r);
        }

        private int HexStringToByteArray(string InString, ref byte[] b)
        {
            int nlen;
            int retutn_len;
            int n, i;
            string temp;
            nlen = InString.Length;
            if (nlen < 16) retutn_len = 16;
            retutn_len = nlen / 2;
            b = new byte[retutn_len];
            i = 0;
            for (n = 0; n < nlen; n = n + 2)
            {
                temp = InString.Substring(n, 2);
                b[i] = (byte)HexToInt(temp);
                i = i + 1;
            }
            return retutn_len;
        }


        public void EnCode(byte[] inb, byte[] outb, string Key)
        {

            UInt32 cnDelta, y, z, a, b, c, d, temp_2;
            UInt32[] buf = new UInt32[16];
            int n, i, nlen;
            UInt32 sum;
            //UInt32 temp, temp_1;
            string temp_string;


            cnDelta = 2654435769;
            sum = 0;

            nlen = Key.Length;
            i = 0;
            for (n = 1; n <= nlen; n = n + 2)
            {
                temp_string = Key.Substring(n - 1, 2);
                buf[i] = HexToInt(temp_string);
                i = i + 1;
            }
            a = 0; b = 0; c = 0; d = 0;
            for (n = 0; n <= 3; n++)
            {
                a = (buf[n] << (n * 8)) | a;
                b = (buf[n + 4] << (n * 8)) | b;
                c = (buf[n + 4 + 4] << (n * 8)) | c;
                d = (buf[n + 4 + 4 + 4] << (n * 8)) | d;
            }



            y = 0;
            z = 0;
            for (n = 0; n <= 3; n++)
            {
                temp_2 = inb[n];
                y = (temp_2 << (n * 8)) | y;
                temp_2 = inb[n + 4];
                z = (temp_2 << (n * 8)) | z;
            }


            n = 32;

            while (n > 0)
            {
                sum = cnDelta + sum;

                /*temp = (z << 4) & 0xFFFFFFFF;
                temp = (temp + a) & 0xFFFFFFFF;
                temp_1 = (z + sum) & 0xFFFFFFFF;
                temp = (temp ^ temp_1) & 0xFFFFFFFF;
                temp_1 = (z >> 5) & 0xFFFFFFFF;
                temp_1 = (temp_1 + b) & 0xFFFFFFFF;
                temp = (temp ^ temp_1) & 0xFFFFFFFF;
                temp = (temp + y) & 0xFFFFFFFF;
                y = temp & 0xFFFFFFFF;*/
                y += ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);

                /*temp = (y << 4) & 0xFFFFFFFF;
                temp = (temp + c) & 0xFFFFFFFF;
                temp_1 = (y + sum) & 0xFFFFFFFF;
                temp = (temp ^ temp_1) & 0xFFFFFFFF;
                temp_1 = (y >> 5) & 0xFFFFFFFF;
                temp_1 = (temp_1 + d) & 0xFFFFFFFF;
                temp = (temp ^ temp_1) & 0xFFFFFFFF;
                temp = (z + temp) & 0xFFFFFFFF;
                z = temp & 0xFFFFFFFF;*/
                z += ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d);
                n = n - 1;

            }

            for (n = 0; n <= 3; n++)
            {
                outb[n] = System.Convert.ToByte((y >> (n * 8)) & 255);
                outb[n + 4] = System.Convert.ToByte((z >> (n * 8)) & 255);
            }

        }

        public void DeCode(byte[] inb, byte[] outb, string Key)
        {

            UInt32 cnDelta, y, z, a, b, c, d, temp_2;
            UInt32[] buf = new UInt32[16];
            int n, i, nlen;
            UInt32 sum;
            //UInt32 temp, temp_1;
            string temp_string;


            cnDelta = 2654435769;
            sum = 0xC6EF3720;

            nlen = Key.Length;
            i = 0;
            for (n = 1; n <= nlen; n = n + 2)
            {
                temp_string = Key.Substring(n - 1, 2);
                buf[i] = HexToInt(temp_string);
                i = i + 1;
            }
            a = 0; b = 0; c = 0; d = 0;
            for (n = 0; n <= 3; n++)
            {
                a = (buf[n] << (n * 8)) | a;
                b = (buf[n + 4] << (n * 8)) | b;
                c = (buf[n + 4 + 4] << (n * 8)) | c;
                d = (buf[n + 4 + 4 + 4] << (n * 8)) | d;
            }



            y = 0;
            z = 0;
            for (n = 0; n <= 3; n++)
            {
                temp_2 = inb[n];
                y = (temp_2 << (n * 8)) | y;
                temp_2 = inb[n + 4];
                z = (temp_2 << (n * 8)) | z;
            }


            n = 32;

            while (n-- > 0)
            {
                z -= ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d);
                y -= ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);
                sum -= cnDelta;

            }

            for (n = 0; n <= 3; n++)
            {
                outb[n] = System.Convert.ToByte((y >> (n * 8)) & 255);
                outb[n + 4] = System.Convert.ToByte((z >> (n * 8)) & 255);
            }

        }


        public string StrEnc(string InString, string Key)//使用增强算法，加密字符串
        {

            byte[] b, outb;
            byte[] temp = new byte[8], outtemp = new byte[8];
            int n, i, nlen, outlen;
            string outstring;


            nlen = lstrlenA(InString) + 1;
            if (nlen < 8)
                outlen = 8;
            else
                outlen = nlen;
            b = new byte[outlen];
            outb = new byte[outlen];

            CopyStringToByte(b, InString, nlen);

            b.CopyTo(outb, 0);

            for (n = 0; n <= outlen - 8; n = n + 8)
            {
                for (i = 0; i < 8; i++) temp[i] = b[i + n];
                EnCode(temp, outtemp, Key);
                for (i = 0; i < 8; i++) outb[i + n] = outtemp[i];
            }

            outstring = "";
            for (n = 0; n <= outlen - 1; n++)
            {
                outstring = outstring + outb[n].ToString("X2");
            }
            return outstring;
        }
        public string StrDec(string InString, string Key) //使用增强算法，加密字符串
        {
            byte[] b, outb;
            byte[] temp = new byte[8], outtemp = new byte[8];
            int n, i, nlen, outlen;
            string temp_string;
            StringBuilder c_str;


            nlen = InString.Length;
            if (nlen < 16) outlen = 16;
            outlen = nlen / 2;
            b = new byte[outlen];
            outb = new byte[outlen];

            i = 0;
            for (n = 1; n <= nlen; n = n + 2)
            {
                temp_string = InString.Substring(n - 1, 2);
                b[i] = System.Convert.ToByte(HexToInt(temp_string));
                i = i + 1;
            }

            b.CopyTo(outb, 0);

            for (n = 0; n <= outlen - 8; n = n + 8)
            {
                for (i = 0; i < 8; i++) temp[i] = b[i + n];
                DeCode(temp, outtemp, Key);
                for (i = 0; i < 8; i++) outb[i + n] = outtemp[i];
            }

            c_str = new StringBuilder("", outlen);
            CopyByteToString(c_str, outb, outlen);
            return c_str.ToString();

        }
        private bool isfindmydevice(int pos, ref int count, ref string OutPath)
        {
            if (Is32)
                return isfindmydevice_32(pos, ref count, ref OutPath);
            else
                return isfindmydevice_64(pos, ref count, ref  OutPath);
        }

        private bool isfindmydevice_64(int pos, ref int count, ref string OutPath)
        {
            int hardwareDeviceInfo;
            SP_INTERFACE_DEVICE_DATA_64 DeviceInfoData = new SP_INTERFACE_DEVICE_DATA_64();
            int i;
            GUID HidGuid = new GUID();
            SP_DEVICE_INTERFACE_DETAIL_DATA functionClassDeviceData = new SP_DEVICE_INTERFACE_DETAIL_DATA();
            int requiredLength;
            int d_handle;
            HIDD_ATTRIBUTES Attributes = new HIDD_ATTRIBUTES();

            i = 0;
            HidD_GetHidGuid(ref HidGuid);

            hardwareDeviceInfo = SetupDiGetClassDevsA(ref HidGuid, 0, 0, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

            if (hardwareDeviceInfo == INVALID_HANDLE_VALUE) return false;

            DeviceInfoData.cbSize = Marshal.SizeOf(DeviceInfoData);

            while (SetupDiEnumDeviceInterfaces_64(hardwareDeviceInfo, 0, ref HidGuid, i, ref DeviceInfoData))
            {
                if (GetLastError() == ERROR_NO_MORE_ITEMS) break;
                functionClassDeviceData.cbSize = 8;
                requiredLength = 0;
                if (!SetupDiGetDeviceInterfaceDetailA_64(hardwareDeviceInfo, ref DeviceInfoData, ref functionClassDeviceData, 300, ref requiredLength, 0))
                {
                    SetupDiDestroyDeviceInfoList(hardwareDeviceInfo);
                    return false;
                }
                OutPath = ByteConvertString(functionClassDeviceData.DevicePath);
                d_handle = CreateFile(OutPath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
                if (INVALID_HANDLE_VALUE != d_handle)
                {
                    if (HidD_GetAttributes(d_handle, ref Attributes))
                    {
                        if ((Attributes.ProductID == PID) && (Attributes.VendorID == VID))
                        {
                            if (pos == count)
                            {
                                SetupDiDestroyDeviceInfoList(hardwareDeviceInfo);
                                CloseHandle(d_handle);
                                return true;
                            }
                            count = count + 1;
                        }
                    }
                    CloseHandle(d_handle);
                }
                i = i + 1;

            }
            SetupDiDestroyDeviceInfoList(hardwareDeviceInfo);
            return false;
        }

        private bool isfindmydevice_32(int pos, ref int count, ref string OutPath)
        {
            int hardwareDeviceInfo;
            SP_INTERFACE_DEVICE_DATA DeviceInfoData = new SP_INTERFACE_DEVICE_DATA();
            int i;
            GUID HidGuid = new GUID();
            SP_DEVICE_INTERFACE_DETAIL_DATA functionClassDeviceData = new SP_DEVICE_INTERFACE_DETAIL_DATA();
            int requiredLength;
            int d_handle;
            HIDD_ATTRIBUTES Attributes = new HIDD_ATTRIBUTES();

            i = 0;
            HidD_GetHidGuid(ref HidGuid);

            hardwareDeviceInfo = SetupDiGetClassDevsA(ref HidGuid, 0, 0, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

            if (hardwareDeviceInfo == INVALID_HANDLE_VALUE) return false;

            DeviceInfoData.cbSize = Marshal.SizeOf(DeviceInfoData);

            while (SetupDiEnumDeviceInterfaces(hardwareDeviceInfo, 0, ref HidGuid, i, ref DeviceInfoData))
            {
                if (GetLastError() == ERROR_NO_MORE_ITEMS) break;
                functionClassDeviceData.cbSize = Marshal.SizeOf(functionClassDeviceData) - 255;// 5;
                requiredLength = 0;
                if (!SetupDiGetDeviceInterfaceDetailA(hardwareDeviceInfo, ref DeviceInfoData, ref functionClassDeviceData, 300, ref requiredLength, 0))
                {
                    SetupDiDestroyDeviceInfoList(hardwareDeviceInfo);
                    return false;
                }
                OutPath = ByteConvertString(functionClassDeviceData.DevicePath);
                d_handle = CreateFile(OutPath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
                if (INVALID_HANDLE_VALUE != d_handle)
                {
                    if (HidD_GetAttributes(d_handle, ref Attributes))
                    {
                        if ((Attributes.ProductID == PID) && (Attributes.VendorID == VID))
                        {
                            if (pos == count)
                            {
                                SetupDiDestroyDeviceInfoList(hardwareDeviceInfo);
                                CloseHandle(d_handle);
                                return true;
                            }
                            count = count + 1;
                        }
                    }
                    CloseHandle(d_handle);
                }
                i = i + 1;

            }
            SetupDiDestroyDeviceInfoList(hardwareDeviceInfo);
            return false;
        }

        private bool GetFeature(int hDevice, byte[] array_out, int out_len)
        {

            bool FeatureStatus;
            bool Status;
            int i;
            byte[] FeatureReportBuffer = new byte[512];
            int Ppd = 0;
            HIDP_CAPS Caps = new HIDP_CAPS();

            if (!HidD_GetPreparsedData(hDevice, ref Ppd)) return false;

            if (HidP_GetCaps(Ppd, ref Caps) <= 0)
            {
                HidD_FreePreparsedData(Ppd);
                return false;
            }

            Status = true;

            FeatureReportBuffer[0] = 1;

            FeatureStatus = HidD_GetFeature(hDevice, FeatureReportBuffer, Caps.FeatureReportByteLength);
            if (FeatureStatus)
            {
                for (i = 0; i < out_len; i++)
                {
                    array_out[i] = FeatureReportBuffer[i];
                }
            }


            Status = Status && FeatureStatus;
            HidD_FreePreparsedData(Ppd);

            return Status;

        }

        private bool SetFeature(int hDevice, byte[] array_in, int in_len)
        {
            bool FeatureStatus;
            bool Status;
            int i;
            byte[] FeatureReportBuffer = new byte[512];
            int Ppd = 0;
            HIDP_CAPS Caps = new HIDP_CAPS();

            if (!HidD_GetPreparsedData(hDevice, ref Ppd)) return false;

            if (HidP_GetCaps(Ppd, ref Caps) <= 0)
            {
                HidD_FreePreparsedData(Ppd);
                return false;
            }

            Status = true;

            FeatureReportBuffer[0] = 2;

            for (i = 0; i < in_len; i++)
            {
                FeatureReportBuffer[i + 1] = array_in[i + 1];

            }
            FeatureStatus = HidD_SetFeature(hDevice, FeatureReportBuffer, Caps.FeatureReportByteLength);


            Status = Status && FeatureStatus;
            HidD_FreePreparsedData(Ppd);

            return Status;

        }

        private int NT_FindPort(int start, ref string OutPath)
        {
            int count = 0;
            if (!isfindmydevice(start, ref count, ref OutPath))
            {
                return -92;
            }
            return 0;
        }

        private int NT_FindPort_2(int start, int in_data, int verf_data, ref string OutPath)
        {
            int count = 0;
            int pos;
            int out_data = 0;
            int ret;
            for (pos = start; pos < 256; pos++)
            {
                if (!isfindmydevice(pos, ref count, ref OutPath)) return -92;
                ret = WriteDword(in_data, OutPath);
                if (ret != 0) return ret;
                ret = ReadDword(ref out_data, OutPath);
                if (ret != 0) return ret;
                if (out_data == verf_data) { return 0; }
            }
            return (-92);
        }
        private int OpenMydivece(ref int hUsbDevice, string Path)
        {
            string OutPath;
            bool biao;
            int count = 0;
            if (Path.Length < 1)
            {
                OutPath = "";
                biao = isfindmydevice(0, ref count, ref OutPath);
                if (!biao) return -92;
                hUsbDevice = CreateFile(OutPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
                if (hUsbDevice == INVALID_HANDLE_VALUE) return -92;
            }
            else
            {
                hUsbDevice = CreateFile(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
                if (hUsbDevice == INVALID_HANDLE_VALUE) return -92;
            }
            return 0;
        }

        private int NT_Read(ref byte ele1, ref byte ele2, ref byte ele3, ref byte ele4, string Path)
        {
            byte[] array_out = new byte[25];
            int hUsbDevice = 0;
            if (OpenMydivece(ref hUsbDevice, Path) != 0) return -92;
            if (!GetFeature(hUsbDevice, array_out, 5)) { CloseHandle(hUsbDevice); return -93; }
            CloseHandle(hUsbDevice);
            ele1 = array_out[0];
            ele2 = array_out[1];
            ele3 = array_out[2];
            ele4 = array_out[3];
            return 0;
        }

        private int NT_Write(byte ele1, byte ele2, byte ele3, byte ele4, string Path)
        {
            byte[] array_in = new byte[25];
            int hUsbDevice = 0;
            if (OpenMydivece(ref hUsbDevice, Path) != 0) { return -92; }
            array_in[1] = 3; array_in[2] = ele1; array_in[3] = ele2; array_in[4] = ele3; array_in[5] = ele4;
            if (!SetFeature(hUsbDevice, array_in, 5)) { CloseHandle(hUsbDevice); return -93; }
            CloseHandle(hUsbDevice);
            return 0;
        }

        private int NT_Write_2(byte ele1, byte ele2, byte ele3, byte ele4, string Path)
        {
            byte[] array_in = new byte[25];
            int hUsbDevice = 0;
            if (OpenMydivece(ref hUsbDevice, Path) != 0) return -92;
            array_in[1] = 4; array_in[2] = ele1; array_in[3] = ele2; array_in[4] = ele3; array_in[5] = ele4;
            if (!SetFeature(hUsbDevice, array_in, 5)) { CloseHandle(hUsbDevice); return -93; }
            CloseHandle(hUsbDevice);
            return 0;
        }
        private int GetIDVersion(ref short Version, string Path)
        {
            byte[] array_in = new byte[25];
            byte[] array_out = new byte[25];
            int hUsbDevice = 0;
            if (OpenMydivece(ref hUsbDevice, Path) != 0) return -92;
            array_in[1] = 1;
            if (!SetFeature(hUsbDevice, array_in, 1)) { CloseHandle(hUsbDevice); return -93; }
            if (!GetFeature(hUsbDevice, array_out, 1)) { CloseHandle(hUsbDevice); return -93; }
            CloseHandle(hUsbDevice);
            Version = array_out[0];
            return 0;
        }

        private int NT_GetID(ref int ID_1, ref int ID_2, string Path)
        {
            int[] t = new int[8];
            byte[] array_in = new byte[25];
            byte[] array_out = new byte[25];
            int hUsbDevice = 0;
            if (OpenMydivece(ref hUsbDevice, Path) != 0) return -92;
            array_in[1] = 2;
            if (!SetFeature(hUsbDevice, array_in, 1)) { CloseHandle(hUsbDevice); return -93; }
            if (!GetFeature(hUsbDevice, array_out, 8)) { CloseHandle(hUsbDevice); return -93; }
            CloseHandle(hUsbDevice);
            t[0] = array_out[0]; t[1] = array_out[1]; t[2] = array_out[2]; t[3] = array_out[3];
            t[4] = array_out[4]; t[5] = array_out[5]; t[6] = array_out[6]; t[7] = array_out[7];
            ID_1 = t[3] | (t[2] << 8) | (t[1] << 16) | (t[0] << 24);
            ID_2 = t[7] | (t[6] << 8) | (t[5] << 16) | (t[4] << 24);
            return 0;
        }


        private int Y_Read(byte[] OutData, int address, int nlen, byte[] password, string Path, int pos)
        {
            int addr_l;
            int addr_h;
            int n;
            byte[] array_in = new byte[25];
            byte[] array_out = new byte[25];
            if ((address > MAX_LEN) || (address < 0)) return -81;
            if ((nlen > 16)) return -87;
            if ((nlen + address) > MAX_LEN) return -88;
            addr_h = (address >> 8) * 2;
            addr_l = address & 255;
            int hUsbDevice = 0;
            if (OpenMydivece(ref hUsbDevice, Path) != 0) return -92;

            array_in[1] = 0x12;
            array_in[2] = (byte)addr_h;
            array_in[3] = (byte)addr_l;
            array_in[4] = (byte)nlen;
            for (n = 0; n <= 7; n++)
            {
                array_in[5 + n] = password[n];
            }
            if (!SetFeature(hUsbDevice, array_in, 13)) { CloseHandle(hUsbDevice); return -93; }
            if (!GetFeature(hUsbDevice, array_out, nlen + 1)) { CloseHandle(hUsbDevice); return -94; }
            CloseHandle(hUsbDevice);
            if (array_out[0] != 0)
            {
                return -83;
            }
            for (n = 0; n < nlen; n++)
            {
                OutData[n + pos] = array_out[n + 1];
            }
            return 0;
        }

        private int Y_Write(byte[] indata, int address, int nlen, byte[] password, string Path, int pos)
        {
            int addr_l;
            int addr_h;
            int n;
            byte[] array_in = new byte[25];
            byte[] array_out = new byte[25];
            if ((nlen > 8)) return -87;
            if ((address + nlen - 1) > (MAX_LEN + 17) || (address < 0)) return -81;
            addr_h = (address >> 8) * 2;
            addr_l = address & 255;
            int hUsbDevice = 0;
            if (OpenMydivece(ref hUsbDevice, Path) != 0) return -92;
            array_in[1] = 0x13;
            array_in[2] = (byte)addr_h;
            array_in[3] = (byte)addr_l;
            array_in[4] = (byte)nlen;
            for (n = 0; n <= 7; n++)
            {
                array_in[5 + n] = password[n];
            }
            for (n = 0; n < nlen; n++)
            {
                array_in[13 + n] = indata[n + pos];
            }
            if (!SetFeature(hUsbDevice, array_in, 13 + nlen)) { CloseHandle(hUsbDevice); return -93; }
            if (!GetFeature(hUsbDevice, array_out, 2)) { CloseHandle(hUsbDevice); return -94; }
            CloseHandle(hUsbDevice);
            if (array_out[0] != 0)
            {
                return -82;
            }
            return 0;
        }

        private int NT_Cal(byte[] InBuf, byte[] outbuf, string Path, int pos)
        {
            int n;
            byte[] array_in = new byte[25];
            byte[] array_out = new byte[25];
            int hUsbDevice = 0;
            if (OpenMydivece(ref hUsbDevice, Path) != 0) return -92;
            array_in[1] = 8;
            for (n = 2; n <= 9; n++)
            {
                array_in[n] = InBuf[n - 2 + pos];
            }
            if (!SetFeature(hUsbDevice, array_in, 9)) { CloseHandle(hUsbDevice); return -93; }
            if (!GetFeature(hUsbDevice, array_out, 9)) { CloseHandle(hUsbDevice); return -93; }
            CloseHandle(hUsbDevice);
            for (n = 0; n < 8; n++)
            {
                outbuf[n + pos] = array_out[n];
            }
            if (array_out[8] != 0x55)
            {
                return -20;
            }
            return 0;
        }

        private int NT_SetCal_2(byte[] indata, byte IsHi, string Path, short pos)
        {

            int n;
            byte[] array_in = new byte[25];
            byte[] array_out = new byte[25];
            int hUsbDevice = 0;
            if (OpenMydivece(ref hUsbDevice, Path) != 0) return -92;
            array_in[1] = 9;
            array_in[2] = IsHi;
            for (n = 0; n < 8; n++)
            {
                array_in[3 + n] = indata[n + pos];
            }
            if (!SetFeature(hUsbDevice, array_in, 11)) { CloseHandle(hUsbDevice); return -93; }
            if (!GetFeature(hUsbDevice, array_out, 2)) { CloseHandle(hUsbDevice); return -94; }
            CloseHandle(hUsbDevice);
            if (array_out[0] != 0)
            {
                return -82;
            }

            return 0;
        }

        private int ReadDword(ref int out_data, string Path)
        {
            byte b1 = 0;
            byte b2 = 0;
            byte b3 = 0;
            byte b4 = 0;
            int t1;
            int t2;
            int t3;
            int t4;
            int ret;
            ret = NT_Read(ref b1, ref b2, ref  b3, ref b4, Path);
            t1 = b1; t2 = b2; t3 = b3; t4 = b4;
            out_data = t1 | (t2 << 8) | (t3 << 16) | (t4 << 24);
            return ret;
        }

        private int WriteDword(int in_data, string Path)
        {
            byte b1;
            byte b2;
            byte b3;
            byte b4;
            b1 = (byte)(in_data & 255);
            b2 = (byte)((in_data >> 8) & 255);
            b3 = (byte)((in_data >> 16) & 255);
            b4 = (byte)((in_data >> 24) & 255);
            return NT_Write(b1, b2, b3, b4, Path);
        }

        private int WriteDword_2(int in_data, string Path)
        {
            byte b1;
            byte b2;
            byte b3;
            byte b4;
            b1 = (byte)(in_data & 255);
            b2 = (byte)((in_data >> 8) & 255);
            b3 = (byte)((in_data >> 16) & 255);
            b4 = (byte)((in_data >> 24) & 255);
            return NT_Write_2(b1, b2, b3, b4, Path);
        }
        public int NT_GetIDVersion(ref short Version, string Path)
        {
            int ret;
            int hsignal;
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = GetIDVersion(ref Version, Path);
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }

        public int GetID(ref int ID_1, ref int ID_2, string Path)
        {
            int ret;
            int hsignal;
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = NT_GetID(ref ID_1, ref ID_2, Path);
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }

        public int sRead(ref int in_data, string Path)
        {
            int ret;
            int hsignal;
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = ReadDword(ref in_data, Path);
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }

        public int sWrite(int out_data, string Path)
        {
            int ret;
            int hsignal;
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = WriteDword(out_data, Path);
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }

        public int YWriteEx(byte[] indata, int address, int nlen, string HKey, string LKey, string Path)
        {
            int ret = 0;
            int hsignal;
            byte[] password = new byte[8];
            int n;
            int leave;
            int temp_leave;
            if ((address + nlen - 1 > MAX_LEN) || (address < 0)) return -81;
            myconvert(HKey, LKey, password);
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            temp_leave = address % 16;
            leave = 16 - temp_leave;
            if (leave > nlen) leave = nlen;
            if (leave > 0)
            {
                for (n = 0; n < leave / 8; n++)
                {
                    ret = Y_Write(indata, address + n * 8, 8, password, Path, 8 * n);
                    if (ret != 0) { ReleaseSemaphore(hsignal, 1, 0); CloseHandle(hsignal); return ret; }
                }
                if (leave - 8 * n > 0)
                {
                    ret = Y_Write(indata, address + n * 8, leave - n * 8, password, Path, 8 * n);
                    if (ret != 0) { ReleaseSemaphore(hsignal, 1, 0); CloseHandle(hsignal); return ret; }
                }
            }
            nlen = nlen - leave; address = address + leave;
            if (nlen > 0)
            {

                for (n = 0; n < nlen / 8; n++)
                {
                    ret = Y_Write(indata, address + n * 8, 8, password, Path, leave + 8 * n);
                    if (ret != 0) { ReleaseSemaphore(hsignal, 1, 0); CloseHandle(hsignal); return ret; }
                }
                if (nlen - 8 * n > 0)
                {
                    ret = Y_Write(indata, address + n * 8, nlen - n * 8, password, Path, leave + 8 * n);
                    if (ret != 0) { ReleaseSemaphore(hsignal, 1, 0); CloseHandle(hsignal); return ret; }
                }
            }
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }

        public int YReadEx(byte[] OutData, short address, short nlen, string HKey, string LKey, string Path)
        {
            int ret = 0;
            int hsignal;
            byte[] password = new byte[8];
            int n;

            if ((address + nlen - 1 > MAX_LEN) || (address < 0)) return (-81);
            myconvert(HKey, LKey, password);
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            for (n = 0; n < nlen / 16; n++)
            {
                ret = Y_Read(OutData, address + n * 16, 16, password, Path, n * 16);
                if (ret != 0) { ReleaseSemaphore(hsignal, 1, 0); CloseHandle(hsignal); return ret; }
            }
            if (nlen - 16 * n > 0)
            {
                ret = Y_Read(OutData, address + n * 16, nlen - 16 * n, password, Path, 16 * n);
                if (ret != 0) { ReleaseSemaphore(hsignal, 1, 0); CloseHandle(hsignal); return ret; }
            }
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }

        public int FindPort_2(int start, int in_data, int verf_data, ref string OutPath)
        {
            int ret;
            int hsignal;
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = NT_FindPort_2(start, in_data, verf_data, ref OutPath);
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }

        public int FindPort(int start, ref string OutPath)
        {
            int ret;
            int hsignal;
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = NT_FindPort(start, ref  OutPath);
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }


        public int sWrite_2(int out_data, string Path)
        {
            int ret;
            int hsignal;
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = WriteDword_2(out_data, Path);
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }
        private string AddZero(string InKey)
        {
            int nlen;
            int n;
            nlen = InKey.Length;
            for (n = nlen; n <= 7; n++)
            {
                InKey = "0" + InKey;
            }
            return InKey;
        }

        private void myconvert(string HKey, string LKey, byte[] out_data)
        {
            HKey = AddZero(HKey);
            LKey = AddZero(LKey);
            int n;
            for (n = 0; n <= 3; n++)
            {
                out_data[n] = (byte)HexToInt(HKey.Substring(n * 2, 2));
            }
            for (n = 0; n <= 3; n++)
            {
                out_data[n + 4] = (byte)HexToInt(LKey.Substring(n * 2, 2));
            }
        }
        public int YRead(ref byte indata, int address, string HKey, string LKey, string Path)
        {
            int ret;
            int hsignal;
            byte[] ary1 = new byte[8];

            if ((address > 495) || (address < 0)) return -81;
            myconvert(HKey, LKey, ary1);
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = sub_YRead(ref indata, address, ary1, Path);
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }
        private int sub_YRead(ref byte OutData, int address, byte[] password, string Path)
        {
            int n;
            byte[] array_in = new byte[25];
            byte[] array_out = new byte[25];
            int hUsbDevice = 0;
            byte opcode;
            if ((address > 495) || (address < 0)) return -81;
            opcode = 128;
            if (address > 255)
            {
                opcode = 160;
                address = address - 256;
            }

            if (OpenMydivece(ref hUsbDevice, Path) != 0) return -92;
            array_in[1] = 16;
            array_in[2] = opcode;
            array_in[3] = (byte)address;
            array_in[4] = (byte)address;
            for (n = 0; n < 8; n++)
            {
                array_in[5 + n] = password[n];
            }
            if (!SetFeature(hUsbDevice, array_in, 13))
            {
                CloseHandle(hUsbDevice); return -93;
            }
            if (!GetFeature(hUsbDevice, array_out, 2))
            {
                CloseHandle(hUsbDevice); return -94;
            }
            CloseHandle(hUsbDevice);
            if (array_out[0] != 83)
            {
                return -83;
            }
            OutData = array_out[1];
            return 0;
        }

        public int YWrite(byte indata, int address, string HKey, string LKey, string Path)
        {
            int ret;
            int hsignal;
            byte[] ary1 = new byte[8];

            if ((address > 495) || (address < 0)) return -81;
            myconvert(HKey, LKey, ary1);
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = sub_YWrite(indata, address, ary1, Path);
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }
        private int sub_YWrite(byte indata, int address, byte[] password, string Path)
        {
            int n;
            byte[] array_in = new byte[25];
            byte[] array_out = new byte[25];
            int hUsbDevice = 0;
            byte opcode;
            if ((address > 511) || (address < 0)) return -81;
            opcode = 64;
            if (address > 255)
            {
                opcode = 96;
                address = address - 256;
            }

            if (OpenMydivece(ref hUsbDevice, Path) != 0) return -92;
            array_in[1] = 17;
            array_in[2] = opcode;
            array_in[3] = (byte)address;
            array_in[4] = indata;
            for (n = 0; n < 8; n++)
            {
                array_in[5 + n] = password[n];
            }
            if (!SetFeature(hUsbDevice, array_in, 13))
            {
                CloseHandle(hUsbDevice); return -93;
            }
            if (GetFeature(hUsbDevice, array_out, 2))
            {
                CloseHandle(hUsbDevice); return -94;
            }
            CloseHandle(hUsbDevice);
            if (array_out[1] != 1)
            {
                return -82;
            }
            return 0;
        }
        public int SetReadPassword(string W_HKey, string W_LKey, string new_HKey, string new_LKey, string Path)
        {
            int ret;
            int hsignal;
            byte[] ary1 = new byte[8];
            byte[] ary2 = new byte[8];
            short address;
            myconvert(W_HKey, W_LKey, ary1);
            myconvert(new_HKey, new_LKey, ary2);
            address = 496;
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = Y_Write(ary2, address, 8, ary1, Path, 0);
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }


        public int SetWritePassword(string W_HKey, string W_LKey, string new_HKey, string new_LKey, string Path)
        {
            int ret;
            int hsignal;
            byte[] ary1 = new byte[8];
            byte[] ary2 = new byte[8];
            short address;
            myconvert(W_HKey, W_LKey, ary1);
            myconvert(new_HKey, new_LKey, ary2);
            address = 504;
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = Y_Write(ary2, address, 8, ary1, Path, 0);
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }

        public int YWriteString(string InString, int address, string HKey, string LKey, string Path)
        {
            int ret = 0;
            byte[] ary1 = new byte[8];
            int hsignal;
            int n;
            int outlen;
            int total_len;
            int temp_leave;
            int leave;
            byte[] b;
            if ((address < 0)) return -81;
            myconvert(HKey, LKey, ary1);

            outlen = lstrlenA(InString); //注意，这里不写入结束字符串，与原来的兼容，也可以写入结束字符串，与原来的不兼容，写入长度会增加1
            b = new byte[outlen];
            CopyStringToByte(b, InString, outlen);

            total_len = address + outlen;
            if (total_len > MAX_LEN) return -47;
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            temp_leave = address % 16;
            leave = 16 - temp_leave;
            if (leave > outlen) leave = outlen;

            if (leave > 0)
            {
                for (n = 0; n < (leave / 8); n++)
                {
                    ret = Y_Write(b, address + n * 8, 8, ary1, Path, n * 8);
                    if (ret != 0) { ReleaseSemaphore(hsignal, 1, 0); CloseHandle(hsignal); return ret; }
                }
                if (leave - 8 * n > 0)
                {
                    ret = Y_Write(b, address + n * 8, leave - n * 8, ary1, Path, 8 * n);
                    if (ret != 0) { ReleaseSemaphore(hsignal, 1, 0); CloseHandle(hsignal); return ret; }
                }
            }
            outlen = outlen - leave;
            address = address + leave;
            if (outlen > 0)
            {
                for (n = 0; n < (outlen / 8); n++)
                {
                    ret = Y_Write(b, address + n * 8, 8, ary1, Path, leave + n * 8);
                    if (ret != 0) { ReleaseSemaphore(hsignal, 1, 0); CloseHandle(hsignal); return ret; }
                }
                if (outlen - 8 * n > 0)
                {
                    ret = Y_Write(b, address + n * 8, outlen - n * 8, ary1, Path, leave + 8 * n);
                    if (ret != 0) { ReleaseSemaphore(hsignal, 1, 0); CloseHandle(hsignal); return ret; }
                }
            }
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }

        public int YReadString(ref string OutString, int address, int nlen, string HKey, string LKey, string Path)
        {
            int ret = 0;
            byte[] ary1 = new byte[8];
            int hsignal;
            int n;
            int total_len;
            byte[] outb;
            StringBuilder temp_OutString;
            outb = new byte[nlen];
            myconvert(HKey, LKey, ary1);
            if (address < 0) return -81;
            total_len = address + nlen;
            if (total_len > MAX_LEN) return -47;
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            for (n = 0; n < (nlen / 16); n++)
            {
                ret = Y_Read(outb, address + n * 16, 16, ary1, Path, n * 16);
                if (ret != 0) { ReleaseSemaphore(hsignal, 1, 0); CloseHandle(hsignal); return ret; }
            }
            if (nlen - 16 * n > 0)
            {
                ret = Y_Read(outb, address + n * 16, nlen - 16 * n, ary1, Path, 16 * n);
                if (ret != 0) { ReleaseSemaphore(hsignal, 1, 0); CloseHandle(hsignal); return ret; }
            }
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            temp_OutString = new StringBuilder("", nlen);
            //初始化数据为0，注意，这步一定是需要的
            for (n = 0; n < nlen; n++)
            {
                temp_OutString.Append(0);
            }
            CopyByteToString(temp_OutString, outb, nlen);
            OutString = temp_OutString.ToString();
            return ret;
        }

        public int SetCal_2(string Key, string Path)
        {
            int ret;
            int hsignal;
            byte[] KeyBuf = new byte[16];
            byte[] inb = new byte[8];
            HexStringToByteArray(Key, ref KeyBuf);
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = NT_SetCal_2(KeyBuf, 0, Path, 8);
            if (ret != 0) goto error1;
            ret = NT_SetCal_2(KeyBuf, 1, Path, 0);
        error1:
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }

        public int Cal(byte[] InBuf, byte[] outbuf, string Path)
        {
            int ret;
            int hsignal;
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = NT_Cal(InBuf, outbuf, Path, 0);
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }

        public int EncString(string InString, ref string OutString, string Path)
        {
            int hsignal;
            byte[] b;
            byte[] outb;
            int n;
            int nlen, temp_len;
            int ret = 0;

            nlen = lstrlenA(InString) + 1;
            temp_len = nlen;
            if (nlen < 8)
            {
                nlen = 8;
            }


            b = new byte[nlen];
            outb = new byte[nlen];

            CopyStringToByte(b, InString, temp_len);

            b.CopyTo(outb, 0);

            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            for (n = 0; n <= (nlen - 8); n = n + 8)
            {
                ret = NT_Cal(b, outb, Path, n);
                if (ret != 0) break;
            }
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            OutString = "";
            for (n = 0; n < nlen; n++)
            {
                OutString = OutString + outb[n].ToString("X2");
            }
            return ret;

        }
        public int sWriteEx(int in_data, ref int out_data, string Path)
        {
            int ret;
            int hsignal;
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = WriteDword(in_data, Path);
            if (ret != 0) goto error1;
            ret = ReadDword(ref out_data, Path);
        error1:
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }

        public int sWrite_2Ex(int in_data, ref int out_data, string Path)
        {
            int ret;
            int hsignal;
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = WriteDword_2(in_data, Path);
            if (ret != 0) goto error1;
            ret = ReadDword(ref out_data, Path);
        error1:
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }
        public int ReSet(string Path)
        {
            int ret;
            int hsignal;
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = NT_ReSet(Path);
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }
        private int NT_ReSet(string Path)
        {
            byte[] array_in = new byte[25];
            byte[] array_out = new byte[25];
            int hUsbDevice = 0;
            if (OpenMydivece(ref hUsbDevice, Path) != 0) return -92;
            array_in[1] = 32;
            if (!SetFeature(hUsbDevice, array_in, 2))
            {
                CloseHandle(hUsbDevice); return -93;
            }
            if (!GetFeature(hUsbDevice, array_out, 2))
            {
                CloseHandle(hUsbDevice); return -93;
            }
            CloseHandle(hUsbDevice);
            if (array_out[0] != 0)
            {
                return -82;
            }
            return 0;
        }

        public int sWriteEx_New(int in_data, ref int out_data, string Path)
        {
            int ret;
            int hsignal;
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = WriteDword_New(in_data, Path);
            if (ret != 0) goto error1;
            ret = ReadDword(ref out_data, Path);
        error1:
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }

        public int sWrite_2Ex_New(int in_data, ref int out_data, string Path)
        {
            int ret;
            int hsignal;
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = WriteDword_2_New(in_data, Path);
            if (ret != 0) goto error1;
            ret = ReadDword(ref out_data, Path);
        error1:
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }
        public int SetCal_New(string Key, string Path)
        {
            int ret;
            int hsignal;
            byte[] KeyBuf = new byte[16];
            byte[] inb = new byte[8];
            HexStringToByteArray(Key, ref KeyBuf);
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = NT_SetCal_New(KeyBuf, 0, Path, 8);
            if (ret != 0) goto error1;
            ret = NT_SetCal_New(KeyBuf, 1, Path, 0);
        error1:
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }

        public int Cal_New(byte[] InBuf, byte[] outbuf, string Path)
        {
            int ret;
            int hsignal;
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = NT_Cal_New(InBuf, outbuf, Path, 0);
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }

        public int EncString_New(string InString, ref string OutString, string Path)
        {
            int hsignal;
            byte[] b;
            byte[] outb;
            int n;
            int nlen, temp_len;
            int ret = 0;

            nlen = lstrlenA(InString) + 1;
            temp_len = nlen;
            if (nlen < 8)
            {
                nlen = 8;
            }


            b = new byte[nlen];
            outb = new byte[nlen];

            CopyStringToByte(b, InString, temp_len);

            b.CopyTo(outb, 0);

            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            for (n = 0; n <= (nlen - 8); n = n + 8)
            {
                ret = NT_Cal_New(b, outb, Path, n);
                if (ret != 0) break;
            }
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            OutString = "";
            for (n = 0; n < nlen; n++)
            {
                OutString = OutString + outb[n].ToString("X2");
            }
            return ret;

        }
        public int FindPort_3(int start, int in_data, int verf_data, ref string OutPath)
        {
            int ret;
            int hsignal;
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = NT_FindPort_3(start, in_data, verf_data, ref OutPath);
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }
        public int NT_GetVersionEx(ref short Version, string Path)
        {
            int ret;
            int hsignal;
            hsignal = CreateSemaphore(0, 1, 1, "ex_sim");
            WaitForSingleObject(hsignal, INFINITE);
            ret = F_GetVersionEx(ref Version, Path);
            ReleaseSemaphore(hsignal, 1, 0);
            CloseHandle(hsignal);
            return ret;
        }
        private int WriteDword_New(int in_data, string Path)
        {
            byte b1;
            byte b2;
            byte b3;
            byte b4;
            b1 = (byte)(in_data & 255);
            b2 = (byte)((in_data >> 8) & 255);
            b3 = (byte)((in_data >> 16) & 255);
            b4 = (byte)((in_data >> 24) & 255);
            return NT_Write_New(b1, b2, b3, b4, Path);
        }

        private int WriteDword_2_New(int in_data, string Path)
        {
            byte b1;
            byte b2;
            byte b3;
            byte b4;
            b1 = (byte)(in_data & 255);
            b2 = (byte)((in_data >> 8) & 255);
            b3 = (byte)((in_data >> 16) & 255);
            b4 = (byte)((in_data >> 24) & 255);
            return NT_Write_2_New(b1, b2, b3, b4, Path);
        }
        private int NT_Cal_New(byte[] InBuf, byte[] outbuf, string Path, int pos)
        {
            int n;
            byte[] array_in = new byte[25];
            byte[] array_out = new byte[25];
            int hUsbDevice = 0;
            if (OpenMydivece(ref hUsbDevice, Path) != 0) return -92;
            array_in[1] = 12;
            for (n = 2; n <= 9; n++)
            {
                array_in[n] = InBuf[n - 2 + pos];
            }
            if (!SetFeature(hUsbDevice, array_in, 9)) { CloseHandle(hUsbDevice); return -93; }
            if (!GetFeature(hUsbDevice, array_out, 9)) { CloseHandle(hUsbDevice); return -93; }
            CloseHandle(hUsbDevice);
            for (n = 0; n < 8; n++)
            {
                outbuf[n + pos] = array_out[n];
            }
            if (array_out[8] != 0x55)
            {
                return -20;
            }
            return 0;
        }

        private int NT_SetCal_New(byte[] indata, byte IsHi, string Path, short pos)
        {

            int n;
            byte[] array_in = new byte[25];
            byte[] array_out = new byte[25];
            int hUsbDevice = 0;
            if (OpenMydivece(ref hUsbDevice, Path) != 0) return -92;
            array_in[1] = 13;
            array_in[2] = IsHi;
            for (n = 0; n < 8; n++)
            {
                array_in[3 + n] = indata[n + pos];
            }
            if (!SetFeature(hUsbDevice, array_in, 11)) { CloseHandle(hUsbDevice); return -93; }
            if (!GetFeature(hUsbDevice, array_out, 2)) { CloseHandle(hUsbDevice); return -94; }
            CloseHandle(hUsbDevice);
            if (array_out[0] != 0)
            {
                return -82;
            }

            return 0;
        }
        private int F_GetVersionEx(ref short Version, string Path)
        {
            byte[] array_in = new byte[25];
            byte[] array_out = new byte[25];
            int hUsbDevice = 0;
            if (OpenMydivece(ref hUsbDevice, Path) != 0) return -92;
            array_in[1] = 5;
            if (!SetFeature(hUsbDevice, array_in, 1)) { CloseHandle(hUsbDevice); return -93; }
            if (!GetFeature(hUsbDevice, array_out, 1)) { CloseHandle(hUsbDevice); return -93; }
            CloseHandle(hUsbDevice);
            Version = array_out[0];
            return 0;
        }
        private int NT_Write_New(byte ele1, byte ele2, byte ele3, byte ele4, string Path)
        {
            byte[] array_in = new byte[25];
            int hUsbDevice = 0;
            if (OpenMydivece(ref hUsbDevice, Path) != 0) { return -92; }
            array_in[1] = 0x0a; array_in[2] = ele1; array_in[3] = ele2; array_in[4] = ele3; array_in[5] = ele4;
            if (!SetFeature(hUsbDevice, array_in, 5)) { CloseHandle(hUsbDevice); return -93; }
            CloseHandle(hUsbDevice);
            return 0;
        }

        private int NT_Write_2_New(byte ele1, byte ele2, byte ele3, byte ele4, string Path)
        {
            byte[] array_in = new byte[25];
            int hUsbDevice = 0;
            if (OpenMydivece(ref hUsbDevice, Path) != 0) return -92;
            array_in[1] = 0x0b; array_in[2] = ele1; array_in[3] = ele2; array_in[4] = ele3; array_in[5] = ele4;
            if (!SetFeature(hUsbDevice, array_in, 5)) { CloseHandle(hUsbDevice); return -93; }
            CloseHandle(hUsbDevice);
            return 0;
        }
        private int NT_FindPort_3(int start, int in_data, int verf_data, ref string OutPath)
        {
            int count = 0;
            int pos;
            int out_data = 0;
            int ret;
            for (pos = start; pos < 256; pos++)
            {
                if (!isfindmydevice(pos, ref count, ref OutPath)) return -92;
                ret = WriteDword_New(in_data, OutPath);
                if (ret != 0) return ret;
                ret = ReadDword(ref out_data, OutPath);
                if (ret != 0) return ret;
                if (out_data == verf_data) { return 0; }
            }
            return (-92);
        }

        public int CheckKeyByFindort_2()
        {
            //使用普通算法一查找指定的加密锁
            string DevicePath = ""; //用于储存加密锁所在的路径
            return FindPort_2(0, 1, -1785508517, ref DevicePath);
        }

        public int CheckKeyByFindort_3()
        {
            //使用普通算法二查找指定的加密锁
            string DevicePath = ""; //用于储存加密锁所在的路径
            //@NoUseCode_FindPort_3 return 2;//如果这个锁不支持这个功能，直接返回2
            return FindPort_3(0, 1, 1613404515, ref DevicePath);
        }

        //使用带长度的方法从指定的地址读取字符串
        private int ReadStringEx(int addr, ref string outstring, string DevicePath)
        {
            int nlen, ret;
            byte[] buf = new byte[1];
            //先从地址0读到以前写入的字符串的长度
            ret = YReadEx(buf, (short)addr, (short)1, "5561F2BF", "F4563BFD", DevicePath);
            if (ret != 0) return ret;
            nlen = buf[0];
            //再读取相应长度的字符串
            return YReadString(ref outstring, addr + 1, nlen, "5561F2BF", "F4563BFD", DevicePath);

        }
        //使用从储存器读取相应数据的方式检查是否存在指定的加密锁
        public int CheckKeyByReadEprom()
        {
            int n, ret;
            string DevicePath = "";//用于储存加密锁所在的路径
            string outstring = "";
            //@NoUseCode_data return 1;//如果没有使用这个功能，直接返回1
            for (n = 0; n < 255; n++)
            {
                ret = FindPort(n, ref DevicePath);
                if (ret != 0) return ret;
                ret = ReadStringEx(0, ref outstring, DevicePath);
                if ((ret == 0) && (outstring.CompareTo("casun_software_v1.0") == 0)) return 0;
            }
            return -92;
        }
        //使用增强算法一检查加密锁，这个方法可以有效地防止仿真
        public int CheckKeyByEncstring()
        {
            //推荐加密方案：生成随机数，让锁做加密运算，同时在程序中端使用代码做同样的加密运算，然后进行比较判断。

            int n, ret;
            string DevicePath = "";//用于储存加密锁所在的路径
            string InString;

            //@NoUseKeyEx return 1;//如果没有使用这个功能，直接返回1
            System.Random rnd = new System.Random();

            InString = rnd.Next(0, 32767).ToString("X") + rnd.Next(0, 32767).ToString("X");

            for (n = 0; n < 255; n++)
            {
                ret = FindPort(n, ref DevicePath);
                if (ret != 0) return ret;
                if (Sub_CheckKeyByEncstring(InString, DevicePath) == 0) return 0;
            }
            return -92;
        }

        private int Sub_CheckKeyByEncstring(string InString, string DevicePath)
        {
            //使用增强算法一对字符串进行加密
            int ret;
            string outstring = "";
            string outstring_2;
            ret = EncString(InString, ref outstring, DevicePath);
            if (ret != 0) return ret;
            outstring_2 = StrEnc(InString, "38EAD53CD7DE1E7AAAB3570449AB8052");
            if (outstring_2.CompareTo(outstring) == 0)//比较结果是否相符
            {
                ret = 0;
            }
            else
            {
                ret = -92;
            }
            return ret;
        }

        //使用增强算法二检查是否存在对应的加密锁
        public int CheckKeyByEncstring_New()
        {
            int n, ret;
            string DevicePath = "";//用于储存加密锁所在的路径
            string outstring = "";
            //@NoUseNewKeyEx return 1;//如果没有使用这个功能，直接返回1
            //@NoSupNewKeyEx return 2;//如果该锁不支持这个功能，直接返回2
            for (n = 0; n < 255; n++)
            {
                ret = FindPort(n, ref DevicePath);
                if (ret != 0) return ret;
                ret = EncString_New("123456", ref outstring, DevicePath);
                if ((ret == 0) && (outstring.CompareTo("25FCF14ACE9FCF26") == 0)) return 0;
            }
            return -92;
        }
    }
}
