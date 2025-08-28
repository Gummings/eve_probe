using System;
using System.Threading;
using System.Runtime.InteropServices;
using EasyHook;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.IO;

namespace HookInject
{
    /// <summary>
    /// Hook 注入入口类。
    ///
    /// 主要职责：
    /// - 通过 EasyHook 在目标进程中安装多处 API 钩子：
    ///   1) 加密/解密相关：advapi32!CryptEncrypt / CryptDecrypt
    ///   2) 网络发送/接收：ws2_32!WSASend / WSARecv
    ///   3) 文件写入：kernel32!WriteFile（用于抓取特定配置文件内容）
    /// - 通过 IPC 与宿主（eve_probe）通信，实时上报抓取到的明文/密文数据、配置文件片段等。
    /// - 维持到宿主的心跳（Ping）并处理从宿主注入回来的数据包（加密后转发）。
    ///
    /// 重要成员：
    /// - <see cref="Interface"/>：与宿主进程通信的 IPC 接口。
    /// - <see cref="ccpSock"/>：识别到的目标服务器 Socket（根据对端 IP 判断）。
    /// - <see cref="lastHkey"/>：最近一次用于 CryptEncrypt/CryptDecrypt 的密钥句柄，用于后续主动加密发送。
    /// - <see cref="antiGC"/>：保存 LocalHook 引用，避免被 GC 回收导致钩子失效。
    /// </summary>
    public class Main : EasyHook.IEntryPoint
    {
        // 与宿主（WPF 端）通信的 IPC 接口
        eve_probe.HookInterface Interface;

        // 记录已识别的服务器 Socket（目标：87.237.34.200），用于后续主动 send()
        IntPtr ccpSock = IntPtr.Zero;

        // 最近一次在加/解密 API 中出现的密钥句柄，用于主动封包时复用
        IntPtr lastHkey = IntPtr.Zero;

        // 保存所有安装的钩子，防止被 GC 回收
        List<LocalHook> antiGC = new List<LocalHook>();

        public Main(
            RemoteHooking.IContext InContext,
            String InChannelName)
        {
            // 连接宿主进程（WPF 端）的 IPC 通道
            Interface = RemoteHooking.IpcConnectClient<eve_probe.HookInterface>(InChannelName);

            // 初始心跳，确认通道畅通
            Interface.Ping();
        }

        public void Run(
            RemoteHooking.IContext InContext,
            String InChannelName)
        {
            // 安装各类 API 钩子
            try
            {
                antiGC.Add(LocalHook.Create(
                    LocalHook.GetProcAddress("advapi32.dll", "CryptEncrypt"),
                    new DCryptEncrypt(CryptEncrypt_Hooked),
                    this));
                // 线程 ACL 设置（按 EasyHook 常见示例使用方式）
                antiGC.Last().ThreadACL.SetExclusiveACL(new Int32[] { 0 });

                antiGC.Add(LocalHook.Create(
                    LocalHook.GetProcAddress("advapi32.dll", "CryptDecrypt"),
                    new DCryptDecrypt(CryptDecrypt_Hooked),
                    this));
                // 线程 ACL 设置（按 EasyHook 常见示例使用方式）
                antiGC.Last().ThreadACL.SetExclusiveACL(new Int32[] { 0 });

                antiGC.Add(LocalHook.Create(
                    LocalHook.GetProcAddress("ws2_32.dll", "WSASend"),
                    new DWSASend(WSASend_Hooked),
                    this));
                // 线程 ACL 设置（按 EasyHook 常见示例使用方式）
                antiGC.Last().ThreadACL.SetExclusiveACL(new Int32[] { 0 });

                antiGC.Add(LocalHook.Create(
                    LocalHook.GetProcAddress("ws2_32.dll", "WSARecv"),
                    new DWSARecv(WSARecv_Hooked),
                    this));
                // 线程 ACL 设置（按 EasyHook 常见示例使用方式）
                antiGC.Last().ThreadACL.SetExclusiveACL(new Int32[] { 0 });

                antiGC.Add(LocalHook.Create(
                    LocalHook.GetProcAddress("Kernel32.dll", "WriteFile"),
                    new DWriteFile(WriteFile_Hooked),
                    this));
                // 线程 ACL 设置（按 EasyHook 常见示例使用方式）
                antiGC.Last().ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            }
            catch (Exception ExtInfo)
            {
                Interface.ReportException(ExtInfo);

                return;
            }

            Interface.IsInstalled(RemoteHooking.GetCurrentProcessId());

            RemoteHooking.WakeUpProcess();

            // 主循环：
            // - 接收宿主注入过来的待发数据（PollInjectionQueue）
            // - 若已识别到服务器 Socket 与有效密钥，则对数据进行就地加密并通过 send() 发送
            // - 定期 Ping 维持心跳；宿主退出将导致 Ping 抛异常，从而结束循环
            try
            {
                while (true)
                {
                    Thread.Sleep(500);

                    try
                    { 
                        var pck = Interface.PollInjectionQueue();
                        if (pck != null && ccpSock != IntPtr.Zero && lastHkey != IntPtr.Zero)
                        {
                            // 预留额外空间：就地加密需要富余缓冲区，同时在前面写入长度头（4 字节）
                            var exlen = 256; // in-place 加密 + 长度头的冗余空间
                            var wsabuf = Marshal.AllocHGlobal(pck.Length + exlen);
                            IntPtr plen = Marshal.AllocHGlobal(4);
                            Marshal.WriteInt32(plen, pck.Length);

                            // 跳过前 4 字节，留作长度头；将原始数据拷贝到缓冲区
                            var wsaData = IntPtr.Add(wsabuf, 4); // 预留长度头
                            Marshal.Copy(pck, 0, wsaData, pck.Length);
                            CryptEncrypt(lastHkey, IntPtr.Zero, 1, 0, wsaData, plen, (uint)(pck.Length + exlen - 4));
                            var len  = Marshal.ReadInt32(plen);
                            // 将加密后长度写入缓冲区头 4 字节
                            Marshal.WriteInt32(wsabuf, Marshal.ReadInt32(plen));

                            int sent = send(ccpSock, wsabuf, len + 4, 0);
                            Interface.log("Sent " + sent + " bytes");

                            Marshal.FreeHGlobal(plen);
                            Marshal.FreeHGlobal(wsabuf);
                        }
                    }
                    catch (Exception ExtInfo)
                    {
                        Interface.ReportException(ExtInfo);
                    }

                    Interface.Ping();
                }
            }
            catch //(Exception ExtInfo)
            {
                //System.Windows.Forms.MessageBox.Show(ExtInfo.ToString());
                // Ping() will raise an exception if host is unreachable
            }

            foreach (var o in antiGC)
                o.Dispose();
            LocalHook.Release();
        }


        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        /// <summary>
        /// WriteFile 的托管委托定义（与原型保持一致）。
        /// </summary>
        /// <param name="hFile">文件句柄</param>
        /// <param name="lpBuffer">写入缓冲区指针</param>
        /// <param name="len">写入字节数</param>
        /// <param name="buflen">实际写入字节数返回指针（可空）</param>
        /// <param name="lpOverlapped">异步结构体（可空）</param>
        delegate bool DWriteFile(IntPtr hFile, IntPtr lpBuffer, int len, IntPtr buflen, IntPtr lpOverlapped);

        [DllImport("kernel32", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool WriteFile(IntPtr hFile, IntPtr lpBuffer, int len, IntPtr buflen, IntPtr lpOverlapped);

        [DllImport("kernel32", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern uint GetFinalPathNameByHandle(IntPtr hFile, IntPtr lpBuffer, uint len, uint flags);

        /// <summary>
        /// WriteFile 钩子：
        /// - 拦截文件写入，定位目标路径是否匹配 core_char_*.dat
        /// - 若匹配，则复制写入内容并通过 IPC 上报（标记为 "Cfg"）
        /// - 最后调用原始 WriteFile 保持原有行为
        /// </summary>
        private bool WriteFile_Hooked(IntPtr hFile, IntPtr lpBuffer, int len, IntPtr buflen, IntPtr lpOverlapped)
        {
            bool ret = false;
            Main This = (Main)HookRuntimeInfo.Callback;
            try
            {
                var path = Marshal.AllocHGlobal(1024);
                var plen = GetFinalPathNameByHandle(hFile, path, 1024, 0);
                var strPath = Marshal.PtrToStringAnsi(path);
                Marshal.FreeHGlobal(path);

                if (plen > 0 && Regex.IsMatch(strPath, "\\\\core_char_(\\d+)\\.dat$"))
                {
                    byte[] data = new byte[len];
                    Marshal.Copy(lpBuffer, data, 0, len);

                    This.Interface.Enqueue(new Tuple<string, byte[], byte[]>("Cfg", data, null));
                }
                
                ret = WriteFile(hFile, lpBuffer, len, buflen, lpOverlapped);
            }
            catch (Exception ExtInfo)
            {
                This.Interface.ReportException(ExtInfo);
            }
            return ret;
        }


        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        /// <summary>
        /// WSASend 的托管委托定义。
        /// </summary>
        delegate int DWSASend(IntPtr s, IntPtr lpBuffers, uint dwBufferCount, IntPtr lpNumberOfBytesSent, uint dwFlags, IntPtr lpOverlapped, IntPtr lpCompletionRoutine);

        [DllImport("ws2_32", SetLastError = true)]
        static extern int WSASend(IntPtr s, IntPtr lpBuffers, uint dwBufferCount, IntPtr lpNumberOfBytesSent, uint dwFlags, IntPtr lpOverlapped, IntPtr lpCompletionRoutine);

        [DllImport("ws2_32", SetLastError = true)]
        static extern int getpeername(IntPtr s, IntPtr sockaddr, IntPtr namelen);

        [DllImport("ws2_32")]
        static extern int WSAGetLastError();

        [DllImport("ws2_32", SetLastError = true)]
        static extern int send(IntPtr s, IntPtr buf, int len, int flags);

        /// <summary>
        /// WSASend 钩子：
        /// - 首次看见该 socket 的对端地址时，通过 getpeername 识别是否为目标服务器（87.237.34.200）
        /// - 若是，则缓存 socket 到 <see cref="ccpSock"/> 以便主动发送封包
        /// - 之后直接调用原始 WSASend
        /// 注意：getpeername 结果中的地址为机器字节序，这里用常量比较（3357732183）。
        /// </summary>
        private int WSASend_Hooked(IntPtr s, IntPtr lpBuffers, uint dwBufferCount, IntPtr lpNumberOfBytesSent, uint dwFlags, IntPtr lpOverlapped, IntPtr lpCompletionRoutine)
        {
            Main This = (Main)HookRuntimeInfo.Callback;
            try
            {
                if (ccpSock == IntPtr.Zero)
                {
                    int len = 16;
                    var name = Marshal.AllocHGlobal(len);
                    var plen = Marshal.AllocHGlobal(sizeof(int));
                    Marshal.WriteInt32(plen, len);
                    var ret = getpeername(s, name, plen);

                    if ((uint)Marshal.ReadInt32(name, 4) == 3357732183) // 87.237.34.200（机器字节序相反）
                    {
                        ccpSock = s;
                    }

                    Marshal.FreeHGlobal(name);
                    Marshal.FreeHGlobal(plen);
                }
            }
            catch (Exception ExtInfo)
            {
                try
                { 
                    This.Interface.ReportException(ExtInfo);
                }
                catch { }
            }
            return WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
        }


        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        /// <summary>
        /// WSARecv 的托管委托定义。
        /// </summary>
        delegate int DWSARecv(IntPtr s, IntPtr lpBuffers, uint dwBufferCount, IntPtr lpNumberOfBytes, IntPtr dwFlags, IntPtr lpOverlapped, IntPtr lpCompletionRoutine);

        [DllImport("ws2_32", SetLastError = true)]
        static extern int WSARecv(IntPtr s, IntPtr lpBuffers, uint dwBufferCount, IntPtr lpNumberOfBytes, IntPtr dwFlags, IntPtr lpOverlapped, IntPtr lpCompletionRoutine);

        /// <summary>
        /// WSARecv 钩子：逻辑与 WSASend 钩子类似，也用于识别目标服务器 socket。
        /// 识别后调用原始 WSARecv，不改变数据流。
        /// </summary>
        private int WSARecv_Hooked(IntPtr s, IntPtr lpBuffers, uint dwBufferCount, IntPtr lpNumberOfBytes, IntPtr dwFlags, IntPtr lpOverlapped, IntPtr lpCompletionRoutine)
        {
            Main This = (Main)HookRuntimeInfo.Callback;
            try
            {
                if (ccpSock == IntPtr.Zero)
                {
                    int len = 16;
                    var name = Marshal.AllocHGlobal(len);
                    var plen = Marshal.AllocHGlobal(sizeof(int));
                    Marshal.WriteInt32(plen, len);
                    var ret = getpeername(s, name, plen);

                    if ((uint)Marshal.ReadInt32(name, 4) == 3357732183) // 87.237.34.200（机器字节序相反）
                    {
                        ccpSock = s;
                    }

                    Marshal.FreeHGlobal(name);
                    Marshal.FreeHGlobal(plen);
                }
            }
            catch (Exception ExtInfo)
            {
                try
                {
                    This.Interface.ReportException(ExtInfo);
                }
                catch { }
            }
            return WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytes, dwFlags, lpOverlapped, lpCompletionRoutine);
        }



        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        /// <summary>
        /// CryptEncrypt 的托管委托定义。
        /// </summary>
        delegate bool DCryptEncrypt(IntPtr hKey, IntPtr hHash, int Final, uint dwFlags, [In] [Out] IntPtr pbData, [In] [Out] IntPtr pdwDataLen, uint dwBufLen);

        [DllImport("advapi32", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CryptEncrypt(IntPtr hKey, IntPtr hHash, int Final, uint dwFlags, [In] [Out] IntPtr pbData, [In] [Out] IntPtr pdwDataLen, uint dwBufLen);

        /// <summary>
        /// CryptEncrypt 钩子：
        /// - 在调用原函数前，复制待加密数据（rawData）
        /// - 调用原函数后，复制加密结果（cryptedData）
        /// - 通过 IPC 上报（标记为 "Out"，表示从本地发往远端的数据）
        /// - 同时缓存 hKey 到 <see cref="lastHkey"/>，便于主动发送时复用密钥
        /// </summary>
        private bool CryptEncrypt_Hooked(IntPtr hKey, IntPtr hHash, int Final, uint dwFlags, [In] [Out] IntPtr pbData, [In] [Out] IntPtr pdwDataLen, uint dwBufLen)
        {
            bool ret = false;
            Main This = (Main)HookRuntimeInfo.Callback;
            try
            {
                var size = Marshal.ReadInt32(pdwDataLen);
                byte[] rawData = new byte[size];
                bool doCopy = (size != 0 && pbData != IntPtr.Zero);

                if (doCopy)
                {
                    lastHkey = hKey;
                    Marshal.Copy(pbData, rawData, 0, size);
                }

                ret = CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);

                if (doCopy)
                {
                    size = Marshal.ReadInt32(pdwDataLen);
                    byte[] cryptedData = new byte[size];
                    Marshal.Copy(pbData, cryptedData, 0, size);

                    This.Interface.Enqueue(new Tuple<string, byte[], byte[]>("Out", rawData, cryptedData));
                }
            }
            catch (Exception ExtInfo)
            {
                try
                {
                    This.Interface.ReportException(ExtInfo);
                }
                catch { }
            }
            return ret;
        }


        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        /// <summary>
        /// CryptDecrypt 的托管委托定义。
        /// </summary>
        delegate bool DCryptDecrypt(IntPtr hKey, IntPtr hHash, int Final, uint dwFlags, [In] [Out] IntPtr pbData, [In] [Out] IntPtr pdwDataLen);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CryptDecrypt(IntPtr hKey, IntPtr hHash, int Final, uint dwFlags, [In] [Out] IntPtr pbData, [In] [Out] IntPtr pdwDataLen);

        /// <summary>
        /// CryptDecrypt 钩子：
        /// - 在调用原函数前，复制输入的密文（cryptedData）
        /// - 调用原函数后，复制解密得到的明文（rawData）
        /// - 通过 IPC 上报（标记为 "In"，表示从远端到本地的数据）
        /// - 同时缓存 hKey 到 <see cref="lastHkey"/>，便于主动发送时复用密钥
        /// </summary>
        private bool CryptDecrypt_Hooked(IntPtr hKey, IntPtr hHash, int Final, uint dwFlags, [In] [Out] IntPtr pbData, [In] [Out] IntPtr pdwDataLen)
        {
            bool ret = false;
            Main This = (Main)HookRuntimeInfo.Callback;
            try
            {
                var size = Marshal.ReadInt32(pdwDataLen);
                byte[] cryptedData = new byte[size];
                bool doCopy = (size != 0 && pbData != IntPtr.Zero);

                if (doCopy)
                {
                    lastHkey = hKey;
                    Marshal.Copy(pbData, cryptedData, 0, size);
                }

                ret = CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);

                if (doCopy)
                {
                    size = Marshal.ReadInt32(pdwDataLen);
                    byte[] rawData = new byte[size];
                    Marshal.Copy(pbData, rawData, 0, size);

                    This.Interface.Enqueue(new Tuple<string, byte[], byte[]>("In", rawData, cryptedData));
                }
            }
            catch (Exception ExtInfo)
            {
                try
                {
                    This.Interface.ReportException(ExtInfo);
                }
                catch { }
            }
            return ret;
        }
    }
}
