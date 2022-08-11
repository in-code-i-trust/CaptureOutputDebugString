using System.Runtime.InteropServices;

#region Usage (Compiles & works on .NET 6)
var v = new Scribble.DebugView();
v.Start((pid, text) => { Console.Write($"{pid}: {text}"); });
Console.CancelKeyPress += (sender, arg) => { v.Stop(); };

while (v.Running) 
{
    Thread.Sleep(100);
}
#endregion

namespace Scribble
{
    /// <summary>
    /// Captures messages coming out from OutputDebugString().
    /// </summary>
    public class DebugView : IDisposable
    {
        ~DebugView() 
        {
            Stop();
        }

        public void Dispose() 
        {
            Stop();
        }

        /// <summary>
        /// Is running or not.
        /// </summary>
        public bool Running { get; private set; }

        /// <summary>
        /// Start capturing.
        /// </summary>
        /// <param name="onReceived">A callback handler called on OutputDebugString(). Note that worker thread will perform callback.</param>
        /// <param name="unique_key">An unique key to identify underlying the Kernel mutex object.</param>
        /// <exception cref="Exception">Thrown if capturing couldn't be started. Possibly due to insufficient kernel resources.</exception>
        public void Start(Action<int, string> onReceived, string? unique_key = default)
        {
            lock (_SyncObject)
            {
                if (Running)
                {
                    throw new Exception("Already running.");
                }

                _OnReceived = onReceived;

                _Mutex = new Mutex(false, unique_key ?? GetType().FullName, out var firstInstance);
                if (!firstInstance)
                {
                    throw new Exception("Another instance with same key is already running.");
                }

                var sa = new SECURITY_ATTRIBUTES();

                _AckEvent = CreateEvent(ref sa, false, false, "DBWIN_BUFFER_READY");
                _ReadyEvent = CreateEvent(ref sa, false, false, "DBWIN_DATA_READY");
                _SharedFile = CreateFileMapping(new IntPtr(-1), ref sa, PAGE_READWRITE, 0, SizeOfDBWinBuffer, "DBWIN_BUFFER");
                _SharedMem = MapViewOfFile(_SharedFile, SECTION_MAP_READ, 0, 0, 0);

                if (_AckEvent == IntPtr.Zero || _ReadyEvent == IntPtr.Zero || _SharedFile == IntPtr.Zero || _SharedMem == IntPtr.Zero)
                {
                    throw new Exception("DBWIN* error.");
                }

                Running = true;
                _CaptureThread = new Thread(CaptureProc);
                _CaptureThread.IsBackground = true;
                _CaptureThread.Start();
            }
        }

        /// <summary>
        /// Stop capturing.
        /// </summary>
        public void Stop()
        {
            lock (_SyncObject)
            {
                if (Running) 
                {
                    Running = false;
                    SetEvent(_ReadyEvent);
                    _CaptureThread!.Join();
                    _CaptureThread = null;
                }
            }
        }

        /// <summary>
        /// Capturing thread.
        /// </summary>
        private void CaptureProc()
        {
            try
            {
                while (Running)
                {
                    SetEvent(_AckEvent);

                    int ret = WaitForSingleObject(_ReadyEvent, INFINITE);
                    if (!Running)
                    {
                        break;
                    }

                    if (ret == WAIT_OBJECT_0)
                    {
                        // Decode `struct DBWinBuffer`
                        var pid = Marshal.ReadInt32(_SharedMem);
                        var text = Marshal.PtrToStringAnsi(new IntPtr(_SharedMem.ToInt64() + Marshal.SizeOf(typeof(int))));

                        try
                        {
                            _OnReceived!.Invoke(pid, text!);
                        }
                        catch { }
                    }
                }
            }
            finally
            {
                CloseHandle(_AckEvent);
                _AckEvent = IntPtr.Zero;

                CloseHandle(_ReadyEvent);
                _ReadyEvent = IntPtr.Zero;

                CloseHandle(_SharedFile);
                _SharedFile = IntPtr.Zero;

                UnmapViewOfFile(_SharedMem);
                _SharedMem = IntPtr.Zero;

                _Mutex!.Close();
                _Mutex = null;
            }
        }

        private IntPtr _AckEvent;
        private IntPtr _ReadyEvent;
        private IntPtr _SharedFile;
        private IntPtr _SharedMem;
        private Thread? _CaptureThread;
        private object _SyncObject = new object();
        private Mutex? _Mutex;
        private Action<int, string>? _OnReceived;

        #region Native API
        // https://docs.microsoft.com/ja-jp/archive/blogs/reiley/a-debugging-approach-to-outputdebugstring
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct DBWinBuffer
        {
            // DWORD dwProcessId;
            // BYTE  abData[4096 - sizeof(DWORD)];
        }
        private const int SizeOfDBWinBuffer = 4096;

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        private const uint PAGE_READWRITE = 0x4;
        private const int WAIT_OBJECT_0 = 0;
        private const uint INFINITE = 0xFFFFFFFF;
        private const uint SECTION_MAP_READ = 0x4;

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateEvent(ref SECURITY_ATTRIBUTES sa, bool bManualReset, bool bInitialState, string lpName);

        [DllImport("kernel32.dll")]
        private static extern bool SetEvent(IntPtr hEvent);

        [DllImport("kernel32", SetLastError = true, ExactSpelling = true)]
        private static extern Int32 WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateFileMapping(IntPtr hFile, ref SECURITY_ATTRIBUTES lpFileMappingAttributes, uint flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, uint dwNumberOfBytesToMap);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hHandle);
        #endregion
    }
}
