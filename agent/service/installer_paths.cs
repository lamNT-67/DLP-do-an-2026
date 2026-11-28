using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace DlpInstaller
{
    // Operations on legacy content use one ordinary NTFS component at a time.
    public static class Paths
    {
        const uint ReadControl = 0x20000, ReadAttributes = 0x80, Synchronize = 0x100000;
        const uint Delete = 0x10000, GenericRead = 0x80000000;
        const uint ShareRead = 1, ShareWrite = 2, ShareDelete = 4;
        const uint DirectoryAttribute = 0x10, ReparseAttribute = 0x400;
        const uint OpenReparsePoint = 0x200000, Synchronous = 0x20;
        const int ObjectNameNotFound = unchecked((int)0xC0000034);
        const int NoSuchFile = unchecked((int)0xC000000F);

        [StructLayout(LayoutKind.Sequential)]
        struct UnicodeString
        {
            public ushort Length, MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct ObjectAttributes
        {
            public int Length;
            public IntPtr RootDirectory, ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor, SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct IoStatusBlock
        {
            public IntPtr Status, Information;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct FileInformation
        {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
            public uint VolumeSerial, SizeHigh, SizeLow, LinkCount, IndexHigh, IndexLow;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct RenameInformation
        {
            public byte ReplaceIfExists;
            public IntPtr RootDirectory;
            public uint FileNameLength;
            public ushort FileName;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security,
            uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        static extern bool MoveFileExW(string source, string destination, uint flags);

        public static void ReplaceConfig(string prepared, string destination)
        {
            // REPLACE_EXISTING | WRITE_THROUGH. No cross-volume copy fallback.
            if (!MoveFileExW(prepared, destination, 1 | 8)) throw new Win32Exception();
        }

        [DllImport("ntdll.dll")]
        static extern int NtCreateFile(out SafeFileHandle file, uint access, ref ObjectAttributes attributes,
            out IoStatusBlock ioStatus, IntPtr allocation, uint fileAttributes, uint share, uint disposition,
            uint options, IntPtr eaBuffer, uint eaLength);

        [DllImport("ntdll.dll")]
        static extern int RtlNtStatusToDosError(int status);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation information);

        [DllImport("ntdll.dll")]
        static extern int NtSetInformationFile(SafeFileHandle file, out IoStatusBlock ioStatus,
            IntPtr data, uint length, int informationClass);

        [DllImport("advapi32.dll")]
        static extern uint GetSecurityInfo(SafeFileHandle file, int objectType, uint information,
            out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);

        [DllImport("advapi32.dll")]
        static extern int GetSecurityDescriptorLength(IntPtr descriptor);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr OpenSCManager(string computer, string database, uint access);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr OpenService(IntPtr manager, string name, uint access);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool QueryServiceObjectSecurity(IntPtr service, uint information, byte[] descriptor,
            uint length, out uint needed);

        [DllImport("advapi32.dll")]
        static extern bool CloseServiceHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr memory);

        static FileInformation Inspect(SafeFileHandle handle)
        {
            FileInformation info;
            if (!GetFileInformationByHandle(handle, out info)) throw new Win32Exception();
            if ((info.Attributes & ReparseAttribute) != 0) throw new IOException("Reparse point.");
            if ((info.Attributes & DirectoryAttribute) == 0 && info.LinkCount != 1)
                throw new IOException("Expected a regular file with exactly one hard link.");
            return info;
        }

        static SafeFileHandle Checked(SafeFileHandle handle, bool directory)
        {
            try
            {
                if (((Inspect(handle).Attributes & DirectoryAttribute) != 0) != directory)
                    throw new IOException(directory ? "Expected a directory." : "Expected a regular file.");
                return handle;
            }
            catch { handle.Dispose(); throw; }
        }

        static void RequireComponent(string name)
        {
            if (String.IsNullOrEmpty(name) || name.Length > 255 || name.EndsWith(".") || name.EndsWith(" ")
                || name.IndexOfAny(new[] { '\\', '/', ':', '\0' }) >= 0)
                throw new ArgumentException("Expected an ordinary path component.", "name");
        }

        public static SafeFileHandle OpenVolume(string path)
        {
            if (Path.GetPathRoot(path) != path || path.Length != 3 || path[1] != ':')
                throw new ArgumentException("Expected a drive root.", "path");
            var drive = new DriveInfo(path);
            if (drive.DriveType != DriveType.Fixed || drive.DriveFormat != "NTFS")
                throw new IOException("Setup requires a fixed NTFS volume.");
            var handle = CreateFileW(path, ReadControl | ReadAttributes, ShareRead | ShareWrite | ShareDelete,
                IntPtr.Zero, 3, 0x02000000 | OpenReparsePoint, IntPtr.Zero);
            if (handle.IsInvalid)
            {
                var error = new Win32Exception();
                handle.Dispose();
                throw error;
            }
            return Checked(handle, true);
        }

        public static SafeFileHandle OpenChild(SafeFileHandle parent, string name, bool directory, bool forRename)
        {
            RequireComponent(name);
            IntPtr text = Marshal.StringToHGlobalUni(name);
            IntPtr value = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
            try
            {
                Marshal.StructureToPtr(new UnicodeString {
                    Length = (ushort)(name.Length * 2), MaximumLength = (ushort)(name.Length * 2 + 2), Buffer = text
                }, value, false);
                var attributes = new ObjectAttributes {
                    Length = Marshal.SizeOf(typeof(ObjectAttributes)), RootDirectory = parent.DangerousGetHandle(),
                    ObjectName = value, Attributes = 0x40 // OBJ_CASE_INSENSITIVE
                };
                // Exclude writes and deletes while reading a data file. A rename
                // handle excludes competing delete/rename handles for that object.
                uint share = directory ? ShareRead | ShareWrite : ShareRead;
                if (directory && !forRename) share |= ShareDelete;
                uint access = directory ? ReadControl | ReadAttributes : GenericRead;
                if (forRename) access |= Delete;
                SafeFileHandle result;
                IoStatusBlock statusBlock;
                int status = NtCreateFile(out result, access | Synchronize, ref attributes, out statusBlock,
                    IntPtr.Zero, 0, share, 1, (directory ? 1u : 0x40u) | Synchronous | OpenReparsePoint,
                    IntPtr.Zero, 0);
                GC.KeepAlive(parent);
                if (status == ObjectNameNotFound || status == NoSuchFile) return null;
                if (status < 0) throw new Win32Exception(RtlNtStatusToDosError(status));
                return Checked(result, directory);
            }
            finally
            {
                Marshal.FreeHGlobal(value);
                Marshal.FreeHGlobal(text);
            }
        }

        public static string Identity(SafeFileHandle handle)
        {
            var info = Inspect(handle);
            return String.Format("{0:X8}:{1:X8}{2:X8}", info.VolumeSerial, info.IndexHigh, info.IndexLow);
        }

        public static byte[] SecurityDescriptor(SafeFileHandle handle)
        {
            IntPtr owner, group, dacl, sacl, descriptor;
            uint error = GetSecurityInfo(handle, 1, 5, out owner, out group, out dacl, out sacl, out descriptor);
            if (error != 0) throw new Win32Exception((int)error);
            try
            {
                var bytes = new byte[GetSecurityDescriptorLength(descriptor)];
                Marshal.Copy(descriptor, bytes, 0, bytes.Length);
                return bytes;
            }
            finally { LocalFree(descriptor); }
        }

        public static byte[] ServiceSecurityDescriptor(string name)
        {
            IntPtr manager = OpenSCManager(null, null, 1);
            if (manager == IntPtr.Zero) throw new Win32Exception();
            try
            {
                IntPtr service = OpenService(manager, name, ReadControl);
                if (service == IntPtr.Zero) throw new Win32Exception();
                try
                {
                    var descriptor = new byte[8192]; // QueryServiceObjectSecurity maximum.
                    uint needed;
                    if (!QueryServiceObjectSecurity(service, 5, descriptor, (uint)descriptor.Length, out needed))
                        throw new Win32Exception();
                    return descriptor;
                }
                finally { CloseServiceHandle(service); }
            }
            finally { CloseServiceHandle(manager); }
        }

        public static byte[] ReadConfig(SafeFileHandle handle)
        {
            Inspect(handle);
            using (var stream = new FileStream(handle, FileAccess.Read))
            {
                if (stream.Length > 65536) throw new IOException("Enrollment config exceeds 64 KiB.");
                var bytes = new byte[(int)stream.Length];
                int read = 0;
                while (read < bytes.Length)
                {
                    int count = stream.Read(bytes, read, bytes.Length - read);
                    if (count == 0) throw new IOException("Enrollment config changed while being read.");
                    read += count;
                }
                Inspect(handle);
                return bytes;
            }
        }

        public static void Rename(SafeFileHandle source, SafeFileHandle parent, string name)
        {
            RequireComponent(name);
            if (Inspect(source).VolumeSerial != Inspect(parent).VolumeSerial)
                throw new IOException("Setup requires a same-volume rename.");
            byte[] fileName = Encoding.Unicode.GetBytes(name);
            int offset = Marshal.OffsetOf(typeof(RenameInformation), "FileName").ToInt32();
            int length = offset + fileName.Length + 2;
            IntPtr buffer = Marshal.AllocHGlobal(length);
            try
            {
                Marshal.Copy(new byte[length], 0, buffer, length);
                Marshal.WriteIntPtr(buffer, Marshal.OffsetOf(typeof(RenameInformation), "RootDirectory").ToInt32(),
                    parent.DangerousGetHandle());
                Marshal.WriteInt32(buffer, Marshal.OffsetOf(typeof(RenameInformation), "FileNameLength").ToInt32(),
                    fileName.Length);
                Marshal.Copy(fileName, 0, IntPtr.Add(buffer, offset), fileName.Length);
                // FileRenameInformation with ReplaceIfExists left false.
                IoStatusBlock ioStatus;
                int status = NtSetInformationFile(source, out ioStatus, buffer, (uint)length, 10);
                if (status < 0) throw new Win32Exception(RtlNtStatusToDosError(status));
                GC.KeepAlive(parent);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
    }

    // Retain the process object from inspection through shutdown. A PID
    // from the process inventory is only a candidate, never a kill target.
    public sealed class ClipboardWorker : IDisposable
    {
        const uint WaitTimeout = 258;
        readonly SafeWaitHandle process;
        readonly uint processId;
        public long CreationTime { get; private set; }

        [StructLayout(LayoutKind.Sequential)]
        struct ProcessBasicInformation
        {
            public IntPtr ExitStatus, Peb, Affinity, Priority, ProcessId, ParentProcessId;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern SafeWaitHandle OpenProcess(uint access, bool inherit, uint pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetProcessTimes(SafeWaitHandle handle, out long created, out long exited,
            out long kernel, out long user);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ProcessIdToSessionId(uint pid, out uint session);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        static extern bool QueryFullProcessImageNameW(SafeWaitHandle handle, uint flags, StringBuilder path, ref int length);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(SafeWaitHandle handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool TerminateProcess(SafeWaitHandle handle, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(SafeWaitHandle handle, IntPtr address, byte[] buffer, UIntPtr size, out UIntPtr read);

        [DllImport("ntdll.dll")]
        static extern int NtQueryInformationProcess(SafeWaitHandle handle, int informationClass,
            out ProcessBasicInformation information, int size, out int resultLength);

        [DllImport("ntdll.dll", EntryPoint = "NtQueryInformationProcess")]
        static extern int QueryProcessPointer(SafeWaitHandle handle, int informationClass,
            out IntPtr information, int size, out int resultLength);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        static extern IntPtr FindWindowExW(IntPtr parent, IntPtr after, string className, string windowName);

        [DllImport("user32.dll")]
        static extern uint GetWindowThreadProcessId(IntPtr window, out uint pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern SafeWaitHandle OpenThread(uint access, bool inherit, uint threadId);

        [DllImport("kernel32.dll")]
        static extern uint GetProcessIdOfThread(SafeWaitHandle handle);

        [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
        static extern bool PostThreadMessageW(uint threadId, uint message, UIntPtr wParam, IntPtr lParam);

        ClipboardWorker(SafeWaitHandle handle, uint pid)
        {
            process = handle;
            processId = pid;
        }

        public static ClipboardWorker Open(uint pid, long expectedTime, uint expectedSession, string expectedImage,
            bool allowTermination)
        {
            // SYNCHRONIZE | QUERY_INFORMATION | QUERY_LIMITED_INFORMATION | VM_READ.
            var handle = OpenProcess(0x101410u | (allowTermination ? 1u : 0), false, pid);
            if (handle.IsInvalid)
            {
                var error = new Win32Exception();
                handle.Dispose();
                if (error.NativeErrorCode == 87) return null; // The candidate has exited.
                throw error;
            }
            var worker = new ClipboardWorker(handle, pid);
            bool matched = false;
            try
            {
                if (worker.HasExited) return null;
                long created, exited, kernel, user;
                if (!GetProcessTimes(handle, out created, out exited, out kernel, out user)) throw new Win32Exception();
                // Win32_Process exposes microseconds. FILETIME uses 100 ns ticks.
                if (created / 10 != expectedTime / 10) return null;
                var path = new StringBuilder(32768);
                int length = path.Capacity;
                uint session;
                if (!QueryFullProcessImageNameW(handle, 0, path, ref length) ||
                    !ProcessIdToSessionId(pid, out session)) throw new Win32Exception();
                if (session != expectedSession || !String.Equals(path.ToString(), expectedImage, StringComparison.OrdinalIgnoreCase))
                    return null;
                worker.CreationTime = created;
                if (worker.HasExited) return null;
                matched = true;
                return worker;
            }
            catch (Win32Exception)
            {
                if (worker.HasExited) return null;
                throw;
            }
            finally { if (!matched) worker.Dispose(); }
        }

        public bool HasExited
        {
            get { return IsSignalled(process); }
        }

        static bool IsSignalled(SafeWaitHandle handle)
        {
            uint result = WaitForSingleObject(handle, 0);
            if (result == 0) return true;
            if (result == WaitTimeout) return false;
            throw new Win32Exception();
        }

        byte[] Read(IntPtr address, int length)
        {
            var bytes = new byte[length];
            UIntPtr count;
            if (address == IntPtr.Zero ||
                !ReadProcessMemory(process, address, bytes, (UIntPtr)(uint)length, out count) || count.ToUInt64() != (ulong)length)
                throw new IOException("Cannot read Clipboard process parameters.");
            return bytes;
        }

        static IntPtr ReadPointer(byte[] bytes, int offset, bool wow64)
        {
            return wow64 ? new IntPtr((long)BitConverter.ToUInt32(bytes, offset)) :
                new IntPtr(BitConverter.ToInt64(bytes, offset));
        }

        public string WorkingDirectory()
        {
            // This installer runs in native 64-bit PowerShell. Read only the
            // CurrentDirectory.DosPath from the held process's parameters.
            if (IntPtr.Size != 8) throw new InvalidOperationException("Clipboard inspection requires a 64-bit installer.");
            IntPtr peb;
            int size;
            if (QueryProcessPointer(process, 26, out peb, IntPtr.Size, out size) < 0)
                throw new IOException("Cannot determine Clipboard process architecture.");
            bool wow64 = peb != IntPtr.Zero;
            if (!wow64)
            {
                ProcessBasicInformation info;
                if (NtQueryInformationProcess(process, 0, out info, Marshal.SizeOf(typeof(ProcessBasicInformation)), out size) < 0)
                    throw new IOException("Cannot locate Clipboard process parameters.");
                peb = info.Peb;
            }
            IntPtr parameters = ReadPointer(Read(IntPtr.Add(peb, wow64 ? 0x10 : 0x20), wow64 ? 4 : 8), 0, wow64);
            byte[] entry = Read(IntPtr.Add(parameters, wow64 ? 0x24 : 0x38), wow64 ? 8 : 16);
            int length = BitConverter.ToUInt16(entry, 0);
            if (length == 0 || (length & 1) != 0 || length > BitConverter.ToUInt16(entry, 2))
                throw new IOException("Invalid Clipboard working directory.");
            return Encoding.Unicode.GetString(Read(ReadPointer(entry, wow64 ? 4 : 8, wow64), length)).TrimEnd('\\');
        }

        public bool RequestExit()
        {
            IntPtr window = IntPtr.Zero;
            for (int i = 0; i < 256 && !HasExited; i++)
            {
                window = FindWindowExW(new IntPtr(-3), window, "DLPClipboardWatcher", null);
                if (window == IntPtr.Zero) break;
                uint owner;
                uint threadId = GetWindowThreadProcessId(window, out owner);
                if (threadId == 0 || owner != processId) continue;
                // Hold the target thread too, and confirm that its message
                // window still belongs to this process before requesting quit.
                using (var thread = OpenThread(0x100800, false, threadId))
                {
                    if (!thread.IsInvalid && GetProcessIdOfThread(thread) == processId && !IsSignalled(thread) &&
                        GetWindowThreadProcessId(window, out owner) == threadId && owner == processId &&
                        !HasExited && PostThreadMessageW(threadId, 0x0012, UIntPtr.Zero, IntPtr.Zero))
                        return true; // WM_QUIT reaches ClipboardWatcher's existing cleanup loop.
                }
            }
            return false; // The task can be on another desktop or still starting.
        }

        public void Terminate()
        {
            if (HasExited || TerminateProcess(process, 1)) return;
            var error = new Win32Exception();
            if (!HasExited) throw error;
        }

        public void Dispose() { process.Dispose(); }
    }
}
