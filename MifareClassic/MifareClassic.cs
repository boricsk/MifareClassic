using System.Runtime.InteropServices;
using System.Text;

namespace MifareClassic
{
    public class MifareClassicCard
    {
        private readonly byte[] _defaultKey = new byte[6] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        private readonly byte[] _zero = new byte[16];
        private readonly byte[] _readCardUID = { 0xFF, 0xCA, 0x00, 0x00, 0x00 };

        private List<byte> M4kWritableBlocks = new List<byte>();
        private List<byte> M2kWritableBlocks = new List<byte>();
        private IntPtr _hContext;
        private IntPtr _hCard;
        private IntPtr _activeProtocol;
        private string _readerName = string.Empty;

        public int SCardEstablishContextReturn { get; private set; }
        public int SCardConnectReturn { get; private set; }        

        #region winscard.dll
        const uint SCARD_SCOPE_USER = 0;
        const uint SCARD_SHARE_SHARED = 2;
        const uint SCARD_PROTOCOL_T0 = 1;
        const uint SCARD_PROTOCOL_T1 = 2;
        const uint SCARD_LEAVE_CARD = 0;

        [DllImport("winscard.dll")]
        static extern int SCardEstablishContext(uint dwScope, IntPtr pvReserved1, IntPtr pvReserved2, out IntPtr phContext);

        [DllImport("winscard.dll")]
        static extern int SCardListReaders(IntPtr hContext, byte[]? mszGroups, byte[] mszReaders, ref uint pcchReaders);

        [DllImport("winscard.dll")]
        static extern int SCardConnect(IntPtr hContext, string szReader, uint dwShareMode, uint dwPreferredProtocols, out IntPtr phCard, out IntPtr pdwActiveProtocol);

        [DllImport("winscard.dll")]
        static extern int SCardTransmit(IntPtr hCard, ref SCARD_IO_REQUEST pioSendPci, byte[] pbSendBuffer, int cbSendLength, IntPtr pioRecvPci, byte[] pbRecvBuffer, ref int pcbRecvLength);

        [DllImport("winscard.dll")]
        static extern int SCardDisconnect(IntPtr hCard, int dwDisposition);

        [StructLayout(LayoutKind.Sequential)]
        public struct SCARD_IO_REQUEST
        {
            public uint dwProtocol;
            public uint cbPciLength;
        }

        static SCARD_IO_REQUEST SCARD_PCI_T1 = new SCARD_IO_REQUEST() { dwProtocol = SCARD_PROTOCOL_T1, cbPciLength = (uint)Marshal.SizeOf(typeof(SCARD_IO_REQUEST)) };
        #endregion

        public MifareClassicCard()
        {
            M4kWritableBlocks = M4kGetWritableBlocks();
            M2kWritableBlocks = M2kGetWritableBlocks();
            SCardEstablishContextReturn = SCardEstablishContext(SCARD_SCOPE_USER, IntPtr.Zero, IntPtr.Zero, out _hContext);
            SCardConnectReturn = SCardConnect(_hContext, GetReaderName(), SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, out _hCard, out _activeProtocol);
            _readerName = GetReaderName();
        }

        #region Private Methods
        private string SendAPDU(IntPtr hCard, byte[] command)
        {
            byte[] recvBuffer = new byte[258];
            int recvLength = recvBuffer.Length;
            int result = SCardTransmit(hCard, ref SCARD_PCI_T1, command, command.Length, IntPtr.Zero, recvBuffer, ref recvLength);

            if (result == 0)
            {
                return BitConverter.ToString(recvBuffer, 0, recvLength);
            }
            else
            {
                return result.ToString();
            }
        }
        #endregion

        #region Public Methods
        public string GetReaderName()
        {
            uint readersLength = 1024;
            byte[] readersList = new byte[readersLength];
            SCardListReaders(_hContext, null, readersList, ref readersLength);
            string readerName = Encoding.ASCII.GetString(readersList, 0, (int)readersLength - 1).Split('\0')[0];
            return readerName;
        }
        public bool IsReaderReady()
        {
            return _readerName != string.Empty;
        }
        public string GetCardUID()
        {
            if (IsReaderReady())
            {
                string ret = SendAPDU(_hCard, _readCardUID) ?? string.Empty;
                return ret;
            }
            else { return string.Empty; }
        }
        public void CardDisconnect()
        {
            SCardDisconnect(_hCard, (int)SCARD_LEAVE_CARD);
        }
        #endregion

        #region Classic2k
        public bool M2kIsBlockWritable(byte blockNumber)
        {
            //UID Block
            if (blockNumber == 0)
                return false;

            // Sector 0–31: 4 block / sector
            return (blockNumber + 1) % 4 != 0;
        }

        public List<byte> M2kGetWritableBlocks()
        {
            List<byte> writableBlocks = new List<byte>();
            for (int i = 0; i < 129; i++)
            {
                if (M2kIsBlockWritable((byte)i)) writableBlocks.Add((byte)i);
            }
            return writableBlocks;
        }
        #endregion

        #region Classic4k
        public bool M4kIsBlockWritable(byte blockNumber)
        {
            //UID Block
            if (blockNumber == 0)
                return false;

            // Sector 0–31: 4 block / sector
            if (blockNumber < 128)
                return (blockNumber + 1) % 4 != 0;

            // Sector 32–39: 16 block / sector
            return (blockNumber + 1 - 128) % 16 != 0;
        }
        public List<byte> M4kGetWritableBlocks()
        {
            List<byte> writableBlocks = new List<byte>();
            for (int i = 0; i < 256; i++)
            {
                if (M4kIsBlockWritable((byte)i)) writableBlocks.Add((byte)i);
            }
            return writableBlocks;
        }

        #region Classick4 Read All Block
        private bool AuthenticateBlock(IntPtr hCard, uint protocol, byte block, byte keyType, byte keyNumber, byte[] key)
        {
            // Load ket to reader
            byte[] loadKey = new byte[11];
            loadKey[0] = 0xFF;
            loadKey[1] = 0x82; // Load key
            loadKey[2] = 0x00;
            loadKey[3] = keyNumber;
            loadKey[4] = 0x06;
            Array.Copy(key, 0, loadKey, 5, 6);

            SCARD_IO_REQUEST ioRequest = new SCARD_IO_REQUEST { dwProtocol = protocol, cbPciLength = 8 };
            byte[] recv = new byte[256];
            int recvLen = recv.Length;
            int result = SCardTransmit(hCard, ref ioRequest, loadKey, loadKey.Length, IntPtr.Zero, recv, ref recvLen);
            if (result != 0 || recv[recvLen - 2] != 0x90 || recv[recvLen - 1] != 0x00)
                return false;

            // Authentication
            byte[] auth = new byte[]
            {
                0xFF, 0x86, 0x00, 0x00, 0x05,
                0x01, 0x00, block, keyType, keyNumber
            };

            recvLen = recv.Length;
            result = SCardTransmit(hCard, ref ioRequest, auth, auth.Length, IntPtr.Zero, recv, ref recvLen);
            return result == 0 && recv[recvLen - 2] == 0x90 && recv[recvLen - 1] == 0x00;
        }
        private string M4kReadBlock(IntPtr hCard, uint protocol, byte block)
        {
            byte[] read = new byte[] { 0xFF, 0xB0, 0x00, block, 0x10 };
            byte[] recv = new byte[258];
            int recvLen = recv.Length;

            SCARD_IO_REQUEST ioRequest = new SCARD_IO_REQUEST { dwProtocol = protocol, cbPciLength = 8 };
            int result = SCardTransmit(hCard, ref ioRequest, read, read.Length, IntPtr.Zero, recv, ref recvLen);
            byte[] data = new byte[recvLen - 2];
            Array.Copy(recv, data, data.Length);
            return Encoding.UTF8.GetString(data);
        }
        public string M4kReadAllBlocksToString(string readerName, byte[]? authKey = null)
        {
            if (authKey == null) authKey = _defaultKey;
            StringBuilder content = new StringBuilder();

            for (int sector = 0; sector < 40; sector++)
            {
                int blocksInSector = (sector < 32) ? 4 : 16;
                int firstBlock = GetFirstBlockOfSector(sector);

                // Authenticate first block only (will be enough for each sector)
                AuthenticateBlock(_hCard, (uint)_activeProtocol, (byte)firstBlock, 0x60, 0x00, authKey);  

                for (byte i = 0; i < blocksInSector; i++)
                {
                    byte blockNumber = (byte)(firstBlock + i);
                    if (M4kIsBlockWritable(blockNumber))
                    {
                        content.Append(M4kReadBlock(_hCard, (uint)_activeProtocol, blockNumber));
                    }
                }
            }            
            return content.ToString();
        }
        private int GetFirstBlockOfSector(int sector)
        {
            if (sector < 32)
                return sector * 4;
            return 128 + (sector - 32) * 16;
        }

        #endregion

        #region Classic4k Write All Block
        private void M4kWriteBlock(string readerName, byte[] blockData, byte blockNumber, byte[]? authKey = null)
        {
            if (authKey == null) authKey = _defaultKey;

            byte[] loadKey = new byte[] {
                    0xFF, 0x82, 0x00, 0x00, 0x06,
                    authKey[0], authKey[1], authKey[2], authKey[3], authKey[4], authKey[5]
                };
            SendAPDU(_hCard, loadKey);

            byte[] authBlock = new byte[] {
                    0xFF, 0x86, 0x00, 0x00, 0x05,
                    0x01, 0x00, blockNumber, 0x60, 0x00
                };
            SendAPDU(_hCard, authBlock);

            SCARD_IO_REQUEST ioRequest = new SCARD_IO_REQUEST()
            {
                dwProtocol = (uint)_activeProtocol,
                cbPciLength = (uint)Marshal.SizeOf(typeof(SCARD_IO_REQUEST))
            };
            // Write to block
            byte[] writeBlock = new byte[21];
            writeBlock[0] = 0xFF;
            writeBlock[1] = 0xD6;
            writeBlock[2] = 0x00;
            writeBlock[3] = blockNumber; // blokk cím
            writeBlock[4] = 0x10; // 16 byte

            //Encoding.ASCII.GetBytes(blockData).CopyTo(writeBlock, 5);
            Array.Copy(blockData, 0, writeBlock, 5, Math.Min(16, blockData.Length));

            SendAPDU(_hCard, writeBlock); 
        }

        public void M4kWriteAllBlocksToString(string reader, string data, bool clearCard = false)
        {
            List<byte[]> chunkedData = new List<byte[]>();
            byte[] dataInBytes = Encoding.UTF8.GetBytes(data);
            //Split data to 16 bytes
            int count = 0;
            for (int i = 0 ; i < dataInBytes.Length; i += 16)
            {
                if (count == M4kWritableBlocks.Count) { break; }
                int blockSize = Math.Min(16, dataInBytes.Length - i);
                byte[] chunk = new byte[blockSize];
                Array.Copy(dataInBytes, i, chunk, 0, blockSize);
                chunkedData.Add(chunk);
                count++;
            }
            if (clearCard)
            {
                //Clear card before writing data
                for (int c = 0; c < M4kWritableBlocks.Count; c++)
                {
                    M4kWriteBlock(reader, _zero, M4kWritableBlocks[c]);
                }
            }
            //Write actual data
            for (int i = 0; i < chunkedData.Count; i++) 
            {
                M4kWriteBlock(reader, chunkedData[i], M4kWritableBlocks[i]);
            }
        }
        #endregion

        #endregion
    }
}
