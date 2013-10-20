using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using System.Management;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using pGina.Shared.Types;
using log4net;

namespace pGina.Plugin.Mellon
{
    public class PluginImpl : 
            pGina.Shared.Interfaces.IPluginAuthentication,
            pGina.Shared.Interfaces.IPluginConfiguration
    {

        class DriveParams
        {
            public string PhysicalID { get; set; }
            public string PhysicalSignature { get; set; }
            public string VolumeName { get; set; }
            public string VolumeSerial { get; set; }
            public string Serial { get; set; }
        }

        class NewCredentials
        {
            public string domain;
            public string username;
            public string password;
            public Boolean hasGot;
        }

        private ILog m_logger;

        private static readonly Guid m_uuid = new Guid("4BFADB37-D82D-4C80-BF60-7C0E851D4904");

        private static readonly string defaultPubKeyName = "pub.pem";
        private static readonly string defaultPrivKeyName = "priv.pem";
        private static readonly int defaultServerPort = 2200;
        private static readonly string defaultServerHostName = "127.0.0.1";
        private static readonly int bufferSize = 4096;

        public PluginImpl()
        {
            m_logger = LogManager.GetLogger("pGina.Plugin.Mellon");
        }

        public string Name
        {
            get { return "Mellon system pGina plugin"; }
        }

        public string Description
        {
            get { return "Authenticates user with USB-stick and server-check"; }
        }

        public Guid Uuid
        {
            get { return m_uuid; }
        }

        public string Version
        {
            get
            {
                return System.Reflection.Assembly.GetExecutingAssembly().GetName().Version.ToString();
            }
        }

        public void Starting() { }

        public void Stopping() { }

        public BooleanResult AuthenticateUser(SessionProperties properties)
        {
            UserInformation userInfo = properties.GetTrackedSingle<UserInformation>();

            NewCredentials newCred = RequestNewCredentials();

            if (newCred.hasGot)
            {
                userInfo.Domain = newCred.domain;
                userInfo.Username = newCred.username;
                userInfo.Password = newCred.password;

                m_logger.InfoFormat("Successfully authenticated {0}", userInfo.Username);

                return new BooleanResult() { Success = false, Message = "Successfully got new credentials, pass to SAM" };
            }
            else
            {
                m_logger.ErrorFormat("Error in getting new credentials, falling back to SAM");
                m_logger.InfoFormat("Not authenticated {0} (fallback)", userInfo.Username);

                return new BooleanResult() { Success = false, Message = "Error in getting new credentials" };
            }
        } //end AuthenticateUser


        private static dynamic m_settings;
        internal static dynamic Settings { get { return m_settings; } }

        static PluginImpl()
        {
            m_settings = new pGina.Shared.Settings.pGinaDynamicSettings(m_uuid);

            m_settings.SetDefault("PubKeyName", defaultPubKeyName);
            m_settings.SetDefault("PrivKeyName", defaultPrivKeyName);
            m_settings.SetDefault("ServerPort", defaultServerPort);
            m_settings.SetDefault("ServerHostName", defaultServerHostName);
        }

        public void Configure()
        {
            Configuration myDialog = new Configuration();
            myDialog.ShowDialog();

        }



        private List<DriveParams> GetDeviceArray(string FromWIN32Class, string ClassItemAdd)
        {
            List<DriveParams> result = new List<DriveParams>();
            ManagementObjectSearcher searcher =
                     new ManagementObjectSearcher("SELECT * FROM " + FromWIN32Class + " WHERE InterfaceType='USB'");
            try
            {
                foreach (ManagementObject obj in searcher.Get())
                {
                    DriveParams currentDriveParams = new DriveParams();
                    ManagementObject theSerialNumberObjectQuery = new ManagementObject("Win32_PhysicalMedia.Tag='" + obj["DeviceID"] + "'");
                    foreach (ManagementObject moDiskDrive in theSerialNumberObjectQuery.GetRelated("Win32_DiskDrive"))
                    {
                        foreach (ManagementObject moDiskPartition in moDiskDrive.GetRelated("Win32_DiskPartition"))
                        {
                            foreach (ManagementObject moLogicalDisk in moDiskPartition.GetRelated("Win32_LogicalDisk"))
                            {
                                currentDriveParams.VolumeName = moLogicalDisk["DeviceID"].ToString();
                                currentDriveParams.VolumeSerial = moLogicalDisk["VolumeSerialNumber"].ToString();
                                break;
                            }
                        }
                        currentDriveParams.PhysicalID = moDiskDrive["DeviceID"].ToString();
                        currentDriveParams.PhysicalSignature = moDiskDrive["Signature"].ToString();
                    }
                    currentDriveParams.Serial = theSerialNumberObjectQuery["SerialNumber"].ToString();
                    result.Add(currentDriveParams);
                }
            }
            catch (Exception ex)
            {
                m_logger.ErrorFormat(ex.Message);
            }
            return result;

        } //end GetDeviceArray


        private Boolean CheckOnDeviceList(List<DriveParams> ListOfDevices, out List<DriveParams> SuitableDevices)
        {
            Boolean result = false;
            Boolean readable = false;
            SuitableDevices = new List<DriveParams>();

            foreach (DriveParams Device in ListOfDevices)
            {
                if (Device.VolumeName != null)
                {
                    string PubKeyPath = Path.Combine(Device.VolumeName, Settings.PubKeyName.ToString());
                    string PrivKeyPath = Path.Combine(Device.VolumeName, Settings.PrivKeyName.ToString());

                    if (System.IO.File.Exists(PubKeyPath) && System.IO.File.Exists(PrivKeyPath))
                    {
                        try
                        {  
                            string PubKey = File.ReadAllText(PubKeyPath);
                            string PrivKey = File.ReadAllText(PrivKeyPath);
                            readable = true;
                        }
                        catch (Exception ex)                    
                        {
                            m_logger.WarnFormat("Keys was found on drive {0}, but files can't be opened: {1}", Device, ex.Message);        
                        }

                        if (readable)
                        {
                            result = true;
                            SuitableDevices.Add(Device);
                            readable = false;
                        }
                    }
                }
            }
            return result;
        } //end CheckOnDeviceList


        private byte[] EncryptRSAPKCSPad(string keyPath, string plainText)
        {
            String fidPublic = Path.Combine(keyPath, Settings.PubKeyName.ToString());
            StreamReader sr = new StreamReader(fidPublic);

            PemReader pr = new PemReader(sr);
            RsaKeyParameters KeyPair = (RsaKeyParameters)pr.ReadObject();
            RSAParameters rsapar = new RSAParameters();
            sr.Close();

            rsapar.Modulus = KeyPair.Modulus.ToByteArrayUnsigned();
            rsapar.Exponent = KeyPair.Exponent.ToByteArrayUnsigned();
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsapar);

            return rsa.Encrypt(Encoding.Default.GetBytes(plainText), false);
        } //end EncryptRSAPKCSPad


        private string DecryptRSAPKCSPad(string keyPath, byte[] cypherText)
        {
            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            AsymmetricCipherKeyPair keyPairFromPem;

            String fidPrivate = Path.Combine(keyPath, Settings.PrivKeyName.ToString());

            try
            {
                using (var reader = File.OpenText(fidPrivate)) // file containing RSA PKCS1 private key
                    keyPairFromPem = (AsymmetricCipherKeyPair)new PemReader(reader).ReadObject();

                var decryptEngine = new Pkcs1Encoding(new RsaEngine());
                decryptEngine.Init(false, keyPairFromPem.Private);
                return Encoding.UTF8.GetString(decryptEngine.ProcessBlock(cypherText, 0, cypherText.Length));
            }
            catch (Exception ex)
            {
                m_logger.ErrorFormat("Decryption failed: {0}", ex.Message);
                return "";
            }

        } //end DecryptRSAPKCSPad


        private byte[] MakeServerRequest(byte[] Request)
        {
            TcpClient Client = new TcpClient();
            byte[] reply = null;

            m_logger.DebugFormat("Server Hostname: {0}", Settings.ServerHostName.ToString());
            m_logger.DebugFormat("Connecting to server...");

            try
            {
                Client.Connect(Settings.ServerHostName.ToString(), Convert.ToInt32(Settings.ServerPort.ToString()));
            }
            catch (Exception ex)
            {
                m_logger.ErrorFormat("Can't connect to server: {0}", ex.Message);
                return null;
            }

            Socket Sock = Client.Client;
            byte[] remdata = new byte[bufferSize];

            try
            {
                Sock.Send(Encoding.UTF8.GetBytes(System.Environment.MachineName));
                m_logger.DebugFormat("Hostname has been sent unencrypted: '{0}'", System.Environment.MachineName);
                Sock.Receive(remdata);

                if ("ok,1" == Encoding.UTF8.GetString(remdata, 0, 4))
                {
                    Sock.Send(Request);
                    Sock.Receive(remdata);
                    m_logger.DebugFormat("Got answer: " + Encoding.UTF8.GetString(remdata, 0, 4));
                    if ("ok,2" == Encoding.UTF8.GetString(remdata, 0, 4))
                    {
                        byte[] tempReply = new byte[bufferSize];
                        int receivedLen = Sock.Receive(tempReply);
                        reply = new byte[receivedLen];
                        Array.Copy(tempReply, reply, receivedLen);
                    }
                    else
                    {
                        m_logger.ErrorFormat("Unexpected reply on encrypted request: " + Encoding.UTF8.GetString(remdata));
                    }
                }
                else
                {
                    m_logger.ErrorFormat("Unexpected reply on sending hostname: " + Encoding.UTF8.GetString(remdata));
                }

            }
            catch (Exception ex)
            {
                m_logger.ErrorFormat("Can't send or recieve message from server: {0}", ex.Message);
            }

            m_logger.DebugFormat("Connection closed");
            Sock.Close();
            Client.Close();
            return reply;
        } //end MakeServerRequest


        private NewCredentials RequestNewCredentials()
        {
            NewCredentials credentials = new NewCredentials { hasGot = false };

            m_logger.DebugFormat("-------------   ALL FOUND USB DRIVES  --------------");

            List<DriveParams> DeviceArray = GetDeviceArray("Win32_DiskDrive", "DeviceID");
            foreach (DriveParams dp in DeviceArray)
            {
                m_logger.DebugFormat(" Physical drive {0}", dp.PhysicalID);
                m_logger.DebugFormat("\t Physical signature: {0}", dp.PhysicalSignature);
                m_logger.DebugFormat("\t Volume name: {0}", dp.VolumeName);
                m_logger.DebugFormat("\t Volume serial number: {0}", dp.VolumeSerial);
                m_logger.DebugFormat("\t Media serial number: {0}", dp.Serial);
            }

            List<DriveParams> SuitDev;

            Boolean result = CheckOnDeviceList(DeviceArray, out SuitDev);
            m_logger.DebugFormat("\n----------------------------------------------");
            m_logger.DebugFormat("Found valid devices: {0}", result);
            m_logger.DebugFormat("\nTested devices: ");

            foreach (DriveParams Device in DeviceArray)
            {
                m_logger.DebugFormat(" {0} ", Device.VolumeName);
            }

            if (result)
            {
                m_logger.DebugFormat("\tKey pairs found on:");
                foreach (DriveParams Device in SuitDev)
                {
                    m_logger.DebugFormat(" Physical drive {0}", Device.PhysicalID);
                    m_logger.DebugFormat("\t Physical signature: {0}", Device.PhysicalSignature);
                    m_logger.DebugFormat("\t Volume name: {0}", Device.VolumeName);
                    m_logger.DebugFormat("\t Volume serial number: {0}", Device.VolumeSerial);
                    m_logger.DebugFormat("\t Media serial number: {0}\n", Device.Serial);

                    m_logger.DebugFormat(" Trying to use current device");

                    string plainTextRequest = Device.PhysicalSignature + ',' + Device.VolumeSerial + ',' + Device.Serial;
                    m_logger.DebugFormat("Unencrypted request to server: {0}\n", plainTextRequest);
                    byte[] cypherTextRequest = EncryptRSAPKCSPad(Device.VolumeName, plainTextRequest);

                    string base64CypherTextRequest = Convert.ToBase64String(cypherTextRequest);
                    m_logger.DebugFormat("Encrypted request to server in base64: {0}\n", base64CypherTextRequest);

                    byte[] bytesToSend = Encoding.UTF8.GetBytes(base64CypherTextRequest);

                    byte[] bytesReceived = MakeServerRequest(bytesToSend);

                    if (null != bytesReceived)
                    {
                        string cypherTextReply = Encoding.UTF8.GetString(bytesReceived);

                        m_logger.DebugFormat("Server's reply:");
                        m_logger.DebugFormat(cypherTextReply);

                        string plainTextReply = DecryptRSAPKCSPad(Device.VolumeName, Convert.FromBase64String(cypherTextReply));

                        if (plainTextReply.Length == 0)
                        {
                            m_logger.ErrorFormat("Unable to decrypt message from server, communication error");
                        }
                        else
                        {
                            m_logger.DebugFormat("Decrypted server's reply: ");
                            m_logger.DebugFormat(plainTextReply);

                            string[] creds = plainTextReply.Split(new Char[] { ',' });

                            if (3 == creds.Length)
                            {
                                m_logger.DebugFormat("Decrypted server's reply looks reasonable, try to use as credentials");
                                credentials = new NewCredentials { domain = creds[0], username = creds[1], password = creds[2], hasGot = true };
                            }
                        }
                    }
                }

            }

            m_logger.DebugFormat("----------------------------------------------");

            return credentials;
        } //end RequestNewCredentials

    }
}
