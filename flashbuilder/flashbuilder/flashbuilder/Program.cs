using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;


namespace flashbuilder
{
    class Program
    {
        static void Main(string[] args)
        {
            List<DriveParams> DeviceArray = GetDeviceArray("Win32_DiskDrive", "DeviceID");

            Console.WriteLine("\n\n---------------- Detected USB drives: ----------------");
            foreach (DriveParams dp in DeviceArray)
            {
                Console.WriteLine(" Physical drive {0}", dp.PhysicalID);
                Console.WriteLine("\t Physical signature: {0}", dp.PhysicalSignature);
                Console.WriteLine("\t Volume name: {0}", dp.VolumeName);
                Console.WriteLine("\t Volume serial number: {0}", dp.VolumeSerial);
                Console.WriteLine("\t Media serial number: {0}", dp.Serial);
            }
            Console.WriteLine("\n------------------------------------------------------\n");

            Console.Write(" Input volume name to generate keys from drives above: ");
            string drive = Console.ReadLine();


            Console.WriteLine(" Generating keys...");

            String workDir = Path.GetTempPath();

            String priv = "priv.pem";
            String pub = "pub.pem";
            String fidPrivate = Path.Combine(workDir, priv);
            String fidPublic = Path.Combine(workDir, pub);


            var keys = GenerateKeys(2048);

            var publicKey = keys.Public.ToString();


            var textWriter = new StreamWriter(fidPrivate);
            var pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(keys.Private);
            pemWriter.Writer.Flush();
            textWriter.Close();


            textWriter = new StreamWriter(fidPublic);
            pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(keys.Public);
            pemWriter.Writer.Flush();
            textWriter.Close();

            Console.WriteLine(" Generating keys done");

            if (File.Exists(Path.Combine(drive, priv)) || (File.Exists(Path.Combine(drive, priv))))
            {
                Console.Write(" Key files on drive {0} already exists. Overwrite (y/n) ? ", drive);
                if ("n" == Console.ReadLine())
                    return;
            }


            try
            {
                FileAttributes attribs;

                if (File.Exists(Path.Combine(drive, priv)))
                {
                    attribs = File.GetAttributes(Path.Combine(drive, priv));
                    attribs = attribs & FileAttributes.Hidden & FileAttributes.System & FileAttributes.ReadOnly;
                    File.SetAttributes(Path.Combine(drive, priv), attribs);
                    File.Delete(Path.Combine(drive, priv));
                }

                if (File.Exists(Path.Combine(drive, pub)))
                {
                    attribs = File.GetAttributes(Path.Combine(drive, pub));
                    attribs = attribs & FileAttributes.Hidden & FileAttributes.System & FileAttributes.ReadOnly;
                    File.SetAttributes(Path.Combine(drive, pub), attribs);
                    File.Delete(Path.Combine(drive, pub));
                }


                File.Copy(fidPublic, Path.Combine(drive, pub), true);
                File.Copy(fidPrivate, Path.Combine(drive, priv), true);
                File.Copy(fidPublic, Path.Combine(Environment.CurrentDirectory, pub), true);
                File.Copy(fidPrivate, Path.Combine(Environment.CurrentDirectory, priv), true);


                attribs = File.GetAttributes(Path.Combine(drive, pub));
                attribs = attribs | FileAttributes.Hidden | FileAttributes.System | FileAttributes.ReadOnly;
                File.SetAttributes(Path.Combine(drive, pub), attribs);
                File.SetAttributes(Path.Combine(drive, priv), attribs);

                File.Delete(fidPrivate);
                File.Delete(fidPublic);

                Console.WriteLine(" Keypair was successfully copied on drive {0}.", drive);
                Console.WriteLine(" You can use files {0} and {1} from current directory to register flashdrive in system", priv, pub);

            }
            catch (Exception ex)
            {
                Console.WriteLine(" Error during key's copying: {0}", ex.Message);
            }


            Console.Write("\n\n Press any key to exit.. ");

            Console.ReadKey();
        }

        class DriveParams
        {
            public string PhysicalID { get; set; }
            public string PhysicalSignature { get; set; }
            public string VolumeName { get; set; }
            public string VolumeSerial { get; set; }
            public string Serial { get; set; }
        }


        private static List<DriveParams> GetDeviceArray(string FromWIN32Class, string ClassItemAdd)
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
                Console.WriteLine(ex.Message);
            }
            return result;

        } //end GetDeviceArray

        public static AsymmetricCipherKeyPair GenerateKeys(int keySizeInBits)
        {
            var r = new RsaKeyPairGenerator();
            r.Init(new KeyGenerationParameters(new SecureRandom(), keySizeInBits));
            var keys = r.GenerateKeyPair();
            return keys;
        }

    }
}
