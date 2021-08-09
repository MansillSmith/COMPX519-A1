using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace COMPX519_A1_Decryption
{
    class Program
    {
        const int NUM_ARGUMENTS = 1;

        public Program(string[] args)
        {
            if (args.Length != NUM_ARGUMENTS)
            {
                InvalidArguments();
            }
            else
            {
                string file = args[0];
                try
                {
                    if(new FileInfo(file).Length > 0)
                    {
                        byte[] fileBytes = File.ReadAllBytes(file);
                        string decodedString = Decode(fileBytes);

                        using(StreamWriter sw = new StreamWriter(file))
                        {
                            sw.WriteLine(decodedString);
                        }
                    }
                }
                catch
                {

                }
            }
        }

        private string Decode(byte[] bytes)
        {
            if(bytes == null)
            {
                throw new ArgumentNullException("bytes");
            }
            else
            {
                // Get the key and IV for decryption
                RegistryKey regkey = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Services", true);
                byte[] key = (byte[])regkey.GetValue("KeyValue");
                byte[] iv = (byte[])regkey.GetValue("IVvalue");

                return DecodeWorker(bytes, key, iv);
            }
        }

        private string DecodeWorker(byte[] bytes, byte[] key, byte[] iv)
        {
            string plainttext = "";
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = key;
                rijAlg.IV = iv;
                rijAlg.Mode = CipherMode.CBC;
                rijAlg.Padding = PaddingMode.Zeros;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(bytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plainttext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plainttext;
        }

        private void InvalidArguments()
        {
            Console.WriteLine("Invalid Arguments + \n " +
                "\n" + 
                "Program Arguments: + \n" +
                "String: The path to a file to decrypt");
            Console.ReadLine();
        }
        static void Main(string[] args)
        {
            new Program(args);
        }
    }
}
