using System;

namespace DataProtection2_9.Models
{
    public class DESContent
    {
        public string encryptionString { get; set; }
        public string decryptionString { get; set; }
        public string encryptionKey { get; set; }
        public string decryptionKey { get; set; }

    }
}
