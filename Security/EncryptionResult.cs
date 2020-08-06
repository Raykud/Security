namespace Security
{
    public class EncryptionResult
    {
        public string Payload { get; private set; }
        public string IV { get; private set; }
        public string Key { get; private set; }

        public EncryptionResult(string payload, string iv, string key)
        {
            Payload = payload;
            IV = iv;
            Key = key;
        }
    }
}