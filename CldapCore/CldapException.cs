namespace Petrsnd.CldapCore
{
    using System;
    using System.Runtime.Serialization;

    public class CldapException : Exception
    {
        public CldapException()
            : base("Unknown CldapException")
        {
        }

        public CldapException(string message)
            : base(message)
        {
        }

        public CldapException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        protected CldapException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
