using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SIP2
{
    public class ConnectionFailedException : Exception
    {
        public ConnectionFailedException() { }
        public ConnectionFailedException(string message) : base(message) { }
    }

    public class HandshakeFailedException : Exception
    {
        public HandshakeFailedException() { }
        public HandshakeFailedException(string message) : base(message) { }
    }

    public class NotConnectedException : Exception
    {
        public NotConnectedException() { }
        public NotConnectedException(string message) : base(message) { }
    }

    public class InvalidParameterException : Exception
    {
        public InvalidParameterException() { }
        public InvalidParameterException(string message) : base(message) { }
    }

    public class NoChecksumException : Exception
    {
        public NoChecksumException() { }
        public NoChecksumException(string message) : base(message) { }
    }
}
