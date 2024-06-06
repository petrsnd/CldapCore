// <copyright file="CldapException.cs" company="petrsnd">
// (c) 2024 Daniel F. Peterson (petrsnd@gmail.com)
// </copyright>
namespace Petrsnd.CldapCore
{
    using System;
    using System.Runtime.Serialization;

    /// <summary>
    /// An error occurred during CLDAP communication or response parsing.
    /// </summary>
    public class CldapException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CldapException"/> class. Used for unknown errors.
        /// </summary>
        public CldapException()
            : base("Unknown CldapException")
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CldapException"/> class. Used for specific errors.
        /// </summary>
        /// <param name="message">Error message describing the specific problem.</param>
        public CldapException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CldapException"/> class. Used for specific errors
        /// caused by another exception.
        /// </summary>
        /// <param name="message">Error message describing the specific problem.</param>
        /// <param name="innerException">Inner exception causing the problem.</param>
        public CldapException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CldapException"/> class. Used for serialization.
        /// </summary>
        /// <param name="info">Serialization info.</param>
        /// <param name="context">Serialization context.</param>
        protected CldapException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
