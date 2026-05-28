// DigestMethod.cs
//
// XAdES Starter Kit for Microsoft .NET 3.5 (and above)
// 2010 Microsoft France
// Published under the CECILL-B Free Software license agreement.
// (http://www.cecill.info/licences/Licence_CeCILL-B_V1-en.txt)
//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
// WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
// THE ENTIRE RISK OF USE OR RESULTS IN CONNECTION WITH THE USE OF THIS CODE
// AND INFORMATION REMAINS WITH THE USER.
//

using System;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    /// <summary>
    /// DigestMethod indicates the digest algorithm
    /// </summary>
    public class DigestMethod
    {
        #region Private variables
        private String algorithm;
        #endregion

        #region Public properties
        /// <summary>
        /// Contains the digest algorithm
        /// </summary>
        public String Algorithm
        {
            get
            {
                return this.algorithm;
            }
            set
            {
                this.algorithm = value;
            }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Default constructor
        /// </summary>
        public DigestMethod()
        {
        }
        #endregion

        #region Public methods
        /// <summary>
        /// Check to see if something has changed in this instance and needs to be serialized
        /// </summary>
        /// <returns>Flag indicating if a member needs serialization</returns>
        public Boolean HasChanged()
        {
            Boolean retVal = false;

            if (!String.IsNullOrEmpty(this.algorithm))
            {
                retVal = true;
            }

            return retVal;
        }

        /// <summary>
        /// Load state from an XML element
        /// </summary>
        /// <param name="xmlElement">XML element containing new state</param>
        public void LoadXml(XmlElement xmlElement)
        {
            if (xmlElement == null)
            {
                throw new ArgumentNullException("xmlElement");
            }

            this.algorithm = xmlElement.GetAttribute("Algorithm");
        }

        /// <summary>
        /// Returns the XML representation of the this object
        /// </summary>
        /// <returns>XML element containing the state of this object</returns>
        public XmlElement GetXml()
        {
            XmlDocument creationXmlDocument = new XmlDocument
            {
                PreserveWhitespace = true
            };
            return this.GetXml(creationXmlDocument);
        }

        internal XmlElement GetXml(XmlDocument creationXmlDocument)
        {
            // Create the actual element
            XmlElement digestMethodElement = creationXmlDocument.CreateElement(SignedXml.DefaultXmlDsigNamespacePrefix, "DigestMethod", SignedXml.XmlDsigNamespaceUrl);

            if (!String.IsNullOrEmpty(this.Algorithm))
            {
                digestMethodElement.SetAttribute("Algorithm", this.Algorithm);
            }

            return digestMethodElement;
        }
        #endregion
    }
}