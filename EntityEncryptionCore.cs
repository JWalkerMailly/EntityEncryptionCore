using System;
using System.IO;
using System.Net;
using System.Text;
using System.Security;
using System.Reflection;
using System.Linq.Expressions;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace EncryptionCore
{
	public static class EntityEncryption
	{
		/// <summary>
		/// Entity encryption core instance used for sealed private key referencing.
		/// </summary>
		private static readonly Lazy<EntityEncryptionCore> instance = new Lazy<EntityEncryptionCore>(() => new EntityEncryptionCore());
		private static EntityEncryptionCore Instance {
			get {
				return instance.Value;
			}
		}

		/// <summary>
		/// Encryption prefix used for string evaluation when encrypting and decrypting.
		/// </summary>
		private const string ENCRYPTION_PREFIX = "!=!enc!=!";

		/// <summary>
		/// Seed function for encryption private key. Private keys should not be stored locally or in plain text.
		/// Private keys are meant to be delivered though an authentification pipeline. For more information about
		/// storing secrets, see this link:
		/// https://azure.microsoft.com/en-ca/services/key-vault/
		/// </summary>
		/// <param name="privateKey">Private key plain text to be stored securely in encryption instance.</param>
		public static void SetPrivateKey(ref string privateKey)
		{
			if (privateKey.Length != 32) return;
            if (Instance.PrivateKey != null) Instance.PrivateKey.Dispose();

			// Construct private key in secure manner.
			var secureKey = new SecureString();
			foreach (char character in privateKey)
				secureKey.AppendChar(character);

			// Dispose of previous memory managed key.
			privateKey = null;

			// Seed entity encryption core.
			Instance.PrivateKey = secureKey;
		}

        /// <summary>
        /// Encrypts the given plain text without exposing the core instance.
        /// </summary>
        /// <param name="plainText">Input text.</param>
        /// <returns>Cipher text.</returns>
        public static string Encrypt(string plainText)
        {
            return Instance.Encrypt(plainText);
        }

        /// <summary>
        /// Decrypts the given cipher without exposing the core instance.
        /// </summary>
        /// <param name="cipherText">Encrypted text.</param>
        /// <returns>Plain text.</returns>
        public static string Decrypt(string cipherText)
        {
            return Instance.Decrypt(cipherText);
        }

		/// <summary>
		/// Encrypts every string properties of an object. For control over which fields are encrypted, pass multiple
		/// lambda expressions refering to said fields.
		/// </summary>
		/// <typeparam name="T">Entity type.</typeparam>
		/// <param name="entity">Entity reference.</param>
		/// <param name="properties">Lambda expressions used for field lookup during encryption.</param>
		public static void EncryptEntity<T>(this T entity, params Expression<Func<T, string>>[] properties) where T : new()
		{
			// Delegate
			if (entity == null) return;
			entity.EncryptDecryptEntity(Instance.Encrypt, properties);
		}

		/// <summary>
		/// Decrypts every string properties of an object. For control over which fields are decrypted, pass multiple
		/// lambda expressions refering to said fields.
		/// </summary>
		/// <typeparam name="T">Entity type.</typeparam>
		/// <param name="entity">Entity reference.</param>
		/// <param name="properties">Lambda expressions used for field lookup during decryption.</param>
		public static void DecryptEntity<T>(this T entity, params Expression<Func<T, string>>[] properties) where T : new()
		{
			// Delegate
			if (entity == null) return;
			entity.EncryptDecryptEntity(Instance.Decrypt, properties);
		}

		/// <summary>
		/// Passthrough method used for encrypting or decrypting an object.
		/// </summary>
		/// <typeparam name="T">Entity type.</typeparam>
		/// <param name="entity">Entity reference.</param>
		/// <param name="process">Delegate callback.</param>
		/// <param name="properties">lambda expressions refering to entity fields.</param>
		private static void EncryptDecryptEntity<T>(this T entity, EncryptDecryptDelegate process, params Expression<Func<T, string>>[] properties) 
			where T : new()
		{
			List<string> propertyNames = new List<string>();

			if (properties.Length == 0)
			{
				// If no properties were passed to the function, get every property for the given entity.
				var entityProperties = entity.GetType().GetProperties();
				foreach (var property in entityProperties)
				{
					if (property.MemberType != MemberTypes.Property) continue;
					propertyNames.Add(property.Name);
				}
			}
			else
			{
				// Prepare every property names from the given list of lambda expressions.
				foreach (var expression in properties)
				{
					var property = expression.Body as MemberExpression;
					if (property == null) continue;
					propertyNames.Add(property.Member.Name);
				}
			}

			// Begin encrypting/decrypting every properties for the given object reference.
			foreach (var property in propertyNames)
			{
				if (string.IsNullOrEmpty(property)) continue;

				// Make sure the property is not write only.
				var entityProperty = entity.GetType().GetProperty(property);
				if (!entityProperty.CanRead) continue;

				// Make sure the property is not read only.
				var plainText = entityProperty.GetValue(entity) as string;
				if (!entityProperty.CanWrite || string.IsNullOrEmpty(plainText)) continue;

				// Attempt to set encrypted value back onto entity.
				try { entityProperty.SetValue(entity, process(plainText)); }
				catch { continue; }
			}
		}
		private delegate string EncryptDecryptDelegate(string input);

		private sealed class EntityEncryptionCore
		{
			/// <summary>
			/// AES 256 bit private key.
			/// </summary>
			private SecureString _PrivateKey;
			public SecureString PrivateKey {
				get { return _PrivateKey; }
				set {
					_PrivateKey = value;
					_PrivateKey.MakeReadOnly();
				}
			}

			/// <summary>
			/// Encrypt given plain text using AES 256 bit algorithm.
			/// </summary>
			/// <param name="plainText">Input text.</param>
			/// <returns>Cipher text with prefix and IV.</returns>
			public string Encrypt(string plainText)
			{
				try
				{
					if (_PrivateKey == null || string.IsNullOrEmpty(plainText) ||  plainText.StartsWith(ENCRYPTION_PREFIX)) return plainText;

					byte[] cipherIV;
					byte[] cipherKey = Encoding.ASCII.GetBytes(new NetworkCredential(string.Empty, _PrivateKey).Password);
					var cipherText = EncryptStringToBytesAes(plainText, cipherKey, out cipherIV);

					return ENCRYPTION_PREFIX + Convert.ToBase64String(cipherIV) + Convert.ToBase64String(cipherText);
				}
				catch
				{
					return plainText;
				}
			}

			/// <summary>
			/// Decrypt given cipher using AES 256 bit algorithm.
			/// </summary>
			/// <param name="cipherText">Encrypted input.</param>
			/// <returns>Original text.</returns>
			public string Decrypt(string cipherText)
			{
				try
				{
					if (_PrivateKey == null || string.IsNullOrEmpty(cipherText) || !cipherText.StartsWith(ENCRYPTION_PREFIX)) return cipherText;

					// Split the IV salt and the cipher in order to begin decrypting.
					byte[] cipherIV = Convert.FromBase64String(cipherText.Substring(ENCRYPTION_PREFIX.Length, 24));
					byte[] cipherBytes = Convert.FromBase64String(cipherText.Substring(24 + ENCRYPTION_PREFIX.Length));
					byte[] cipherKey = Encoding.ASCII.GetBytes(new NetworkCredential(string.Empty, _PrivateKey).Password);

					return DecryptStringFromBytesAes(cipherBytes, cipherKey, cipherIV);
				}
				catch
				{
					return cipherText;
				}
			}

			/// <summary>
			/// https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes?view=netframework-4.7.2
			/// </summary>
			private byte[] EncryptStringToBytesAes(string plainText, byte[] Key, out byte[] IV)
			{
				// Check arguments.
				if (plainText == null || plainText.Length <= 0)
					throw new ArgumentNullException("Attempt to encrypt invalid string.");
				if (Key == null || Key.Length <= 0)
					throw new ArgumentNullException("Invalid encryption key.");
				byte[] encrypted;

				// Create an Aes object with the specified key and IV.
				using (Aes aesAlg = Aes.Create())
				{
					// Paranoia
					aesAlg.Mode = CipherMode.CBC;
					aesAlg.KeySize = 256;
					aesAlg.BlockSize = 128;

					aesAlg.Key = Key;
					aesAlg.GenerateIV();
					IV = aesAlg.IV;

					// Create an encryptor to perform the stream transform.
					ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

					// Create the streams used for encryption.
					using (MemoryStream msEncrypt = new MemoryStream())
					{
						using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
						{
							using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
							{
								//Write all data to the stream.
								swEncrypt.Write(plainText);
							}
							encrypted = msEncrypt.ToArray();
						}
					}
				}

				// Return the encrypted bytes from the memory stream.
				return encrypted;

			}

			/// <summary>
			/// https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes?view=netframework-4.7.2
			/// </summary>
			private string DecryptStringFromBytesAes(byte[] cipherText, byte[] Key, byte[] IV)
			{
				// Check arguments.
				if (cipherText == null || cipherText.Length <= 0)
					throw new ArgumentNullException("Attempt to decrypt invalid string.");
				if (Key == null || Key.Length <= 0)
					throw new ArgumentNullException("Invalid decryption key.");
				if (IV == null || IV.Length <= 0)
					throw new ArgumentNullException("Invalid hash vector.");

				// Declare the string used to hold the decrypted text.
				string plaintext = null;

				// Create an Aes object with the specified key and IV.
				using (Aes aesAlg = Aes.Create())
				{
					// Paranoia
					aesAlg.Mode = CipherMode.CBC;
					aesAlg.KeySize = 256;
					aesAlg.BlockSize = 128;

					aesAlg.Key = Key;
					aesAlg.IV = IV;

					// Create a decryptor to perform the stream transform.
					ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

					// Create the streams used for decryption.
					using (MemoryStream msDecrypt = new MemoryStream(cipherText))
					{
						using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
						{
							using (StreamReader srDecrypt = new StreamReader(csDecrypt))
							{
								// Read the decrypted bytes from the decrypting stream and place them in a string.
								plaintext = srDecrypt.ReadToEnd();
							}
						}
					}
				}

				return plaintext;
			}
		}
	}
}