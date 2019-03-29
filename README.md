# C# Entity Encryption Core

Generic AES 256 bit encryption utility for the .NET platform.
This library was designed to be fool proof and easy to use with portability and flexibility in mind. Note that this class cannot be used for encryption folding (encrypting an encrypted input).

The current implementation uses a 256 bit (32 byte string) encryption key with a 128 bit (16 byte string) initialization vector (IV/hash). Note that this algorithm is symmetric, but at such a high resolution and block size, the algorithm becomes as strong if not stronger than a  2048 bit RSA encryption.

Methods:
```csharp
// Getting started
static void SetPrivateKey(ref string privateKey)

// Example 1
static string Encrypt(string plainText)
static string Decrypt(string cipherText)

// Example 2 & 3
static void EncryptEntity<T>(this T entity, params Expression<Func<T, string>>[] properties)
static void DecryptEntity<T>(this T entity, params Expression<Func<T, string>>[] properties)
```

## Getting Started

Simply drop this class into your current project and reference the correct namespace:
```csharp
using EncryptionCore;
```
This library uses the singleton design pattern. In order for the library to work correctly, the instance must be seeded with an appropriate private key. Note that this private key will not and **should not** be held onto in managed memory.

In order to seed the instance, simply call the following method:
```csharp
    var privateKey = "MY_PRIVATE_KEY_STRING";
    EntityEncryption.SetPrivateKey(ref privateKey);
```
The private key is passed to the instance by reference in order to cleanup resources. Note that this class does not clean up spurious copies of the initial string. The key retrieval and implementation is up to the developers using this class.
The private key should never be stored locally or in plain text, in a perfect scenario, the private key should be obtained through an authentification pipeline offsite.
For more information about storing secrets, see this link:
https://docs.microsoft.com/en-us/azure/key-vault/

### Examples

* Note that all examples can be used with their Decryption counterparts.

**Encrypting a basic string**:
```csharp
    var myString = "Hello World!";
    var encryptedString = EntityEncryption.Encrypt(myString);
```
```
output: !=!enc!=!kk/eKSEjmA1ttIClmImn1A==odM1Dpe0ky+TeExOEaX0Eg==
```

**Encrypting an entire object** (Note that only 'string' type properties will be encrypted):
```csharp
    class MyClass
    {
        public string Name { get; set; }
        public string Surname { get; set; }
    }
    ...
    var myObject = new MyClass()
    {
        Name = "Hello",
        Surname = "World"
    };
    ...
    myObject.EncryptEntity();
```
```
output: 
name:    !=!enc!=!57QiHtSHjZHmHTj7ADsDfg==0GVYmacs9NCVqqSgX7LPJA==
surname: !=!enc!=!HlOvhhfb9nhf3pTWfoenOw==pJ4zPYmOT4eqYPos5EA0XQ==
```

**Encrypting certain object properties**:
```csharp
    class MyClass
    {
        public string Name { get; set; }
        public string Surname { get; set; }
    }
    ...
    var myObject = new MyClass()
    {
        Name = "Hello",
        Surname = "World"
    };
    ...
    myObject.EncryptEntity(
        x => x.Name,
        x => x.Surname
    );
```
```
output: 
name:    !=!enc!=!57QiHtSHjZHmHTj7ADsDfg==0GVYmacs9NCVqqSgX7LPJA==
surname: !=!enc!=!HlOvhhfb9nhf3pTWfoenOw==pJ4zPYmOT4eqYPos5EA0XQ==
```

## Authors

* **Jessy Walker** - *Initial work*