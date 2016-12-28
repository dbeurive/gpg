# Introduction

This package implements a wrapper around the PGP command line tool. 

> Please note that the ambition of this wrapper is not to be "complete".
> This wrapper has been developed in order to automat the GPG processing of a large number of files.
> Therefore, only the basic GPG functionalities have been wrapped (signing, encryption, decryption and signature verification).

# License

This code is published under the following license:
 
[Creative Common Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)](https://creativecommons.org/licenses/by-nc/4.0/legalcode)

See the file [LICENSE.TXT](LICENSE.TXT)

# Synopsis

```php
// Get the fingerprint of a key.

$fgp = Gpg::getPublicKeyFingerPrint('protected key');
$fgp = Gpg::getPrivateKeyFingerPrint('protected key');

// Remove a key from the keyring.

Gpg::removePublicKey($fgp);
Gpg::removePrivateKey($fgp);

// Import a key into the keyring.

Gpg::importPublicKey('open.pub');
Gpg::importPrivateKey('open.prv');

// Check that a key is in the keyring.

Gpg::isPublicKeyPresent($fgp);
Gpg::isPrivateKeyPresent($fgp);

// Sign (encrypt with a private key).

Gpg::signFile('/path/to/document', $fgp, 'my password (if any), or null', '/path/to/encrypted_file');
Gpg::signFile('/path/to/document', $fgp, null, '/path/to/encrypted_file');
Gpg::signString('AZERTY', $fgp, 'my password (if any), or null', '/path/to/encrypted_file');
Gpg::signString('AZERTY', $fgp, null, '/path/to/encrypted_file');

$encryptedString = Gpg::signFile('/path/to/document', $fgp, 'my password (if any), or null', null);
$encryptedString = Gpg::signFile('/path/to/document', $fgp, null, null);
$encryptedString = Gpg::signString('AZERTY', $fgp, 'my password (if any), or null', null);
$encryptedString = Gpg::signString('AZERTY', $fgp, null, null);

// Clear sign

Gpg::clearSignFile('/path/to/document', $fgp, 'my password (if any), or null', '/path/to/signed_document');
Gpg::clearSignFile('/path/to/document', $fgp, null, '/path/to/signed_document');
Gpg::clearSignString('AZERTY', $fgp, 'my password (if any), or null', '/path/to/signed_document');
Gpg::clearSignString('AZERTY', $fgp, null, '/path/to/signed_document');

$signedDocument = Gpg::clearSignFile('/path/to/document', $fgp, 'my password (if any), or null', null);
$signedDocument = Gpg::clearSignFile('/path/to/document', $fgp, null, null);
$signedDocument = Gpg::clearSignString('AZERTY', $fgp, 'my password (if any), or null', null);
$signedDocument = Gpg::clearSignString('AZERTY', $fgp, null, null);

// Detach sign

Gpg::detachSignFile('/path/to/document', $fgp, 'my password (if any), or null', '/path/to/signature');
Gpg::detachSignFile('/path/to/document', $fgp, null, '/path/to/signature');
Gpg::detachSignString('AZERTY', $fgp, 'my password (if any), or null', '/path/to/signature');
Gpg::detachSignString('AZERTY', $fgp, null, '/path/to/signature');

$signature = Gpg::detachSignFile('/path/to/document', $fgp, 'my password (if any), or null', null);
$signature = Gpg::detachSignFile('/path/to/document', $fgp, null, null);
$signature = Gpg::detachSignString('AZERTY', $fgp, 'my password (if any), or null', null);
$signature = Gpg::detachSignString('AZERTY', $fgp, null, null);

// Verify a "clear" signature (that is: a file that contains the document and it signature)

$warning = null;
$status = Gpg::verifyClearSignedFile('/path/to/signed_document', $warning); // true: valid signature, false: invalid signature.
$status = Gpg::verifyClearSignedString($signature, $warning); // true: valid signature, false: invalid signature.

// Verify a "detached" signature (against a document)

$warning = null;
$status = Gpg::verifyDetachedSignedFile('/path/to/signature', '/path/to/document', $warning);
$status = Gpg::verifyDetachedSignedString($signature, '/path/to/document', $warning);

// Encrypt with a public key

Gpg::encryptAsymmetricFile('/path/to/document', $fgp, '/path/to/encrypted_file');
Gpg::encryptAsymmetricString('AZERTY', $fgp, '/path/to/encrypted_file');

$encryptedString = Gpg::encryptAsymmetricFile('AZERTY', $fgp, null);
$encryptedString = Gpg::encryptAsymmetricString('AZERTY', $fgp, null);

// Decrypt a document

Gpg::decryptFile('/path/to/encrypted_file', 'my password (if any), or null', '/path/to/decrypted_file');
Gpg::decryptFile('/path/to/encrypted_file', null, '/path/to/decrypted_file');
Gpg::decryptString($encryptedString, 'my password (if any), or null', '/path/to/decrypted_file');
Gpg::decryptString($encryptedString, null, '/path/to/decrypted_file');

$decryptedString = Gpg::decryptFile('/path/to/encrypted_file', 'my password (if any), or null', null);
$decryptedString = Gpg::decryptFile('/path/to/encrypted_file', null, null);
$decryptedString = Gpg::decryptString($encryptedString, 'my password (if any), or null', null);
$decryptedString = Gpg::decryptString($encryptedString, null, null);
```

For a detailed description of the return codes, please consult [this file](src/Gpg.php). 

# Signing a document (using the private key)

To sign a document means: encrypt the document using the private key.

## Command line

Command:

    gpg --armor -u 03DEC874738344206A1A7D31E07D9D14954C8DC5 --output document.sig --sign document
    
For automation inside a script:
    
    exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --armor -u 03DEC874738344206A1A7D31E07D9D14954C8DC5 --output file_to_sign.sig --clearsign file_to_sign.txt; echo $?; exec 3>&-
    
Then to decrypt the document (using the public key)

    gpg --output document.decrypted --decrypt document.sig
    gpg --output - --decrypt document.sig

> Please note that you can use the **sub key** associated to the private key instead of the private key itself.

## API

Sign:

    static function signFile($inAPath, $inPrivateKeyFingerPrint, $inOptPassword=null, $inOptSignaturePath=null)
    static function signString($inString, $inPrivateKeyFingerPrint, $inPassword=null, $inOptSignaturePath=null)

Decrypt:

    static function decryptFile($inAbsolutePath, $inOptPassword=null, $inOptOutputFile=null)
    static function decryptString($inString, $inOptPassword=null, $inOptOutputFile=null)

# Clear signing a document (using the private key)
    
To "clear sign" a document means:

* generate a hash of the document (using SHA1, for example).
* encrypt the previously generated hash with the private key.
* append the encrypted hash to the end of the document (which remains clear).

## Command line

Command:

    gpg --armor -u 03DEC874738344206A1A7D31E07D9D14954C8DC5 --output document.sig --clearsign document
    
Verify the signature:

    gpg --verify document.sig 

## API

Sign:

    static function clearSignFile($inPath, $inPrivateKeyFingerPrint, $inOptPassword=null, $inOptSignaturePath=null)
    static function clearSignString($inString, $inPrivateKeyFingerPrint, $inPassword=null, $inOptSignaturePath=null)

Verify the signature:

    static function verifyClearSignedFile($inFilePath, &$outWarning)
    static function verifyClearSignedString($inString, &$outWarning) {

# Creating a detached signature (using the private key)

Creating a "detached signature" means:

* generate a hash of the document (using SHA1, for example).
* encrypt the previously generated hash with the private key.
* write the encrypted hash in a (specified) file.

Please note that a "detached signature" and a "clear signature" are identical.
The difference between a "detached signature" and a "clear signature" is that the former is put into a separate file, whereas the latter is appended to the end of the signed document. 

## Command line

Command:

    gpg --armor -u 03DEC874738344206A1A7D31E07D9D14954C8DC5 --output document.sig --detach-sign document
    
Verify the signature:

    gpg --verify document.sig document 

## API

Sign:

    static function detachSignFile($inPath, $inPrivateKeyFingerPrint, $inOptPassword=null, $inOptSignaturePath=null)
    static function detachSignString($inString, $inPrivateKeyFingerPrint, $inPassword=null, $inOptSignaturePath=null)

Verify a signature:

    static function verifyDetachedSignedFile($inSignatureFilePath, $inDocument, &$outWarning)
    static function verifyDetachedSignedString($inSignature, $inDocument, &$outWarning)

# Encrypting a document (using a public key) 

## Command line

Command:

    gpg --armor --output encrypted_file --encrypt --recipient 03DEC874738344206A1A7D31E07D9D14954C8DC5 file_to_sign.txt

For automation inside a script:

    exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --always-trust --armor --output encrypted_file --encrypt --recipient 03DEC874738344206A1A7D31E07D9D14954C8DC5 file_to_sign.txt; echo $?; exec 3>&-

## API

    static function encryptAsymmetricFile($inInputPath, $inPublicKeyFingerPrint, $inOptOutputFile=null)
    static function encryptAsymmetricString($inString, $inPublicKeyFingerPrint, $inOptOutputFile=null)

# Decrypt a encrypted file

Please note that the document may have been encrypted using a public key or a secret key (that is, _signed_).

* If the document has been encrypted with a public key (probably yours), you will need a private key to decrypt it.
* If the document has been signed with a private key, you will need a public key to decrypt it.

## Command line

Command:

    gpg --output decrypted_file --decrypt encrypted_file

For automation inside a script:

    exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --always-trust --output decrypted_file --decrypt encrypted_file; echo $?; exec 3>&-

## API

    static function decryptFile($inAbsolutePath, $inOptPassword=null, $inOptOutputFile=null)
    static function decryptString($inString, $inOptPassword=null, $inOptOutputFile=null)

# Key management

Except when calling the methods that returns the fingerprints (`getPublicKeyFingerPrint` and `getPrivateKeyFingerPrint`), the keys are identified by their fingerprints
This ensures maximum security against "side effects" that may occur when specifying keys' IDs.

## API

    static function getPublicKeyFingerPrint($inPublicKey)
    static function getPrivateKeyFingerPrint($inPrivateKey)
    static function isPrivateKeyPresent($inPrivateKeyFingerPrint)
    static function isPublicKeyPresent($inPublicKeyFingerPrint)
    static function removePrivateKey($inPrivateKeyFingerPrint)
    static function removePublicKey($inPublicKeyFingerPrint)
    static function importPrivateKey($inPrivateKeyPath)
    static function importPublicKey($inPublicKeyPath)
    
# Other methods

    static function version()
    static function checkVersion()

# Testing the package

This package contains two pairs of keys:

* One pair which secret key is protected by a password.
* One pair which secret key is not protected.

These keys are located in the directory `tests/data`:

* `open.prv` / `open.pub`: this pair of keys is not protected.
* `protected.prv` / `protected.pub`: this pair of keys is protected.

## Importing these keys

    cd tests/data
    gpg --import open.prv; gpg --import open.pub; gpg --import protected.prv; gpg --import protected.pub

## Getting IDs and fingerprints

For public keys:

    gpg --batch --list-keys --fingerprint --with-colon
    
For private keys:
    
    gpg --batch --list-secret-keys --fingerprint --with-colon

> See [this document](http://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob_plain;f=doc/DETAILS) for a detailed description of the output of the option `--with-colon`. 

The Perl script [list-keys.pl](utilities/list-keys.pl) may be used to print the list of public keys.

    gpg --list-keys --with-colon --fingerprint | perl list-keys.pl
    gpg --list-secret-keys --with-colon --fingerprint | perl list-keys.pl

Example:

`   gpg --list-secret-keys --with-colon --fingerprint | perl list-keys.pl`

Outputs:

    6   sec E07D9D14954C8DC5 03DEC874738344206A1A7D31E07D9D14954C8DC5 0C185D728E760EC0 open key <ok@test.com>
    6   sec 29A778386005B911 881C41F8B8FD138E86E7230929A778386005B911 6A492A01B27F4819 protected key <pk@test.com>

Whith:

    Column 1: the total number of columns for the current line.
    Column 2: the type of key (pub: public, sec: secret).
    Column 3: the UID of the key.
    Column 4: the fingerprint of the key.
    Column 5: the UID of the associated sub key.
    Column 6: the ID of the key.

Please note that

* the last field of each line may have spaces (ex: `PHP coder <php_coder@php.com>`).
* a key may have more than one sub key. Therefore, a line may have more than 6 columns.
 
# Useful links
    
https://www.void.gr/kargig/blog/2013/12/02/creating-a-new-gpg-key-with-subkeys/
http://www.spywarewarrior.com/uiuc/gpg/gpg-com-4.htm
