<?php

// Copyright (c) 2016 Denis BEURIVE
//
// This work is licensed under the Creative Common Attribution-NonCommercial 4.0 International (CC BY-NC 4.0).

/**
 * This file implements a wrapper around the GPG's command line interface.
 *
 * Please note that the ambition of this wrapper is not to be "complete".
 *
 * This wrapper has been developed in order to automat the GPG processing of a large number of files.
 *
 * Therefore, the only the basic GPG functionalities have been wrapped (signing, encryption, decryption and signature verification).
 */

namespace dbeurive\Gpg;

/**
 * Class Gpg
 *
 * This class is a wrapper around the GPG's command line interface.
 * It implements the following functionalities.
 *    - Import a key, from a file, into the keyring.
 *    - Remove a key from the keyring.
 *    - Get the fingerprint of a given key, identified by its ID.
 *    - Test if a key, identified by it's fingerprint, is in the keyring.
 *    - Sign a document (file or string), using a private key.
 *    - Clear sign a document (file or string), using a private key.
 *    - Detach sign a document (file or string), using a private key.
 *    - Encrypt a document (file or string), using a private key.
 *    - Decrypt a signed document (file or string), using a public key.
 *    - Decrypt an encrypted document (file or string), using a private key (this may require a password).
 *    - Verify a signature.
 *
 * Conventions
 * ===========
 *
 * Except when calling the methods that returns the fingerprints, the keys are identified by their fingerprints
 * This ensures maximum security against "side effects" that may occur when specifying keys' IDs.
 *
 * Get the keys fingerprints:
 *
 *      gpg --batch --list-keys --fingerprint --with-colon
 **
 * Please note that the following command can also be used:
 *
 *      gpg --batch --list-keys --fingerprint
 *
 * However, while specifying fingerprints, no spaces should be used.
 * Therefore, the former command (with the option --with-colon) is recommended.
 *
 * Get the keys' IDs is:
 *
 *      gpg --list-keys --keyid-format=long
 *      gpg --list-keys --with-fingerprint --keyid-format=long
 *
 * Find out which key has been used to sign (or encrypt) a file:
 *
 *      gpg  --list-packets file_to_sign.sig
 *
 * All encrypted data is "armored". See GPG documentation for details.
 *
 * Notes
 * =====
 *
 * To import the keys used within the examples:
 *
 *      cd tests/data
 *      gpg --import open.prv; gpg --import open.pub; gpg --import protected.prv; gpg --import protected.pub
 *
 * To understand the content of the file generated while using the option --status-fd:
 *
 *      http://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob_plain;f=doc/DETAILS
 *
 *      Look for the string "Format of the --status-fd output"
 *
 * To encrypt using a private key is called "signing" in GPG lingo.
 * That is, the use of the option "--sign" will actually encrypt a document using a private key.
 * However, "signing" does not always mean that you will encrypt a document.
 * Indeed, you can produce a detached signature of the document (which is not the encrypted content of the document).
 * Or you can append a signature to a document (the appended signature is not the encrypted content of the document).
 *
 * Compatibility
 * =============
 *
 * This wrapper has been tested against GPG version 1.4.20.
 * It should work with other versions.
 * However, this is not guaranteed, since it relies in the output of the "gpg" command.
 * To test the wrapper against a specific version of GPG, you should run the unit tests.
 *
 * To do
 * =====
 *
 * I did not test the verification of a signature in the following conditions:
 *
 *   - The signature with the keyid is good, but the signature is expired (EXPSIG).
 *   - The signature with the keyid is good, but the signature was made by an expired key (EXPKEYSIG).
 *   - The signature with the keyid is good, but the signature was made by a revoked key (REVKEYSIG).
 *
 * The methods that verify signatures are designed to process these situations.
 * However, the unit tests does note cover these situations.
 *
 * @package dbeurive\Gpg
 */

class Gpg
{
    /** Path to GPG. */
    const EXE_GPG = '/usr/bin/gpg';

    /** This constant is used to signal an error. */
    const STATUS_ERROR = 0;
    /** This constant is used to signal the successful completion of a command. */
    const STATUS_SUCCESS = 1;
    /** This constant is used to signal that a key is present within a keyring. */
    const STATUS_KEY_PRESENT = 2;
    /** This constant is used to signal that a key is absent from a keyring. */
    const STATUS_KEY_ABSENT  = 3;
    /** This constant is used to signal that a signature is valid. */
    const STATUS_SIG_VALID = 4;
    /** This constant is used to signal that a signature is "mathematically valid", but a warning must be reported. */
    const STATUS_SIG_VALID_BUT_WARNING = 5;
    /** This constant is used to signal that a signature is not valid. */
    const STATUS_SIG_INVALID = 6;
    /** This constant is used to signal that we cannot verify the signature (because of a technical problem). */
    const STATUS_SIG_ERROR = 7;


    /** @see Gpg::__getKeyFingerPrintData() */
    const KEY_STATUS = 'status';
    /** @see Gpg::__getKeyFingerPrintData() */
    const KEY_DATA = 'data';

    /** The command being executed. */
    const KEY_COMMAND = 'command';
    /** The value returned the the command (that is: $?). */
    const KEY_COMMAND_RETURN_CODE = 'status code';
    /** The text loaded from the file identified be the option "--status-fd." */
    const KEY_COMMAND_STATUS_FILE = 'status file';
    /** The text loaded from the file identified be the option "--output." */
    const KEY_COMMAND_OUTPUT = 'output';
    /** An array that contains the standard output of the command. */
    const KEY_COMMAND_STDOUT = 'stdout';

    /**
     * Return the version of GPG.
     * @return string The version of GPG.
     * @note Command:
     *       gpg --version; echo $?
     * @note The option '--status-fd' is not available for this command.
     *       => To decide whether the command was successful or not, we look at the status returned by the command.
     *          On success, its value should be 0.
     * @note The option '--output' is not available for this command.
     * @throws \Exception
     */
    static public function version() {

        $cmd = array(
            '--version'
        );

        $result = self::__exec($cmd);
        $output = $result[self::KEY_COMMAND_STDOUT];

        if ($result[self::KEY_COMMAND_RETURN_CODE] != 0) {
            throw new \Exception("Error while executing the following command: " . $result[self::KEY_COMMAND]);
        }
        if (! isset($output[0])) {
            throw new \Exception("Error while executing the following command: " . $result[self::KEY_COMMAND]);
        }
        $line = $output[0];
        $matches = array();
        if (1 === preg_match('/^gpg \(GnuPG\) (.+)$/', $line, $matches)) {
            return $matches[1];
        }
        throw new \Exception("Error while executing the following command: " . $result[self::KEY_COMMAND]);
    }

    /**
     * Check the current version of GPG.
     * @return bool If the current version has been tested, and is known to work with the wrapper, then the method returns the value true.
     *         Otherwise, it returns the value false.
     * @note Please note that if the returned value is false, then it does not mean that the wrapper does not work with the current version of GPG.
     *       It just means that the wrapper has not been tested against the version.
     *       The procedure used to test the wrapper is pretty simple: just execute the unit tests.
     */
    static public function checkVersion() {
        $version = self::version();
        return 0 === version_compare('1.4.20', $version);
    }

    /**
     * Get the fingerprint of a public key, identified by its ID.
     * @param string $inPublicKey The public key ID.
     * @return null|false|string The method may return one of the following values:
     *         null: the key was not found.
     *         false: an error occurred.
     *         string: the key's fingerprint.
     * @note Command:
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --output /tmp/result --list-keys --fingerprint --with-colon "open key"; echo $?; exec 3>&-
     * @note The option '--status-fd' is not available for this command.
     *       A specific method is assigned to explore the output of this command.
     *       It parses the standard output of the command, so it may not be 100% reliable.
     * @note The option '--output' is not available for this command.
     * @see Gpg::__getKeyFingerPrintData
     */
    static public function getPublicKeyFingerPrint($inPublicKey) {

        $cmd = array(
            '--list-keys',
            '--fingerprint',
            '--with-colon',
            escapeshellarg($inPublicKey)
        );

        $result = self::__exec($cmd);
        $output = $result[self::KEY_COMMAND_STDOUT];

        $data = self::__getKeyFingerPrintData($output);
        if (self::STATUS_ERROR == $data[self::KEY_STATUS]) {
            return false;
        }
        if (self::STATUS_KEY_ABSENT == $data[self::KEY_STATUS]) {
            return null;
        }
        return $data[self::KEY_DATA];
    }

    /**
     * Get the fingerprint of a private key, identified by its ID.
     * @param string $inPrivateKey The private key ID.
     * @return null|false|string The method may return one of the following values:
     *         null: the key was not found.
     *         false: an error occurred.
     *         string: the key's fingerprint.
     * @note Command:
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --output /tmp/result --list-secret-keys --fingerprint --with-colon "open key"; echo $?; exec 3>&-
     * @note The option '--status-fd' is not available for this command.
     *       A specific method is assigned to explore the output of this command.
     *       It parses the standard output of the command, so it may not be 100% reliable.
     * @note The option '--output' is not available for this command.
     * @see Gpg::__getKeyFingerPrintData
     */
    static public function getPrivateKeyFingerPrint($inPrivateKey) {

        $cmd = array(
            '--list-secret-keys',
            '--fingerprint',
            '--with-colon',
            escapeshellarg($inPrivateKey)
        );

        $result = self::__exec($cmd);
        $output = $result[self::KEY_COMMAND_STDOUT];

        $data = self::__getKeyFingerPrintData($output);
        if (self::STATUS_ERROR == $data[self::KEY_STATUS]) {
            return false;
        }
        if (self::STATUS_KEY_ABSENT == $data[self::KEY_STATUS]) {
            return null;
        }
        return $data[self::KEY_DATA];
    }

    /**
     * Test if a private key, identified by its fingerprint, is present within the key ring.
     * @param string $inPrivateKeyFingerPrint Fingerprint of the private key.
     * @return bool If the key is present, then the method returns the value true.
     *         Otherwise, it returns the value false.
     * @note Command:
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --output /tmp/result --list-secret-keys "open key"; echo $?; exec 3>&-
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --output /tmp/result --list-secret-keys --fingerprint --with-colon "open key"; echo $?; exec 3>&-
     * @note The option '--status-fd' is not available for this command.
     *       If the value of the returned code is 0, then it means that the private key is in the keyring.
     *       If the value of the returned code is 2, then we must parse the output of the command in order to find out if the error means whether the key is absent or not.
     *       A specific method is assigned to explore the output of this command.
     *       It parses the standard output of the command, so it may not be 100% reliable.
     * @note The option '--output' is not available for this command.
     * @throws \Exception
     * @see Gpg::__getListKeysStatus
     */
    static public function isPrivateKeyPresent($inPrivateKeyFingerPrint) {

        $cmd = array(
            '--list-secret-keys',
            escapeshellarg($inPrivateKeyFingerPrint)
        );

        $result = self::__exec($cmd);
        $output = $result[self::KEY_COMMAND_STDOUT];
        $status = $result[self::KEY_COMMAND_RETURN_CODE];

        if (0 === $status) {
            // This means that the key is in the keyring.
            return true;
        }

        if (2 === $status) {
            // The key should not be in the keyring... but let's make sure of this.
            if (self::STATUS_KEY_ABSENT == self::__getListKeysStatus($output)) {
                return false;
            }
        }

        throw new \Exception("Error while executing the following command: " . $result[self::KEY_COMMAND]);
    }

    /**
     * Test if a public key, identified by its fingerprint, is present within the key ring.
     * @param string $inPublicKeyFingerPrint Fingerprint of the private key.
     * @return bool If the key is present, then the method returns the value true.
     *         Otherwise, it returns the value false.
     * @note Command:
     *       gpg --list-keys "open key"; echo $?
     *       gpg --list-keys --fingerprint --with-colon "open key"; echo $?
     * @note The option '--status-fd' is not available for this command.
     *       If the value of the returned code is 0, then it means that the private key is in the keyring.
     *       If the value of the returned code is 2, then we must parse the output of the command in order to find out if the error means whether the key is absent or not.
     *       A specific method is assigned to explore the output of this command.
     *       It parses the standard output of the command, so it may not be 100% reliable.
     * @note The option '--output' is not available for this command.
     * @throws \Exception
     * @see Gpg::__getListKeysStatus
     */
    static public function isPublicKeyPresent($inPublicKeyFingerPrint) {

        $cmd = array(
            '--list-keys',
            escapeshellarg($inPublicKeyFingerPrint)
        );

        $result = self::__exec($cmd);
        $output = $result[self::KEY_COMMAND_STDOUT];
        $status = $result[self::KEY_COMMAND_RETURN_CODE];

        if (0 === $status) {
            // This means that the key is in the keyring.
            return true;
        }
        if (2 === $status) {
            // The key should not be in the keyring... but let's make sure of this.
            if (self::STATUS_KEY_ABSENT == self::__getListKeysStatus($output)) {
                return false;
            }
        }

        throw new \Exception("Error while executing the following command: " . $result[self::KEY_COMMAND]);
    }

    /**
     * Remove a private key, identified by its fingerprint, from the keyring.
     * @param string $inPrivateKeyFingerPrint Fingerprint of the private key to remove.
     * @return bool Upon successful completion the method returns the value true.
     *         Otherwise, it returns the value false. This means that the key was not in the keyring. Hence, it could not be removed.
     * @note Command:
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --delete-secret-keys "881C41F8B8FD138E86E7230929A778386005B911"; echo $?; exec 3>&-
     *       SUCCESS: /tmp/status is empty.
     *                And the status returned by the command is 0.
     *       ERROR:   /tmp/status contains:
     *                [GNUPG:] DELETE_PROBLEM 1
     *                And the status returned by the command is not 0.
     *
     *                From "doc/DETAILS":
     *                *** DELETE_PROBLEM <reason_code>
     *                Deleting a key failed.  Reason codes are:
     *                - 1 :: No such key
     *                - 2 :: Must delete secret key first
     *                - 3 :: Ambigious specification
     *                - 4 :: Key is stored on a smartcard.
     *
     *       => To decide whether the command was successful or not, we look at the status returned by the command.
     *          On success, its value should be 0.
     *       => If the status returned by the command is not 0, then we look at the file "/tmp/status".
     * @note The option '--output' is not available for this command.
     * @throws \Exception
     * @see Gpg::__getRemoveKeyStatus
     */
    static public function removePrivateKey($inPrivateKeyFingerPrint) {

        $cmd = array(
            '--delete-secret-keys',
            escapeshellarg($inPrivateKeyFingerPrint)
        );

        $result = self::__exec($cmd);
        $status = $result[self::KEY_COMMAND_RETURN_CODE];
        $error  = 'Unexpected error';

        if (0 === $status) {
            // This means that the key was removed from the keyring.
            return true;
        }
        if (2 === $status) {

            $statusText = explode(PHP_EOL, $result[self::KEY_COMMAND_STATUS_FILE]);

            // This should mean that the key was not in the keyring.
            if (self::STATUS_SUCCESS == self::__getRemoveKeyStatus($statusText, $error)) {
                return false;
            }
        }

        throw new \Exception("Error while executing the following command: " . $result[self::KEY_COMMAND] . ' ' . $error);
    }

    /**
     * Remove a public key, identified by its fingerprint, from the key ring.
     * @param string $inPublicKeyFingerPrint Fingerprint of the public key to remove.
     * @return bool Upon successful completion the method returns the value true.
     *         Otherwise, it returns the value false. This means that the key was not in the keyring. Hence, it could not be removed.
     * @note Command:
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --delete-keys "881C41F8B8FD138E86E7230929A778386005B911"; echo $?; exec 3>&-
     *       SUCCESS: /tmp/status is empty.
     *                And the status returned by the command is 0.
     *       ERROR:   /tmp/status contains:
     *                [GNUPG:] DELETE_PROBLEM 1
     *                And the status returned by the command is not 0.
     *
     *                From "doc/DETAILS":
     *                *** DELETE_PROBLEM <reason_code>
     *                Deleting a key failed.  Reason codes are:
     *                - 1 :: No such key
     *                - 2 :: Must delete secret key first
     *                - 3 :: Ambigious specification
     *                - 4 :: Key is stored on a smartcard.
     *
     *       => To decide whether the command was successful or not, we look at the status returned by the command.
     *          On success, its value should be 0.
     *       => If the status returned by the command is not 0, then we look at the file "/tmp/status".
     * @note The option '--output' is not available for this command.
     * @throws \Exception
     * @see Gpg::__getRemoveKeyStatus
     */
    static public function removePublicKey($inPublicKeyFingerPrint) {

        $cmd = array(
            '--delete-keys',
            escapeshellarg($inPublicKeyFingerPrint)
        );

        $result = self::__exec($cmd);
        $status = $result[self::KEY_COMMAND_RETURN_CODE];

        if (0 === $status) {
            // This means that the key was removed from the keyring.
            return true;
        }
        if (2 === $status) {

            $statusText = explode(PHP_EOL, $result[self::KEY_COMMAND_STATUS_FILE]);

            // This should mean that the key was not in the keyring.
            if (self::STATUS_SUCCESS == self::__getRemoveKeyStatus($statusText, $error)) {
                return false;
            }
        }

        throw new \Exception("Error while executing the following command: " . $result[self::KEY_COMMAND] . ' ');
    }

    /**
     * Import a private key from a file.
     * @param string $inPrivateKeyPath Path to the file that contains the private key to load.
     * @return bool Upon successful completion the method returns the value true.
     *         Otherwise, it returns the value false. This means that the key was already in the keyring. Hence, the key was not imported.
     * @see Gpg::__getImportPrivateKeyStatus
     * @note Command:
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --import open.prv; echo $?; exec 3>&-
     *       SUCCESS: /tmp/status contains:
     *                [GNUPG:] IMPORT_OK 16 03DEC874738344206A1A7D31E07D9D14954C8DC5
     *                [GNUPG:] IMPORT_RES 1 0 0 0 0 0 0 0 0 1 0 1 0 0
     *                However, the status code may be 0 or 2.
     *       ERROR:   /tmp/status contains:
     *                [GNUPG:] IMPORT_RES 0 0 0 0 0 0 0 0 0 0 0 0 0 0
     *                And the status returned by the command is not 0.
     *
     *                From "doc/DETAILS":
     *                *** IMPORT_OK  <reason> [<fingerprint>]
     *                The key with the primary key's FINGERPRINT has been imported.
     *                REASON flags are:
     *                - 0 :: Not actually changed
     *                - 1 :: Entirely new key.
     *                - 2 :: New user IDs
     *                - 4 :: New signatures
     *                - 8 :: New subkeys
     *                - 16 :: Contains private key.
     *
     *       => To decide whether the command was successful or not, we look at "IMPORT_OK" in the status file (regardless of the value of the status returned by the command).
     *          * if this pattern is found, then the operation was successful.
     *          * otherwise, an error occurred.
     *
     * @throws \Exception
     */
    static public function importPrivateKey($inPrivateKeyPath) {

        if (! file_exists($inPrivateKeyPath)) {
            throw new \Exception("File \"$inPrivateKeyPath\" does not exist.");
        }

        $cmd = array(
            '--import',
            escapeshellarg($inPrivateKeyPath)
        );

        $result = self::__exec($cmd);
        $status = $result[self::KEY_COMMAND_RETURN_CODE];
        $statusText = explode(PHP_EOL, $result[self::KEY_COMMAND_STATUS_FILE]);

        if ((0 == $status) || (2 == $status)) {
            return self::__getImportPrivateKeyStatus($statusText);
        }

        throw new \Exception("Error while executing the following command: " . $result[self::KEY_COMMAND] . ' Status code was ' . $status);
    }

    /**
     * Import a public key from a file.
     * @param string $inPublicKeyPath Path to the file that contains the public key to load.
     * @return true Upon successful completion the method returns the value true.
     * @note Please note that, unlike when importing a private key, the return value could not be used to distinguish whether the key was already in the keyring or not, prior to its importation.
     *       Whether the key was already in the keyring or not, the method returns the value true.
     * @note Command:
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --import open.pub; echo $?; exec 3>&-
     *       SUCCESS: /tmp/status contains:
     *                [GNUPG:] IMPORT_OK 0 03DEC874738344206A1A7D31E07D9D14954C8DC5
     *                [GNUPG:] IMPORT_RES 1 0 0 0 1 0 0 0 0 0 0 0 0 0
     *                However, the status code may be 0 or 2.
     *       ERROR:   /tmp/status contains:
     *                [GNUPG:] IMPORT_RES 0 0 0 0 0 0 0 0 0 0 0 0 0 0
     *                And the status returned by the command is not 0.
     *
     *                From "doc/DETAILS":
     *                *** IMPORT_OK  <reason> [<fingerprint>]
     *                The key with the primary key's FINGERPRINT has been imported.
     *                REASON flags are:
     *                - 0 :: Not actually changed
     *                - 1 :: Entirely new key.
     *                - 2 :: New user IDs
     *                - 4 :: New signatures
     *                - 8 :: New subkeys
     *                - 16 :: Contains private key.
     *
     *       => To decide whether the command was successful or not, we look at "IMPORT_OK" in the status file (regardless of the value of the status returned by the command).
     *          * if this pattern is found, then the operation was successful.
     *          * otherwise, an error occurred.
     *
     * @throws \Exception
     */
    static public function importPublicKey($inPublicKeyPath) {

        if (! file_exists($inPublicKeyPath)) {
            throw new \Exception("File \"$inPublicKeyPath\" does not exist.");
        }

        $cmd = array(
            '--import',
            escapeshellarg($inPublicKeyPath)
        );

        $result = self::__exec($cmd);
        $status = $result[self::KEY_COMMAND_RETURN_CODE];
        $statusText = explode(PHP_EOL, $result[self::KEY_COMMAND_STATUS_FILE]);

        if ((0 == $status) || (2 == $status)) {
            return self::__getImportPrivateKeyStatus($statusText);
        }

        throw new \Exception("Error while executing the following command: " . $result[self::KEY_COMMAND] . ' Status code was ' . $status);
    }

    /**
     * Sign a given file, using a given private key.
     * @param string $inAbsolutePath Absolute path to the file to sign.
     * @param string $inPrivateKeyFingerPrint Fingerprint of the private key to use.
     * @param string $inOptPassword Password associated to the private key.
     *        If no password is required, then you should set the value of this parameter to null.
     * @param null|string $inOptSignaturePath Absolute path to the generated signature.
     *        If this parameter is not specified, then the method will return the signature as a string.
     * @return true|string Upon successful completion:
     *         If a destination file has been specified, then the method returns the value true.
     *         Otherwise, the method returns a string that represents the signature.
     * @throws \Exception
     * @see Gpg::__getSignFileStatus
     * @note Commands:
     *       gpg --list-secret-keys --fingerprint --with-colon
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --armor -u 03DEC874738344206A1A7D31E07D9D14954C8DC5 --output file_to_sign.sig --sign file_to_sign.txt; echo $?; exec 3>&-
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --armor -u 03DEC874738344206A1A7D31E07D9D14954C8DC5 --output - --sign file_to_sign.txt; echo $?; exec 3>&-
     *       exec 3> /tmp/status; echo 'password' | gpg --batch --yes --status-fd 3 --armor -u 881C41F8B8FD138E86E7230929A778386005B911 --passphrase-fd 0 --output file_to_sign.sig --sign file_to_sign.txt; echo $?; exec 3>&-
     *       exec 3> /tmp/status; echo 'password' | gpg --batch --yes --status-fd 3 --armor -u 881C41F8B8FD138E86E7230929A778386005B911 --passphrase-fd 0 --output - --sign file_to_sign.txt; echo $?; exec 3>&-
     *       SUCCESS: /tmp/status contains:
     *                [GNUPG:] GOOD_PASSPHRASE
     *                [GNUPG:] BEGIN_SIGNING
     *                [GNUPG:] SIG_CREATED S 1 2 00 1482578614 03DEC874738344206A1A7D31E07D9D14954C8DC5
     *                And the status returned by the command is 0.
     *       ERROR:   /tmp/status may be empty or not.
     *                However, the pattern "SIG_CREATED" is absent.
     *                And the status returned by the command is not 0.
     *
     *                *** SIG_CREATED <type> <pk_algo> <hash_algo> <class> <timestamp> <keyfpr>
     *                A signature has been created using these parameters.
     *                Values for type <type> are:
     *                - D :: detached
     *                - C :: cleartext
     *                - S :: standard
     *                (only the first character should be checked)
     *
     *       => To decide whether the command was successful or not, we look at "SIG_CREATED" in the status file (regardless of the value of the status returned by the command).
     *          * if this pattern is found, then the operation was successful.
     *          * otherwise, an error occurred.
     */
    static public function signFile($inAbsolutePath, $inPrivateKeyFingerPrint, $inOptPassword=null, $inOptSignaturePath=null) {

        $inAbsolutePath = realpath($inAbsolutePath);
        $inOptSignaturePath = is_null($inOptSignaturePath) ? null : $inOptSignaturePath;

        if (! file_exists($inAbsolutePath)) {
            throw new \Exception("File \"$inAbsolutePath\" does not exist.");
        }

        $cmd = array(
            '--armor',
            '-u',
            escapeshellarg($inPrivateKeyFingerPrint),
            '--sign',
            escapeshellarg($inAbsolutePath)
        );

        $result = self::__exec($cmd, $inOptSignaturePath, $inOptPassword);
        $statusText = explode(PHP_EOL, $result[self::KEY_COMMAND_STATUS_FILE]);

        if (! self::__getSignFileStatus($statusText)) {
            $status = $result[self::KEY_COMMAND_RETURN_CODE];
            throw new \Exception("Error while executing the following command: " . $result[self::KEY_COMMAND] . ' Status code was ' . $status);
        }

        if (! is_null($inOptSignaturePath)) {
            // This file exists (see method self::__exec).
            return true;
        }

        return $result[self::KEY_COMMAND_OUTPUT];
    }

    /**
     * Sign a given string, using a given private key.
     * @param string $inString String to sign.
     * @param string $inPrivateKeyFingerPrint Fingerprint of the private key to use.
     * @param string $inPassword Password associated to the private key.
     *        If no password is required, then you should set the value of this parameter to null.
     * @param null|string $inOptSignaturePath Absolute path to the generated signature.
     *        If this parameter is not specified, then the method will return the signature as a string.
     * @return true|string Upon successful completion:
     *         If a destination file has been specified, then the method returns the value true.
     *         Otherwise, the method returns a string that represents the signature.
     * @throws \Exception
     * @note This method uses a temporary file.
     */
    static function signString($inString, $inPrivateKeyFingerPrint, $inPassword=null, $inOptSignaturePath=null) {

        $input = tempnam(sys_get_temp_dir(), 'Gpg::signString::');
        if (false === file_put_contents($input, $inString)) {
            throw new \Exception("Can not write data into temporary file \"$input\"");
        }

        $result = self::signFile($input, $inPrivateKeyFingerPrint, $inPassword, $inOptSignaturePath);

        if (false === unlink($input)) {
            throw new \Exception("Can not remove file \"$input\".");
        }

        return $result;
    }

    /**
     * Clear sign a given file, using a given private key.
     * @param string $inAbsolutePath Absolute path to the file to sign.
     * @param string $inPrivateKeyFingerPrint Fingerprint of the private key to use.
     * @param string $inOptPassword Password associated to the private key.
     *        If no password is required, then you should set the value of this parameter to null.
     * @param null|string $inOptSignaturePath Absolute path to the generated signature.
     *        If this parameter is not specified, then the method will return the signature as a string.
     * @return true|string Upon successful completion:
     *         If a destination file has been specified, then the method returns the value true.
     *         Otherwise, the method returns a string that represents the signature.
     * @throws \Exception
     * @note Commands:
     *       gpg --list-secret-keys --fingerprint --with-colon
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --armor -u 03DEC874738344206A1A7D31E07D9D14954C8DC5 --output file_to_sign.sig --clearsign file_to_sign.txt; echo $?; exec 3>&-
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --armor -u 03DEC874738344206A1A7D31E07D9D14954C8DC5 --output - --clearsign file_to_sign.txt; echo $?; exec 3>&-
     *       exec 3> /tmp/status; echo 'password' | gpg --batch --yes --status-fd 3 --armor -u 881C41F8B8FD138E86E7230929A778386005B911 --passphrase-fd 0 --output file_to_sign.sig --clearsign file_to_sign.txt; echo $?; exec 3>&-
     *       exec 3> /tmp/status; echo 'password' | gpg --batch --yes --status-fd 3 --armor -u 881C41F8B8FD138E86E7230929A778386005B911 --passphrase-fd 0 --output - --clearsign file_to_sign.txt; echo $?; exec 3>&-
     * @see Gpg::__getSignFileStatus
     * @see Gpg::signFile
     */
    static public function clearSignFile($inAbsolutePath, $inPrivateKeyFingerPrint, $inOptPassword=null, $inOptSignaturePath=null)
    {
        $inAbsolutePath = realpath($inAbsolutePath);
        $inOptSignaturePath = is_null($inOptSignaturePath) ? null : $inOptSignaturePath;

        if (! file_exists($inAbsolutePath)) {
            throw new \Exception("File \"$inAbsolutePath\" does not exist.");
        }

        $cmd = array(
            '--armor',
            '-u',
            escapeshellarg($inPrivateKeyFingerPrint),
            '--clearsign',
            escapeshellarg($inAbsolutePath)
        );

        $result = self::__exec($cmd, $inOptSignaturePath, $inOptPassword);
        $statusText = explode(PHP_EOL, $result[self::KEY_COMMAND_STATUS_FILE]);

        if (! self::__getSignFileStatus($statusText)) {
            $status = $result[self::KEY_COMMAND_RETURN_CODE];
            throw new \Exception("Error while executing the following command: " . $result[self::KEY_COMMAND] . ' Status code was ' . $status);
        }

        if (! is_null($inOptSignaturePath)) {
            // This file exists (see method self::__exec).
            return true;
        }

        return $result[self::KEY_COMMAND_OUTPUT];
    }

    /**
     * Clear sign a given string, using a given private key.
     * @param string $inString String to sign.
     * @param string $inPrivateKeyFingerPrint Fingerprint of the private key to use.
     * @param string $inPassword Password associated to the private key.
     *        If no password is required, then you should set the value of this parameter to null.
     * @param null|string $inOptSignaturePath Absolute path to the generated signature.
     *        If this parameter is not specified, then the method will return the signature as a string.
     * @return true|string Upon successful completion:
     *         If a destination file has been specified, then the method returns the value true.
     *         Otherwise, the method returns a string that represents the signature.
     * @throws \Exception
     * @note This method uses a temporary file.
     */
    static function clearSignString($inString, $inPrivateKeyFingerPrint, $inPassword=null, $inOptSignaturePath=null) {

        $input = tempnam(sys_get_temp_dir(), 'Gpg::signString::');
        if (false === file_put_contents($input, $inString)) {
            throw new \Exception("Can not write data into temporary file \"$input\"");
        }

        $result = self::clearSignFile($input, $inPrivateKeyFingerPrint, $inPassword, $inOptSignaturePath);

        if (false === unlink($input)) {
            throw new \Exception("Can not remove file \"$input\".");
        }

        return $result;
    }

    /**
     * Verify a signature embedded within the output of a clear signing process.
     * @param string $inFilePath Path to the file that contains the signature (and the signed document).
     * @param string $outWarning Reference to a string used to store a warning message.
     *        Warning messages may be reported for valid signatures (that is, when the returned value is true).
     * @return bool If the signature is valid, then the method returns the value true.
     *         Otherwise, it returns the value false.
     *         Please note that if the returned value is true, indicating that the signature is valid, then you should look for warning messages.
     *         Indeed, although a signature may be "mathematically" valid, it may have been created with a revoked key (for example).
     *         In such a case, a warning message is reported, indicating than the key used to produce the signature has been revoked.
     * @note Command:
     *       gpg --armor -u 03DEC874738344206A1A7D31E07D9D14954C8DC5 --output signature --clearsign file_to_sign
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --verify signature; echo $?; exec 3>&-
     * @note In order to verify the status of the execution:
     *
     *       If the returned status code is not 0 or 1, then it means that an error occurred.
     *
     *       If the returned status code is 0, then we look at the content of the file which file descriptor is specified by the option "--status-fd".
     *
     *       Valid signatures:
     *          If we find one of the following tags, we consider that the signature is valid (the return value is true):
     *          VALIDSIG, GOODSIG, EXPSIG, EXPKEYSIG, or REVKEYSIG.
     *          Please note that the presence of the following tag will trigger a warning message:
     *          EXPSIG, EXPKEYSIG, or REVKEYSIG.
     *
     *       Invalid signatures:
     *          If we find the tag BADSIG, then we consider that the signature is not valid (the return value is false).
     *
     *       Errors:
     *          If we find the tag ERRSIG, then we raise an exception. It means that we can not verify the signature.
     *
     * @see http://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob_plain;f=doc/DETAILS
     * @throws \Exception
     */
    static public function verifyClearSignedFile($inFilePath, &$outWarning) {

        $outWarning = null;

        if (! file_exists($inFilePath)) {
            throw new \Exception("File \"$inFilePath\" does not exist!");
        }

        $cmd = array(
            '--verify',
            escapeshellarg($inFilePath)
        );

        $result = self::__exec($cmd);
        $statusCode = $result[self::KEY_COMMAND_RETURN_CODE];

        if ((0 !== $statusCode) && (1 !== $statusCode)) {
            throw new \Exception("Could not verify the signature from file \"$inFilePath\": return code is $statusCode.");
        }

        $statusText = explode(PHP_EOL, $result[self::KEY_COMMAND_STATUS_FILE]);
        $status = self::__getVerifySignatureStatus($statusText, $outWarning);
        switch ($status) {
            case self::STATUS_SIG_VALID: return true;
            case self::STATUS_SIG_VALID_BUT_WARNING: return true;
            case self::STATUS_SIG_INVALID; return false;
        }

        throw new \Exception("Could not verify the signature from file \"$inFilePath\": $outWarning");
    }

    /**
     * Verify a signature, stored within a given string, obtained by clear signing a document.
     * @param string $inString String that contains the signature.
     * @param string $outWarning Reference to a string used to report an error message.
     *        Warning messages may be reported for valid signatures (that is, when the returned value is true).
     * @return bool If the signature is valid, then the method returns the value true.
     *         Otherwise, it returns the value false.
     *         Please note that if the returned value is true, indicating that the signature is valid, then you should look for warning messages.
     *         Indeed, although a signature may be "mathematically" valid, it may have been created with a revoked key (for example).
     *         In such a case, a warning message is reported, indicating than the key used to produce the signature has been revoked.     * @throws \Exception
     * @throws \Exception
     * @see Gpg::verifyClearSignedFile()
     */
    static public function verifyClearSignedString($inString, &$outWarning) {

        $outWarning = null;
        $input = tempnam(sys_get_temp_dir(), 'Gpg::signString::');
        if (false === file_put_contents($input, $inString)) {
            throw new \Exception("Can not write data into temporary file \"$input\"");
        }

        $result = self::verifyClearSignedFile($input, $outWarning);

        if (false === unlink($input)) {
            throw new \Exception("Can not remove file \"$input\".");
        }

        return $result;
    }

    /**
     * Verify a detached signature against a given document.
     * @param string $inSignatureFilePath Path to the file that contains the (detached) signature.
     * @param string $inDocument Path to the document.
     * @param string $outWarning Reference to a string used to store a warning message.
     *        Warning messages may be reported for valid signatures (that is, when the returned value is true).
     * @return bool If the signature is valid, then the method returns the value true.
     *         Otherwise, it returns the value false.
     *         Please note that if the returned value is true, indicating that the signature is valid, then you should look for warning messages.
     *         Indeed, although a signature may be "mathematically" valid, it may have been created with a revoked key (for example).
     *         In such a case, a warning message is reported, indicating than the key used to produce the signature has been revoked.
     * @note Command:
     *       gpg --armor -u 03DEC874738344206A1A7D31E07D9D14954C8DC5 --output signature --detach-sign file_to_sign
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --verify signature file_to_sign; echo $?; exec 3>&-
     * @note In order to verify the status of the execution:
     *
     *       If the returned status code is not 0 or 1, then it means that an error occurred.
     *
     *       If the returned status code is 0, then we look at the content of the file which file descriptor is specified by the option "--status-fd".
     *
     *       Valid signatures:
     *          If we find one of the following tags, we consider that the signature is valid (the return value is true):
     *          VALIDSIG, GOODSIG, EXPSIG, EXPKEYSIG, or REVKEYSIG.
     *          Please note that the presence of the following tag will trigger a warning message:
     *          EXPSIG, EXPKEYSIG, or REVKEYSIG.
     *
     *       Invalid signatures:
     *          If we find the tag BADSIG, then we consider that the signature is not valid (the return value is false).
     *
     *       Errors:
     *          If we find the tag ERRSIG, then we raise an exception. It means that we can not verify the signature.
     *
     * @see http://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob_plain;f=doc/DETAILS
     * @throws \Exception
     */
    static public function verifyDetachedSignedFile($inSignatureFilePath, $inDocument, &$outWarning) {

        $outWarning = null;

        if (! file_exists($inSignatureFilePath)) {
            throw new \Exception("File \"$inSignatureFilePath\" does not exist!");
        }

        if (! file_exists($inDocument)) {
            throw new \Exception("File \"$inDocument\" does not exist!");
        }

        $cmd = array(
            '--verify',
            escapeshellarg($inSignatureFilePath),
            escapeshellarg($inDocument)
        );

        $result = self::__exec($cmd);
        $statusCode = $result[self::KEY_COMMAND_RETURN_CODE];

        if ((0 !== $statusCode) && (1 !== $statusCode)) {
            throw new \Exception("Could not verify the signature from file \"$inSignatureFilePath\": return code is $statusCode.");
        }

        $statusText = explode(PHP_EOL, $result[self::KEY_COMMAND_STATUS_FILE]);

        $status = self::__getVerifySignatureStatus($statusText, $outWarning);
        switch ($status) {
            case self::STATUS_SIG_VALID: return true;
            case self::STATUS_SIG_VALID_BUT_WARNING: return true;
            case self::STATUS_SIG_INVALID; return false;
        }

        throw new \Exception("Could not verify the signature from file \"$inSignatureFilePath\": $outWarning");
    }

    /**
     * Verify a detached signature, given as a string, against a given document.
     * @param string $inSignature String that contains the (detached) signature.
     * @param string $inDocument Path to the document.
     * @param string $outWarning Reference to a string used to store a warning message.
     *        Warning messages may be reported for valid signatures (that is, when the returned value is true).
     * @return bool If the signature is valid, then the method returns the value true.
     *         Otherwise, it returns the value false.
     *         Please note that if the returned value is true, indicating that the signature is valid, then you should look for warning messages.
     *         Indeed, although a signature may be "mathematically" valid, it may have been created with a revoked key (for example).
     *         In such a case, a warning message is reported, indicating than the key used to produce the signature has been revoked.
     * @throws \Exception
     * @see Gpg::verifyDetachedSignedFile()
     */
    static public function verifyDetachedSignedString($inSignature, $inDocument, &$outWarning) {

        if (! file_exists($inDocument)) {
            throw new \Exception("File \"$inDocument\" does not exist!");
        }

        $outWarning = null;
        $input = tempnam(sys_get_temp_dir(), 'Gpg::verifyDetachedSignedString::');
        if (false === file_put_contents($input, $inSignature)) {
            throw new \Exception("Can not write data into temporary file \"$input\"");
        }

        $result = self::verifyDetachedSignedFile($input, $inDocument, $outWarning);

        if (false === unlink($input)) {
            throw new \Exception("Can not remove file \"$input\".");
        }

        return $result;
    }

    /**
     * Detach sign a given file, using a given private key.
     * @param string $inAbsolutePath Absolute path to the file to sign.
     * @param string $inPrivateKeyFingerPrint Fingerprint of the private key to use.
     * @param string $inOptPassword Password associated to the private key.
     *        If no password is required, then you should set the value of this parameter to null.
     * @param null|string $inOptSignaturePath Absolute path to the generated signature.
     *        If this parameter is not specified, then the method will return the signature as a string.
     * @return true|string Upon successful completion:
     *         If a destination file has been specified, then the method returns the value true.
     *         Otherwise, the method returns a string that represents the signature.
     * @throws \Exception
     * @note Commands:
     *       gpg --list-secret-keys --fingerprint --with-colon
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --armor -u 03DEC874738344206A1A7D31E07D9D14954C8DC5 --output file_to_sign.sig --detach-sign file_to_sign.txt; echo $?; exec 3>&-
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --armor -u 03DEC874738344206A1A7D31E07D9D14954C8DC5 --output - --detach-sign file_to_sign.txt; echo $?; exec 3>&-
     *       exec 3> /tmp/status; echo 'password' | gpg --batch --yes --status-fd 3 --armor -u 881C41F8B8FD138E86E7230929A778386005B911 --passphrase-fd 0 --output file_to_sign.sig --detach-sign file_to_sign.txt; echo $?; exec 3>&-
     *       exec 3> /tmp/status; echo 'password' | gpg --batch --yes --status-fd 3 --armor -u 881C41F8B8FD138E86E7230929A778386005B911 --passphrase-fd 0 --output - --detach-sign file_to_sign.txt; echo $?; exec 3>&-
     * @see Gpg::__getSignFileStatus
     * @see Gpg::signFile
     */
    static public function detachSignFile($inAbsolutePath, $inPrivateKeyFingerPrint, $inOptPassword=null, $inOptSignaturePath=null)
    {
        $inAbsolutePath = realpath($inAbsolutePath);
        $inOptSignaturePath = is_null($inOptSignaturePath) ? null : $inOptSignaturePath;

        if (! file_exists($inAbsolutePath)) {
            throw new \Exception("File <$inAbsolutePath> does not exist.");
        }

        $cmd = array(
            '--armor',
            '-u',
            escapeshellarg($inPrivateKeyFingerPrint),
            '--detach-sign',
            escapeshellarg($inAbsolutePath)
        );

        $result = self::__exec($cmd, $inOptSignaturePath, $inOptPassword);
        $statusText = explode(PHP_EOL, $result[self::KEY_COMMAND_STATUS_FILE]);

        if (! self::__getSignFileStatus($statusText)) {
            $status = $result[self::KEY_COMMAND_RETURN_CODE];
            throw new \Exception("Error while executing the following command: " . $result[self::KEY_COMMAND] . ' Status code was ' . $status);
        }

        if (! is_null($inOptSignaturePath)) {
            // This file exists (see method self::__exec).
            return true;
        }

        return $result[self::KEY_COMMAND_OUTPUT];
    }


    /**
     * Detach sign a given string, using a given private key.
     * @param string $inString String to sign.
     * @param string $inPrivateKeyFingerPrint Fingerprint of the private key to use.
     * @param string $inPassword Password associated to the private key.
     *        If no password is required, then you should set the value of this parameter to null.
     * @param null|string $inOptSignaturePath Absolute path to the generated signature.
     *        If this parameter is not specified, then the method will return the signature as a string.
     * @return true|string Upon successful completion:
     *         If a destination file has been specified, then the method returns the value true.
     *         Otherwise, the method returns a string that represents the signature.
     * @throws \Exception
     * @note This method uses a temporary file.
     */
    static function detachSignString($inString, $inPrivateKeyFingerPrint, $inPassword=null, $inOptSignaturePath=null) {

        $input = tempnam(sys_get_temp_dir(), 'Gpg::signString::');
        if (false === file_put_contents($input, $inString)) {
            throw new \Exception("Can not write data into temporary file \"$input\"");
        }

        $result = self::detachSignFile($input, $inPrivateKeyFingerPrint, $inPassword, $inOptSignaturePath);

        if (false === unlink($input)) {
            throw new \Exception("Can not remove file \"$input\".");
        }

        return $result;
    }

    /**
     * Decrypt a file.
     * @param string $inAbsolutePath Path to the file to decrypt.
     * @param string|null $inOptPassword Password for the private key that will be used to decrypt the file.
     *        This parameter may be null if no password is needed.
     *        Please note that while signing may require a password (since it uses a private key), encrypting does not (since it uses a public key).
     *        Therefore:
     *        * while decoding a signed file, you may need to specify a password.
     *        * while decoding an encrypted file, you don't need to specify a password.
     * @param string|null $inOptOutputFile Path to the decrypted file.
     *        If the value of this parameter is null, then the decrypted file is returned as a string.
     * @return true|string Upon successful completion:
     *         If a destination file has been specified, then the method returns the value true.
     *         Otherwise, the method returns a string that represents the signature.
     * @throws \Exception
     * @note Commands:
     *       ## Encrypt a file:
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --armor -u 03DEC874738344206A1A7D31E07D9D14954C8DC5 --output encrypted_file --sign file_to_sign.txt; echo $?; exec 3>&-
     *       or
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --always-trust --armor --output encrypted_file --encrypt --recipient 03DEC874738344206A1A7D31E07D9D14954C8DC5 file_to_sign.txt; echo $?; exec 3>&-
     *       ## Then decrypt it:
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --output decrypted_file --decrypt encrypted_file; echo $?; exec 3>&-
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --output - --decrypt encrypted_file; echo $?; exec 3>&-
     *       SUCCESS: /tmp/status contains:
     *
     *                If we decrypt a signed file (using a private key):
     *                [GNUPG:] PLAINTEXT 62 1482579714 file_to_sign.txt
     *                [GNUPG:] PLAINTEXT_LENGTH 22
     *                [GNUPG:] SIG_ID cABJ71ZaLdgq0OBEEeAxYV3Frfg 2016-12-24 1482579714
     *                [GNUPG:] GOODSIG E07D9D14954C8DC5 open key <ok@test.com>
     *                [GNUPG:] VALIDSIG 03DEC874738344206A1A7D31E07D9D14954C8DC5 2016-12-24 1482579714 0 4 0 1 2 00 03DEC874738344206A1A7D31E07D9D14954C8DC5
     *                [GNUPG:] TRUST_UNDEFINED
     *
     *                If we decrypt an encrypted file (using a public key):
     *                [GNUPG:] ENC_TO 0C185D728E760EC0 1 0
     *                [GNUPG:] GOOD_PASSPHRASE
     *                [GNUPG:] BEGIN_DECRYPTION
     *                [GNUPG:] DECRYPTION_INFO 2 9
     *                [GNUPG:] PLAINTEXT 62 1482586001 file_to_sign.txt
     *                [GNUPG:] PLAINTEXT_LENGTH 19315
     *                [GNUPG:] DECRYPTION_OKAY
     *                [GNUPG:] GOODMDC
     *                [GNUPG:] END_DECRYPTION
     *
     *                And the status returned by the command is 0.
     *       ERROR:   /tmp/status may be empty, ot it may contain lines. For example:
     *                [GNUPG:] NODATA 3  // the encrypted file was corrupted.
     *                And the status returned by the command is not 0.
     *
     *       => To decide whether the command was successful or not, we look at the status returned by the command.
     *          On success, its value should be 0.
     */
    static public function decryptFile($inAbsolutePath, $inOptPassword=null, $inOptOutputFile=null) {

        $inAbsolutePath = realpath($inAbsolutePath);
        $inOptOutputFile = is_null($inOptOutputFile) ? null : $inOptOutputFile;

        $cmd = array(
            '--decrypt',
            escapeshellarg($inAbsolutePath)
        );

        $result = self::__exec($cmd, $inOptOutputFile, $inOptPassword);
        $status = $result[self::KEY_COMMAND_RETURN_CODE];

        if (0 != $status) {
            throw new \Exception("The command \"" . $result[self::KEY_COMMAND] . "\" failed. Execution status is $status.");
        }

        if (! is_null($inOptOutputFile)) {
            // The result should be in the file which path is $inOptOutputFile.
            return true;
        }

        // Return the result as a string.
        return $result[self::KEY_COMMAND_OUTPUT];
    }

    /**
     * Decrypt a string.
     * @param string $inString String to decode.
     * @param string|null $inOptPassword Password for the private key that will be used to decrypt the file.
     *        This parameter may be null if no password is needed.
     *        Please note that while signing may require a password (since it uses a private key), encrypting does not (since it uses a public key).
     *        Therefore:
     *        * while decoding a signed string, you may need to specify a password.
     *        * while decoding an encrypted file, you don't need to specify a password.
     * @param string|null $inOptOutputFile Path to the decrypted file.
     *        If the value of this parameter is null, then the decrypted file is returned as a string.
     * @return true|string Upon successful completion:
     *         If a destination file has been specified, then the method returns the value true.
     *         Otherwise, the method returns a string that represents the signature.
     * @throws \Exception
     */
    static public function decryptString($inString, $inOptPassword=null, $inOptOutputFile=null) {
        $input = tempnam(sys_get_temp_dir(), 'Gpg::decryptString::');
        if (false === file_put_contents($input, $inString)) {
            throw new \Exception("Can not write data into temporary file \"$input\"");
        }

        $result = self::decryptFile($input, $inOptPassword, $inOptOutputFile);

        if (false === unlink($input)) {
            throw new \Exception("Can not remove file \"$input\".");
        }

        return $result;
    }

    /**
     * Cypher a given file using a given public key, identified by its fingerprint.
     * @param string $inInputPath Path to the input file to cypher.
     * @param string $inPublicKeyFingerPrint Fingerprint of the public key to use.
     * @param null|string $inOptOutputFile Path the the file used to store the generated signature.
     * @return true|string Upon successful completion:
     *         If a destination file has been specified, then the method returns the value true.
     *         Otherwise, the method returns a string that represents the encrypted file.
     * @note Commands:
     *       gpg --list-keys --fingerprint --with-colon
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --always-trust --armor --output encrypted_file --encrypt --recipient 03DEC874738344206A1A7D31E07D9D14954C8DC5 file_to_sign.txt; echo $?; exec 3>&-
     *       exec 3> /tmp/status; gpg --batch --yes --status-fd 3 --always-trust --armor --output - --encrypt --recipient 03DEC874738344206A1A7D31E07D9D14954C8DC5 file_to_sign.txt; echo $?; exec 3>&-
     *       SUCCESS: /tmp/status contains:
     *                [GNUPG:] BEGIN_ENCRYPTION 2 9
     *                [GNUPG:] END_ENCRYPTION
     *                And the status returned by the command is 0.
     *       ERROR:   /tmp/status may be empty, ot it may contain lines. For example:
     *                [GNUPG:] INV_RECP 0 03DEC874738344206A1A7D31E07D9D14954C8DC
     *                And the status returned by the command is not 0.
     *
     *       => To decide whether the command was successful or not, we look at the status returned by the command.
     *          On success, its value should be 0.
     *
     * @throws \Exception
     */
    static public function encryptAsymmetricFile($inInputPath, $inPublicKeyFingerPrint, $inOptOutputFile=null) {

        $cmd = array(
            '--always-trust',
            '--armor',
            '--encrypt',
            '--recipient',
            escapeshellarg($inPublicKeyFingerPrint),
            escapeshellarg($inInputPath)
        );

        $result = self::__exec($cmd, $inOptOutputFile, null);
        $status = $result[self::KEY_COMMAND_RETURN_CODE];

        if (0 != $status) {
            throw new \Exception("The command \"" . $result[self::KEY_COMMAND] . "\" failed. Execution status is $status.");
        }

        if (! is_null($inOptOutputFile)) {
            // The result should be in the file which path is $inOptOutputFile.
            return true;
        }

        // Return the result as a string.
        return $result[self::KEY_COMMAND_OUTPUT];
    }

    /**
     * Cypher a given string using a given public key, identified by its fingerprint.
     * @param string $inString String to cypher.
     * @param string $inPublicKeyFingerPrint Fingerprint of the public key to use.
     * @param null|string $inOptOutputFile Path the the file used to store the generated signature.
     * @return true|string If an output file has been specified, then the method returns the value true.
     *         Otherwise, the method returns the encrypted string.
     * @throws \Exception
     */
    static public function encryptAsymmetricString($inString, $inPublicKeyFingerPrint, $inOptOutputFile=null) {

        $input = tempnam(sys_get_temp_dir(), 'Gpg::encryptAsymmetricString::');
        if (false === file_put_contents($input, $inString)) {
            throw new \Exception("Can not write data into temporary file \"$input\"");
        }

        $result = Gpg::encryptAsymmetricFile($input, $inPublicKeyFingerPrint, $inOptOutputFile);

        if (false === unlink($input)) {
            throw new \Exception("Can not remove file \"$input\".");
        }

        return $result;
    }

    /**
     * Process the output of the following commands:
     * * gpg --batch --list-keys --fingerprint --with-colon "public key"
     * * gpg --batch --list-secret-keys --fingerprint --with-colon "private key"
     * @param array $inOutput Array that contains the output of the command.
     * @return array The method returns an array that contains the following keys:
     *         * Gpg::KEY_STATUS: status of the action. The value may be:
     *           * Gpg::STATUS_KEY_PRESENT: the key was found.
     *           * Gpg::STATUS_KEY_ABSENT: the key was not found.
     *           * Gpg::STATUS_ERROR: an error occurred.
     *         * Gpg::KEY_DATA: the data (if any).
     *           * If the key was found (status is Gpg::STATUS_KEY_PRESENT), then the value is the fingerprint.
     *           * In all other cases, the value is null.
     * @see Gpg::KEY_STATUS
     * @see Gpg::KEY_DATA
     * @see Gpg::STATUS_KEY_PRESENT
     * @see Gpg::STATUS_KEY_ABSENT
     * @see Gpg::STATUS_ERROR
     */
    static private function __getKeyFingerPrintData(array $inOutput) {
        foreach ($inOutput as $_line) {

            $matches = array();
            if (1 === preg_match('/^fpr:+([0-9A-F]+)/', $_line, $matches)) {
                return array(
                    self::KEY_STATUS => self::STATUS_KEY_PRESENT,
                    self::KEY_DATA => $matches[1]
                );
            }

            if (1 === preg_match('/^gpg: error reading key: public key not found/', $_line)) {
                return array(
                    self::KEY_STATUS => self::STATUS_KEY_ABSENT,
                    self::KEY_DATA => null
                );
            }

            if (1 === preg_match('/^gpg: error reading key: secret key not available/', $_line)) {
                return array(
                    self::KEY_STATUS => self::STATUS_KEY_ABSENT,
                    self::KEY_DATA => null
                );
            }
        }
        return array(
            self::KEY_STATUS => self::STATUS_ERROR,
            self::KEY_DATA => null
        );
    }

    /**
     * Process the output of the following commands, in the event where the status of the command is 2.
     * This should mean that the key is not in the keyring.
     * * gpg --batch --list-secret-keys "my private key"
     * * gpg --list-keys "my public key"
     * @param array $inOutput Array that contains the output of the command.
     * @return int If the key is in the keyring, then the method returns the value Gpg::STATUS_KEY_PRESENT.
     *         Otherwise, it returns the value Gpg::STATUS_KEY_ABSENT.
     * @see Gpg::STATUS_KEY_ABSENT
     * @see Gpg::STATUS_ERROR
     */
    static private function __getListKeysStatus(array $inOutput) {
        foreach ($inOutput as $_line) {
            if (1 === preg_match('/^gpg: error reading key: public key not found/i', $_line)) {
                return self::STATUS_KEY_ABSENT;
            }

            if (1 === preg_match('/^gpg: error reading key: secret key not available/i', $_line)) {
                return self::STATUS_KEY_ABSENT;
            }
        }
        return self::STATUS_ERROR;
    }

    /**
     * Process the output of the following commands, in the event where the status of the command is 2.
     * * gpg --batch --yes --delete-secret-keys "881C41F8B8FD138E86E7230929A778386005B911"
     * * gpg --batch --yes --delete-keys "881C41F8B8FD138E86E7230929A778386005B911"
     * @param array $inOutPut Array that contains the output of the command.
     * @param string $outError Reference to a string used to store an error message, if necessary.
     * @return int If the removal succeed, then the method returns the value Gpg::STATUS_SUCCESS.
     *         Otherwise, the method returns the value Gpg::STATUS_ERROR.
     * @see Gpg::STATUS_SUCCESS
     * @see Gpg::STATUS_ERROR
     */
    static private function __getRemoveKeyStatus(array $inOutPut, &$outError) {

        $outError = null;

        foreach ($inOutPut as $_line) {

            $matches = array();
            if (preg_match('/^\[GNUPG:\]\s+DELETE_PROBLEM\s+(\d+)\s*$/i', $_line, $matches)) {

                $code = $matches[1];

                if (1 == $code) {
                    $outError = "The specified key does not exist.";
                    return self::STATUS_SUCCESS;
                }

                switch ($code) {
                    case 2: $outError = 'The private key must be deleted first'; return self::STATUS_ERROR;
                    case 3: $outError = 'Ambigious specification'; return self::STATUS_ERROR;
                    case 4: $outError = 'The specified key is stored on a smartcard'; return self::STATUS_ERROR;
                }
            }
        }

        return self::STATUS_ERROR;
    }

    /**
     * Process the output of the following commands, in the event where the status of the command is 2.
     * * gpg --batch --import key.prv
     * @param array $inOutput Array that contains the output of the command.
     * @return bool If the key already was in the keyring, then the method returns the value true.
     *         Otherwise, it returns the value false.
     * @note Please note that this function only works for private keys.
     */
    static private function __getImportPrivateKeyStatus(array $inOutput) {
        foreach ($inOutput as $_line) {
            if (preg_match('/^\[GNUPG:\]\s+IMPORT_OK\s+/i', $_line)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Process the output of the following commands:
     * gpg --batch --yes --status-fd 3 --armor -u 03DEC874738344206A1A7D31E07D9D14954C8DC5 --output file_to_sign.sig --sign file_to_sign.txt
     * @param array $inStatusFdFile This array contains the files extracted from the file which file descriptor is specified by the option "--status-fd".
     * @return bool If the command was successful, then the method returns the value true.
     *         Otherwise, it returns the value false.
     */
    static private function __getSignFileStatus(array $inStatusFdFile) {
        foreach ($inStatusFdFile as $_line) {
            if (preg_match('/^\[GNUPG:\]\s+SIG_CREATED\s+/i', $_line)) {
                return true;
            }
        }
        return false;
    }

    /**
     * This method scans the "status file" produced by the GPG execution in order to find out the status of the signature verification.
     * @param array $inStatusFileContent Array that contains the content of the "status file".
     * @param string $outWarning Reference to a string used to store a warning message.
     * @return int The method may return one of the following value:
     *         Gpg::STATUS_SIG_VALID
     *         Gpg::STATUS_SIG_VALID_BUT_WARNING
     *         Gpg::STATUS_SIG_INVALID
     *         Gpg::STATUS_SIG_ERROR
     * @see Gpg::STATUS_SIG_VALID
     * @see Gpg::STATUS_SIG_VALID_BUT_WARNING
     * @see Gpg::STATUS_SIG_INVALID
     * @see Gpg::STATUS_SIG_ERROR
     */
    static private function __getVerifySignatureStatus(array $inStatusFileContent, &$outWarning) {

        $outWarning = null;
        foreach ($inStatusFileContent as $_line) {

            if (1 === preg_match('/^\[GNUPG:\]\s+VALIDSIG\s+/', $_line)) {
                return self::STATUS_SIG_VALID;
            }

            if (1 === preg_match('/^\[GNUPG:\]\s+GOODSIG\s+/', $_line)) {
                return self::STATUS_SIG_VALID;
            }

            if (1 === preg_match('/^\[GNUPG:\]\s+EXPSIG\s+/', $_line)) {
                $outWarning = 'The signature is good, but the signature is expired.';
                return self::STATUS_SIG_VALID_BUT_WARNING;
            }

            if (1 === preg_match('/^\[GNUPG:\]\s+EXPKEYSIG\s+/', $_line)) {
                $outWarning = 'The signature is good, but the signature was made by an expired key.';
                return self::STATUS_SIG_VALID_BUT_WARNING;
            }

            if (1 === preg_match('/^\[GNUPG:\]\s+REVKEYSIG\s+/', $_line)) {
                $outWarning = 'The signature is good, but the signature was made by a revoked key.';
                return self::STATUS_SIG_VALID_BUT_WARNING;
            }

            if (1 === preg_match('/^\[GNUPG:\]\s+BADSIG\s+/', $_line)) {
                return self::STATUS_SIG_INVALID;
            }

            if (1 === preg_match('/^\[GNUPG:\]\s+ERRSIG\s+/', $_line)) {
                return self::STATUS_SIG_ERROR;
            }
        }

        return self::STATUS_SIG_ERROR;
    }

    /**
     * Execute a GPG command line.
     * @param array $inCliArguments Command line arguments.
     * @param null $inOptOutputFile Optional output file.
     * @param null $inOptPassword Optional password (used when secret keys are manipulated).
     * @return array The method returns an array that represents the status of the execution.
     * @throws \Exception
     */
    static private function __exec(array $inCliArguments, $inOptOutputFile=null, $inOptPassword=null) {

        // Create the temporary file used to store status information.
        $tempStatusFilePath = tempnam(sys_get_temp_dir(), 'Gpg-Status-File::');

        // Create the file used to store the command's output.
        // This file may be a temporary file.
        $tempCommandOutputPath = is_null($inOptOutputFile) ? tempnam(sys_get_temp_dir(), 'Gpg-Output::') :
            $inOptOutputFile;

        // Create the temporary file used to store the command's status code.
        $tempCommandStatusCode = tempnam(sys_get_temp_dir(), 'Gpg-Status-Code::');

        // Prepare and execute the command.
        $cmd = array(
            'exec',
            '3>',
            escapeshellarg($tempStatusFilePath),
            ';'
        );

        if (! is_null($inOptPassword)) {
            $cmd[] = 'echo';
            $cmd[] = escapeshellarg($inOptPassword);
            $cmd[] = '|';
        }

        $cmd[] = self::EXE_GPG;
        $cmd[] = '--batch';
        $cmd[] = '--yes';
        $cmd[] = '--always-trust';
        $cmd[] = '--output';
        $cmd[] = escapeshellarg($tempCommandOutputPath);
        $cmd[] = '--status-fd';
        $cmd[] = '3';

        if (! is_null($inOptPassword)) {
            $cmd[] = '--passphrase-fd';
            $cmd[] = '0';
        }

        $cmd = array_merge($cmd, $inCliArguments, array(
            '2>&1',
            ';',
            'echo',
            '$?',
            '>',
            escapeshellarg($tempCommandStatusCode),
            ';',
            'exec',
            '3>&-')
        );

        $output = array();
        $status = null; // This value is not interesting.
        $cmd = implode(' ', $cmd);

        // print "\n$cmd\n"; flush();

        exec($cmd, $output, $status);

        // Load the output and the status.
        if (false === $outputFromFile = file_get_contents($tempCommandOutputPath)) {
            throw new \Exception("The command below failed:\n$cmd\n\n.Can not load the content of the file that contains the output of the command (\"$tempCommandOutputPath\").");
        }

        if (false === $statusFromFile = file_get_contents($tempStatusFilePath)) {
            throw new \Exception("The command below failed:\n$cmd\n\n.Can not load the content of the file that contains the execution status of the command (\"$tempStatusFilePath\").");
        }

        if (false === $statusCode = file_get_contents($tempCommandStatusCode)) {
            throw new \Exception("The command below failed:\n$cmd\n\n.Can not load the content of the file that contains the execution status code of the command (\"$tempCommandStatusCode\").");
        }

        $statusCode = trim($statusCode);
        if (! preg_match('/^\d+$/', $statusCode)) {
            throw new \Exception("The command below failed:\n$cmd\n\n. This status code stored in the file \"$tempCommandStatusCode\" is not an integer!.");
        }
        $statusCode = intval($statusCode);

        self::__unlink($tempStatusFilePath);
        if (is_null($inOptOutputFile)) {
            self::__unlink($tempCommandOutputPath);
        }
        self::__unlink($tempCommandStatusCode);

        // Return the data.
        return array(
            self::KEY_COMMAND_STATUS_FILE => $statusFromFile,
            self::KEY_COMMAND_OUTPUT           => $outputFromFile,
            self::KEY_COMMAND_RETURN_CODE      => $statusCode,
            self::KEY_COMMAND_STDOUT           => $output,
            self::KEY_COMMAND                  => $cmd
        );
    }

    private function __unlink($inPath) {
        if (file_exists($inPath)) {
            if (false === unlink($inPath)) {
                throw new \Exception("Can not delete the file <$inPath>");
            }
        }
    }


}