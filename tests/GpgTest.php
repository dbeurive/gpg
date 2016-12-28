<?php

// gpg --gen-key
//
// Key with a password:
//   Name: "protected key"
//   Password: "password"
//
// Key Without password:
//   Name: "open key"
//   Password: none
//
// Export all keys:
//
//   gpg --export-secret-key -a "protected key" > data/protected.prv
//   gpg --export -a "protected key" > data/protected.pub
//
//   gpg --export-secret-key -a "open key" > data/open.prv
//   gpg --export -a "open key" > data/open.pub
//
// Get the keys IDs:
//
//   gpg --keyid-format long --list-keys
//   gpg --keyid-format long --list-secret-keys
//
// Sign a file:
//
//   gpg --armor -u 'protected key' --output open.sig --sign file_to_sign.txt
//   gpg --armor -u 'open key' --output protected.sig --sign file_to_sign.txt



use dbeurive\Gpg\Gpg;

class GpgTest extends PHPUnit_Framework_TestCase
{
    private $__outputDir;
    private $__dataDir;


    static private $__data = array();
    const PASSWORD = 'password';

    public static function tearDownAfterClass()
    {
        print PHP_EOL . implode(PHP_EOL, self::$__data) . PHP_EOL;
    }

    /**
     * Load the keys into the key rings.
     */
    private function __loadKeys() {

        $privateKeyOpen      = $this->__dataDir . DIRECTORY_SEPARATOR . 'open.prv';
        $privateKeyProtected = $this->__dataDir . DIRECTORY_SEPARATOR . 'protected.prv';
        $publicKeyOpen       = $this->__dataDir . DIRECTORY_SEPARATOR . 'open.pub';
        $publicKeyProtected  = $this->__dataDir . DIRECTORY_SEPARATOR . 'protected.pub';

        $keys = array($privateKeyOpen, $privateKeyProtected, $publicKeyOpen, $publicKeyProtected);

        foreach ($keys as $_key) {
            $cmd = array(
                Gpg::EXE_GPG,
                '--import',
                escapeshellarg($_key),
                '2>&1'
            );

            $output = array();
            $status = null;
            $cmd = implode(' ', $cmd);
            exec($cmd, $output, $status);
        }
    }

    public function setUp() {
        $this->__outputDir = implode(DIRECTORY_SEPARATOR, array(__DIR__, 'output'));
        $this->__dataDir = implode(DIRECTORY_SEPARATOR, array(__DIR__, 'data'));
    }

    public function testVersion() {
        $version = Gpg::version();
        $this->assertInternalType('string', $version);
        $this->assertTrue(1 === preg_match('/^\d+\.\d+\.\d+$/', $version));
    }

    public function testCheckVersion() {
        $version = Gpg::version();

        if ('1.4.20' == $version) {
            // It has been tested.
            $this->assertTrue(Gpg::checkVersion());
        } else {
            $this->assertFalse(Gpg::checkVersion());
        }
    }

    public function testGetFingerPrint() {
        $this->__loadKeys();

        $fgp = Gpg::getPublicKeyFingerPrint('protected key');
        $this->assertInternalType('string', $fgp);
        self::$__data[] = sprintf("%-25s %s", "fgp('PUB: protected key')", $fgp);

        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $this->assertInternalType('string', $fgp);
        self::$__data[] = sprintf("%-25s %s", "fgp('PRV: protected key')", $fgp);

        $fgp = Gpg::getPublicKeyFingerPrint('open key');
        $this->assertInternalType('string', $fgp);
        self::$__data[] = sprintf("%-25s %s", "fgp('PUB: open key')", $fgp);

        $fgp = Gpg::getPrivateKeyFingerPrint('open key');
        $this->assertInternalType('string', $fgp);
        self::$__data[] = sprintf("%-25s %s", "fgp('PRV: open key')", $fgp);
    }

    public function testRemoveKey() {
        $this->__loadKeys();

        // ---------------------------------------------------------
        // Remove the private keys.
        // ---------------------------------------------------------

        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $this->assertTrue(Gpg::removePrivateKey($fgp));
        $this->assertFalse(Gpg::removePrivateKey($fgp));

        $fgp = Gpg::getPrivateKeyFingerPrint('open key');
        $this->assertTrue(Gpg::removePrivateKey($fgp));
        $this->assertFalse(Gpg::removePrivateKey($fgp));

        // ---------------------------------------------------------
        // Remove the public keys.
        // ---------------------------------------------------------

        $fgp = Gpg::getPublicKeyFingerPrint('protected key');
        $this->assertTrue(Gpg::removePublicKey($fgp));
        $this->assertFalse(Gpg::removePublicKey($fgp));

        $fgp = Gpg::getPublicKeyFingerPrint('open key');
        $this->assertTrue(Gpg::removePublicKey($fgp));
        $this->assertFalse(Gpg::removePublicKey($fgp));
    }

    public function testIsKeyPresent() {
        $this->__loadKeys();

        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $this->assertTrue(Gpg::isPublicKeyPresent($fgp));
        $this->assertTrue(Gpg::isPrivateKeyPresent($fgp));

        $fgp = Gpg::getPrivateKeyFingerPrint('open key');
        $this->assertTrue(Gpg::isPublicKeyPresent($fgp));
        $this->assertTrue(Gpg::isPrivateKeyPresent($fgp));

        // ---------------------------------------------------------
        // Remove the keys.
        // ---------------------------------------------------------

        $fgpPrivateProtected = Gpg::getPrivateKeyFingerPrint('protected key');
        $this->assertTrue(Gpg::removePrivateKey($fgpPrivateProtected));

        $fgpPrivateOpen = Gpg::getPrivateKeyFingerPrint('open key');
        $this->assertTrue(Gpg::removePrivateKey($fgpPrivateOpen));

        $fgpPublicProtected = Gpg::getPublicKeyFingerPrint('protected key');
        $this->assertTrue(Gpg::removePublicKey($fgpPublicProtected));

        $fgpPublicOpen = Gpg::getPublicKeyFingerPrint('open key');
        $this->assertTrue(Gpg::removePublicKey($fgpPublicOpen));

        // ---------------------------------------------------------
        // Test the presence of the keys again.
        // ---------------------------------------------------------

        $this->assertFalse(Gpg::isPublicKeyPresent($fgpPublicProtected));
        $this->assertFalse(Gpg::isPrivateKeyPresent($fgpPrivateProtected));

        $this->assertFalse(Gpg::isPublicKeyPresent($fgpPublicOpen));
        $this->assertFalse(Gpg::isPrivateKeyPresent($fgpPrivateOpen));
    }

    public function testImportKey() {
        $this->__loadKeys();

        // ---------------------------------------------------------
        // Remove the public keys.
        // ---------------------------------------------------------

        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $this->assertTrue(Gpg::removePrivateKey($fgp));

        $fgp = Gpg::getPrivateKeyFingerPrint('open key');
        $this->assertTrue(Gpg::removePrivateKey($fgp));

        $fgp = Gpg::getPublicKeyFingerPrint('protected key');
        $this->assertTrue(Gpg::removePublicKey($fgp));

        $fgp = Gpg::getPublicKeyFingerPrint('open key');
        $this->assertTrue(Gpg::removePublicKey($fgp));

        // ---------------------------------------------------------
        // All keys have been removed. Add them to the keyring.
        // ---------------------------------------------------------

        $this->assertTrue(Gpg::importPrivateKey($this->__dataDir . DIRECTORY_SEPARATOR . 'open.prv'));
        $this->assertTrue(Gpg::importPrivateKey($this->__dataDir . DIRECTORY_SEPARATOR . 'protected.prv'));
        $this->assertTrue(Gpg::importPublicKey($this->__dataDir . DIRECTORY_SEPARATOR . 'open.pub'));
        $this->assertTrue(Gpg::importPublicKey($this->__dataDir . DIRECTORY_SEPARATOR . 'protected.pub'));

        // ---------------------------------------------------------
        // All keys are already in the keyring. Add them again.
        // ---------------------------------------------------------

        $this->assertTrue(Gpg::importPrivateKey($this->__dataDir . DIRECTORY_SEPARATOR . 'open.prv'));
        $this->assertTrue(Gpg::importPrivateKey($this->__dataDir . DIRECTORY_SEPARATOR . 'protected.prv'));
        $this->assertTrue(Gpg::importPublicKey($this->__dataDir . DIRECTORY_SEPARATOR . 'open.pub'));
        $this->assertTrue(Gpg::importPublicKey($this->__dataDir . DIRECTORY_SEPARATOR . 'protected.pub'));
    }

    function testSignFileToFile() {
        $this->__loadKeys();

        $input = __FILE__;
        $output = $this->__outputDir . DIRECTORY_SEPARATOR . basename($input) . '.sig';

        // Sign using the password protected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $this->__unlink($output);
        $this->assertTrue(Gpg::signFile($input, $fgp, self::PASSWORD, $output));
        $this->assertFileExists($output);
        $data = file_get_contents($output);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP MESSAGE\-\-\-\-\-/', $data));

        // Sign using the unprotected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('open key');
        $this->__unlink($output);
        $this->assertTrue(Gpg::signFile($input, $fgp, null, $output));
        $this->assertFileExists($output);
        $data = file_get_contents($output);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP MESSAGE\-\-\-\-\-/', $data));
    }

    function testClearSignFileToFile() {
        $this->__loadKeys();

        $input = __FILE__;
        $output = $this->__outputDir . DIRECTORY_SEPARATOR . basename($input) . '.sig';

        // Sign using the password protected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $this->__unlink($output);
        $this->assertTrue(Gpg::clearSignFile($input, $fgp, self::PASSWORD, $output));
        $this->assertFileExists($output);
        $data = file_get_contents($output);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP SIGNED MESSAGE\-\-\-\-\-/', $data));

        // Sign using the unprotected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('open key');
        $this->__unlink($output);
        $this->assertTrue(Gpg::clearSignFile($input, $fgp, null, $output));
        $this->assertFileExists($output);
        $data = file_get_contents($output);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP SIGNED MESSAGE\-\-\-\-\-/', $data));
    }

    function testDetachSignFileToFile() {
        $this->__loadKeys();

        $input = __FILE__;
        $output = $this->__outputDir . DIRECTORY_SEPARATOR . basename($input) . '.sig';

        // Sign using the password protected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $this->__unlink($output);
        $this->assertTrue(Gpg::detachSignFile($input, $fgp, self::PASSWORD, $output));
        $this->assertFileExists($output);
        $data = file_get_contents($output);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP SIGNATURE\-\-\-\-\-/', $data));

        // Sign using the unprotected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('open key');
        $this->__unlink($output);
        $this->assertTrue(Gpg::detachSignFile($input, $fgp, null, $output));
        $this->assertFileExists($output);
        $data = file_get_contents($output);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP SIGNATURE\-\-\-\-\-/', $data));
    }

    function testSignFileToStdout() {
        $input = __FILE__;

        // Sign using the password protected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $res = Gpg::signFile($input, $fgp, self::PASSWORD, null);
        $this->assertInternalType('string', $res);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP MESSAGE\-\-\-\-\-/', $res));

        // Sign using the unprotected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('open key');
        $res = Gpg::signFile($input, $fgp, null, null);
        $this->assertInternalType('string', $res);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP MESSAGE\-\-\-\-\-/', $res));
    }

    function testClearSignFileToStdout() {
        $input = __FILE__;

        // Sign using the password protected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $res = Gpg::clearSignFile($input, $fgp, self::PASSWORD, null);
        $this->assertInternalType('string', $res);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP SIGNED MESSAGE\-\-\-\-\-/', $res));

        // Sign using the unprotected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('open key');
        $res = Gpg::clearSignFile($input, $fgp, null, null);
        $this->assertInternalType('string', $res);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP SIGNED MESSAGE\-\-\-\-\-/', $res));
    }

    function testDetachSignFileToStdout() {
        $input = __FILE__;

        // Sign using the password protected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $res = Gpg::detachSignFile($input, $fgp, self::PASSWORD, null);
        $this->assertInternalType('string', $res);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP SIGNATURE\-\-\-\-\-/', $res));

        // Sign using the unprotected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('open key');
        $res = Gpg::detachSignFile($input, $fgp, null, null);
        $this->assertInternalType('string', $res);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP SIGNATURE\-\-\-\-\-/', $res));
    }

    public function testSignStringToFile() {
        $this->__loadKeys();

        $output = $this->__outputDir . DIRECTORY_SEPARATOR . basename(__FILE__) . '.sig';

        // Sign using the password protected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $this->__unlink($output);
        $this->assertTrue(Gpg::signString('AZERTY', $fgp, self::PASSWORD, $output));
        $this->assertFileExists($output);
        $data = file_get_contents($output);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP MESSAGE\-\-\-\-\-/', $data));

        // Sign using the unprotected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('open key');
        $this->__unlink($output);
        $this->assertTrue(Gpg::signString('AZERTY', $fgp, null, $output));
        $this->assertFileExists($output);
        $data = file_get_contents($output);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP MESSAGE\-\-\-\-\-/', $data));
    }

    public function testClearSignStringToFile() {
        $this->__loadKeys();

        $output = $this->__outputDir . DIRECTORY_SEPARATOR . basename(__FILE__) . '.sig';

        // Sign using the password protected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $this->__unlink($output);
        $this->assertTrue(Gpg::clearSignString('AZERTY', $fgp, self::PASSWORD, $output));
        $this->assertFileExists($output);
        $data = file_get_contents($output);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP SIGNED MESSAGE\-\-\-\-\-/', $data));

        // Sign using the unprotected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('open key');
        $this->__unlink($output);
        $this->assertTrue(Gpg::clearSignString('AZERTY', $fgp, null, $output));
        $this->assertFileExists($output);
        $data = file_get_contents($output);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP SIGNED MESSAGE\-\-\-\-\-/', $data));
    }

    public function testDetachSignStringToFile() {
        $this->__loadKeys();

        $output = $this->__outputDir . DIRECTORY_SEPARATOR . basename(__FILE__) . '.sig';

        // Sign using the password protected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $this->__unlink($output);
        $this->assertTrue(Gpg::detachSignString('AZERTY', $fgp, self::PASSWORD, $output));
        $this->assertFileExists($output);
        $data = file_get_contents($output);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP SIGNATURE\-\-\-\-\-/', $data));

        // Sign using the unprotected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('open key');
        $this->__unlink($output);
        $this->assertTrue(Gpg::detachSignString('AZERTY', $fgp, null, $output));
        $this->assertFileExists($output);
        $data = file_get_contents($output);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP SIGNATURE\-\-\-\-\-/', $data));
    }

    public function testSignStringToString()
    {
        $this->__loadKeys();

        // Sign using the password protected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $string = Gpg::signString('AZERTY', $fgp, self::PASSWORD, null);
        $this->assertInternalType('string', $string);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP MESSAGE\-\-\-\-\-/', $string));

        // Sign using the unprotected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('open key');
        $string = Gpg::signString('AZERTY', $fgp, null, null);
        $this->assertInternalType('string', $string);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP MESSAGE\-\-\-\-\-/', $string));
    }

    public function testClearSignStringToString()
    {
        $this->__loadKeys();

        // Sign using the password protected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $string = Gpg::clearSignString('AZERTY', $fgp, self::PASSWORD, null);
        $this->assertInternalType('string', $string);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP SIGNED MESSAGE\-\-\-\-\-/', $string));

        // Sign using the unprotected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('open key');
        $string = Gpg::clearSignString('AZERTY', $fgp, null, null);
        $this->assertInternalType('string', $string);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP SIGNED MESSAGE\-\-\-\-\-/', $string));
    }

    public function testDetachSignStringToString()
    {
        $this->__loadKeys();

        // Sign using the password protected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $string = Gpg::detachSignString('AZERTY', $fgp, self::PASSWORD, null);
        $this->assertInternalType('string', $string);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP SIGNATURE\-\-\-\-\-/', $string));

        // Sign using the unprotected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('open key');
        $string = Gpg::detachSignString('AZERTY', $fgp, null, null);
        $this->assertInternalType('string', $string);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP SIGNATURE\-\-\-\-\-/', $string));
    }

    public function testEncryptToFile() {
        $this->__loadKeys();
        $input = __FILE__;
        $output = $this->__outputDir . DIRECTORY_SEPARATOR . basename($input) . '.sig';

        $fgp = Gpg::getPublicKeyFingerPrint('open key');
        $this->__unlink($output);
        $this->assertTrue(Gpg::encryptAsymmetricFile($input, $fgp, $output));
        $this->assertFileExists($output);
        $data = file_get_contents($output);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP MESSAGE\-\-\-\-\-/', $data));
    }

    public function testEncryptToStdout() {
        $this->__loadKeys();
        $input = __FILE__;
        $output = $this->__outputDir . DIRECTORY_SEPARATOR . basename($input) . '.sig';

        $fgp = Gpg::getPublicKeyFingerPrint('open key');
        $this->__unlink($output);
        $string = Gpg::encryptAsymmetricFile($input, $fgp);
        $this->assertInternalType('string', $string);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP MESSAGE\-\-\-\-\-/', $string));
    }

    public function testEncryptAsymmetricStringToFile() {
        $this->__loadKeys();
        $output = $this->__outputDir . DIRECTORY_SEPARATOR . basename(__FILE__) . '.gpg';

        $fgp = Gpg::getPublicKeyFingerPrint('open key');
        $this->__unlink($output);
        $this->assertTrue(Gpg::encryptAsymmetricString('AZERTY', $fgp, $output));
        $this->assertFileExists($output);
        $data = file_get_contents($output);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP MESSAGE\-\-\-\-\-/', $data));
    }

    public function testEncryptAsymmetricStringToString() {
        $this->__loadKeys();

        $fgp = Gpg::getPublicKeyFingerPrint('open key');
        $string = Gpg::encryptAsymmetricString('AZERTY', $fgp, null);
        $this->assertInternalType('string', $string);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP MESSAGE\-\-\-\-\-/', $string));
    }

    public function testDecryptSignedFile() {
        $this->__loadKeys();

        // ---------------------------------------------------------
        // Start by signing a file.
        // ---------------------------------------------------------

        $input = __FILE__;
        $encryptedFile = $this->__outputDir . DIRECTORY_SEPARATOR . basename($input) . '.sig';

        // Sign using the password protected private key.
        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $this->__unlink($encryptedFile);
        $this->assertTrue(Gpg::signFile($input, $fgp, self::PASSWORD, $encryptedFile));
        $this->assertFileExists($encryptedFile);
        $data = file_get_contents($encryptedFile);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP MESSAGE\-\-\-\-\-/', $data));

        // ---------------------------------------------------------
        // Then decrypt the file.
        // ---------------------------------------------------------

        $decryptedFile = $this->__outputDir . DIRECTORY_SEPARATOR . basename(__FILE__) . '.clr';
        $this->__unlink($decryptedFile);
        $this->assertTrue(Gpg::decryptFile($encryptedFile, null, $decryptedFile));
        $this->assertFileExists($decryptedFile);

        // ---------------------------------------------------------
        // And compare the decrypted file with the original.
        // ---------------------------------------------------------

        $this->assertFileEquals(__FILE__, $decryptedFile);

        // ---------------------------------------------------------
        // Do the same test, but while returning a string.
        // ---------------------------------------------------------

        $string = Gpg::decryptFile($encryptedFile, null, null);
        if (false === $original = file_get_contents(__FILE__)) {
            throw new \Exception("Can not read file " . __FILE__);
        }

        $this->assertEquals($original, $string);

        $this->__unlink($encryptedFile);
        $this->__unlink($decryptedFile);
    }

    public function testDecryptEncryptedFile() {

        $this->__loadKeys();

        // ---------------------------------------------------------
        // Start by encrypting a file.
        // ---------------------------------------------------------

        $input = __FILE__;
        $encryptedFile = $this->__outputDir . DIRECTORY_SEPARATOR . basename($input) . '.cry';

        // Sign using the password protected private key.
        $fgp = Gpg::getPublicKeyFingerPrint('protected key');
        $this->__unlink($encryptedFile);
        $this->assertTrue(Gpg::encryptAsymmetricFile($input, $fgp, $encryptedFile));
        $this->assertFileExists($encryptedFile);
        $data = file_get_contents($encryptedFile);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP MESSAGE\-\-\-\-\-/', $data));

        // ---------------------------------------------------------
        // Then decrypt the file.
        // ---------------------------------------------------------

        $decryptedFile = $this->__outputDir . DIRECTORY_SEPARATOR . basename(__FILE__) . '.clr';
        $this->__unlink($decryptedFile);
        $this->assertTrue(Gpg::decryptFile($encryptedFile, self::PASSWORD, $decryptedFile));
        $this->assertFileExists($decryptedFile);

        // ---------------------------------------------------------
        // And compare the decrypted file with the original.
        // ---------------------------------------------------------

        $this->assertFileEquals(__FILE__, $decryptedFile);

        // ---------------------------------------------------------
        // Do the same test, but while returning a string.
        // ---------------------------------------------------------

        $string = Gpg::decryptFile($encryptedFile, self::PASSWORD, null);
        if (false === $original = file_get_contents(__FILE__)) {
            throw new \Exception("Can not read file " . __FILE__);
        }

        $this->assertEquals($original, $string);

        $this->__unlink($encryptedFile);
        $this->__unlink($decryptedFile);
    }


    public function testDecryptEncryptedString() {

        $this->__loadKeys();

        // ---------------------------------------------------------
        // Start by encrypting a file.
        // ---------------------------------------------------------

        $input = __FILE__;
        $encryptedFile = $this->__outputDir . DIRECTORY_SEPARATOR . basename($input) . '.cry';

        // Sign using the password protected private key.
        $fgp = Gpg::getPublicKeyFingerPrint('protected key');
        $this->__unlink($encryptedFile);
        $this->assertTrue(Gpg::encryptAsymmetricFile($input, $fgp, $encryptedFile));
        $this->assertFileExists($encryptedFile);
        $data = file_get_contents($encryptedFile);
        $this->assertTrue(1 === preg_match('/^\-\-\-\-\-BEGIN PGP MESSAGE\-\-\-\-\-/', $data));

        // ---------------------------------------------------------
        // Load the content of the file.
        // ---------------------------------------------------------

        if (false === $encryptedString = file_get_contents($encryptedFile)) {
            throw new \Exception("Can not read file " . $encryptedFile);
        }

        // ---------------------------------------------------------
        // The decrypt the string
        // ---------------------------------------------------------

        $decryptedFile = $this->__outputDir . DIRECTORY_SEPARATOR . basename(__FILE__) . '.clr';
        $this->__unlink($decryptedFile);
        $this->assertTrue(Gpg::decryptString($encryptedString, self::PASSWORD, $decryptedFile));
        $this->assertFileEquals(__FILE__, $decryptedFile);

        // ---------------------------------------------------------
        // Do the same test, but while returning a string.
        // ---------------------------------------------------------

        $string = Gpg::decryptString($encryptedString, self::PASSWORD, null);
        $this->assertInternalType('string', $string);
        if (false === $original = file_get_contents(__FILE__)) {
            throw new \Exception(__FILE__);
        }

        $this->assertEquals($original, $string);

        $this->__unlink($encryptedFile);
        $this->__unlink($decryptedFile);
    }

    public function testVerifyClearSignFile() {

        $this->__loadKeys();

        // ---------------------------------------------------------
        // Start by clear signing a file.
        // ---------------------------------------------------------

        $input = __FILE__;
        $clearSignatureFile = $this->__outputDir . DIRECTORY_SEPARATOR . basename($input) . '.sig';
        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $this->__unlink($clearSignatureFile);
        $this->assertTrue(Gpg::clearSignFile($input, $fgp, self::PASSWORD, $clearSignatureFile));

        // ---------------------------------------------------------
        // Now, verify the signature.
        // ---------------------------------------------------------

        $warning = null;
        $this->assertTrue(Gpg::verifyClearSignedFile($clearSignatureFile, $warning));
        $this->assertNull($warning);

        // ---------------------------------------------------------
        // Let modify the signature file, so the signature is not
        // valid.
        // ---------------------------------------------------------

        // The two first lines of the file should be:
        // -----BEGIN PGP SIGNED MESSAGE-----
        // Hash: SHA1

        if (false === $signature = file_get_contents($clearSignatureFile)) {
            throw new \Exception("Can not load file \"$clearSignatureFile\".");
        }

        $temp = tempnam(sys_get_temp_dir(), 'GpgTest::');
        $lines = explode(PHP_EOL, $signature);
        array_splice($lines, 5, 0, array('toto'));
        file_put_contents($temp, implode(PHP_EOL, $lines));

        // ---------------------------------------------------------
        // Now, verify the signature. It should be invalid.
        // ---------------------------------------------------------

        $warning = null;
        $this->assertFalse(Gpg::verifyClearSignedFile($temp, $warning));
        $this->assertNull($warning);

        $this->__unlink($temp);
        $this->__unlink($clearSignatureFile);
    }

    public function testVerifyClearSignString() {

        $this->__loadKeys();

        // ---------------------------------------------------------
        // Start by clear signing a file.
        // ---------------------------------------------------------

        $input = __FILE__;
        $clearSignatureFile = $this->__outputDir . DIRECTORY_SEPARATOR . basename($input) . '.sig';
        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $this->__unlink($clearSignatureFile);
        $this->assertTrue(Gpg::clearSignFile($input, $fgp, self::PASSWORD, $clearSignatureFile));

        // ---------------------------------------------------------
        // Load the signature.
        // ---------------------------------------------------------

        if (false === $signature = file_get_contents($clearSignatureFile)) {
            throw new \Exception("Can not load file \"$clearSignatureFile\".");
        }

        // ---------------------------------------------------------
        // Now, verify the signature.
        // ---------------------------------------------------------

        $warning = null;
        $this->assertTrue(Gpg::verifyClearSignedString($signature, $warning));
        $this->assertNull($warning);

        // ---------------------------------------------------------
        // Let modify the signature, so the signature is not
        // valid.
        // ---------------------------------------------------------

        // The two first lines of the file should be:
        // -----BEGIN PGP SIGNED MESSAGE-----
        // Hash: SHA1

        if (false === $signature = file_get_contents($clearSignatureFile)) {
            throw new \Exception("Can not load file \"$clearSignatureFile\".");
        }

        $lines = explode(PHP_EOL, $signature);
        array_splice($lines, 5, 0, array('toto'));
        $signature = implode(PHP_EOL, $lines);

        // ---------------------------------------------------------
        // Now, verify the signature. It should be invalid.
        // ---------------------------------------------------------

        $warning = null;
        $this->assertFalse(Gpg::verifyClearSignedString($signature, $warning));
        $this->assertNull($warning);

        $this->__unlink($clearSignatureFile);
    }

    public function testVerifyClearSignFileError() {

        $this->__loadKeys();

        // ---------------------------------------------------------
        // Start by clear signing a file.
        // ---------------------------------------------------------

        $input = __FILE__;
        $clearSignatureFile = $this->__outputDir . DIRECTORY_SEPARATOR . basename($input) . '.sig';
        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $this->__unlink($clearSignatureFile);
        $this->assertTrue(Gpg::clearSignFile($input, $fgp, self::PASSWORD, $clearSignatureFile));

        // ---------------------------------------------------------
        // Let modify the signature file, so the format of the file
        // is not valid. We remove the last line of the file...
        // ---------------------------------------------------------

        if (false === $signature = file_get_contents($clearSignatureFile)) {
            throw new \Exception("Can not load file \"$clearSignatureFile\".");
        }

        $temp = tempnam(sys_get_temp_dir(), 'GpgTest::');
        $lines = explode(PHP_EOL, $signature);
        array_pop($lines);
        array_pop($lines);
        file_put_contents($temp, implode(PHP_EOL, $lines));

        // ---------------------------------------------------------
        // Now, verify the signature. It should throw an error.
        // ---------------------------------------------------------

        $warning = null;
        $this->expectException(\Exception::class);
        Gpg::verifyClearSignedFile($temp, $warning);
    }

    public function testVerifyDetachSignFile()
    {

        $this->__loadKeys();

        // ---------------------------------------------------------
        // Start by detach signing a file.
        // ---------------------------------------------------------

        $input = __FILE__;
        $detachedSignatureFile = $this->__outputDir . DIRECTORY_SEPARATOR . basename($input) . '.sig';
        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $this->__unlink($detachedSignatureFile);
        $this->assertTrue(Gpg::detachSignFile($input, $fgp, self::PASSWORD, $detachedSignatureFile));

        // ---------------------------------------------------------
        // Now, verify the signature.
        // ---------------------------------------------------------

        $warning = null;
        $this->assertTrue(Gpg::verifyDetachedSignedFile($detachedSignatureFile, $input, $warning));
        $this->assertNull($warning);
    }

    public function testVerifyDetachSignString()
    {

        $this->__loadKeys();

        // ---------------------------------------------------------
        // Start by detach signing a file.
        // ---------------------------------------------------------

        $input = __FILE__;
        $detachedSignatureFile = $this->__outputDir . DIRECTORY_SEPARATOR . basename($input) . '.sig';
        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $this->__unlink($detachedSignatureFile);
        $this->assertTrue(Gpg::detachSignFile($input, $fgp, self::PASSWORD, $detachedSignatureFile));

        // ---------------------------------------------------------
        // Load the signature.
        // ---------------------------------------------------------

        if (false === $signature = file_get_contents($detachedSignatureFile)) {
            throw new \Exception("Can not load file \"$detachedSignatureFile\".");
        }

        // ---------------------------------------------------------
        // Now, verify the signature.
        // ---------------------------------------------------------

        $warning = null;
        $this->assertTrue(Gpg::verifyDetachedSignedString($signature, $input, $warning));
        $this->assertNull($warning);
    }

    public function testVerifyDetachSignFileError()
    {

        $this->__loadKeys();

        // ---------------------------------------------------------
        // Start by detach signing a file.
        // ---------------------------------------------------------

        $input = __FILE__;
        $detachedSignatureFile = $this->__outputDir . DIRECTORY_SEPARATOR . basename($input) . '.sig';
        $fgp = Gpg::getPrivateKeyFingerPrint('protected key');
        $this->__unlink($detachedSignatureFile);
        $this->assertTrue(Gpg::detachSignFile($input, $fgp, self::PASSWORD, $detachedSignatureFile));

        // ---------------------------------------------------------
        // Let modify the input file... so that it does not match
        // the signature.
        // ---------------------------------------------------------

        if (false === $text = file_get_contents(__FILE__)) {
            throw new \Exception("Can not load the input file " . __FILE__);
        }

        $text .= '0';
        $temp  = tempnam(sys_get_temp_dir(), 'GpgTest::');

        if (false === file_put_contents($temp, $text)) {
            throw new \Exception("Can not write into file \"$temp\".");
        }

        // ---------------------------------------------------------
        // Now, verify the signature... it does not match with the
        // modified document.
        // ---------------------------------------------------------

        $warning = null;
        $this->assertFalse(Gpg::verifyDetachedSignedFile($detachedSignatureFile, $temp, $warning));
        $this->assertNull($warning);

        // ---------------------------------------------------------
        // Let modify the signature file, so the signature is not
        // valid => CRC error.
        // ---------------------------------------------------------

        // -----BEGIN PGP SIGNATURE-----
        // Version: GnuPG v1
        //
        // iQEcBAABAgAGBQJYX+f1AAoJEP9rQHkVcZ0b7OEH/j+kw92MNLMdDgmUawWtJxzh
        // wNYQICSHDJLJGY0VNhGfRxVzunmbbspB7Z1ecwFBb3v4uYIGNVWrmhmVfAqpTTwL
        // 0DlDhC/ate69noxg6AGyUfniTaMIaBEvFVT/5WeRuoCZXb1IsUcddxJkOEj7QcoG
        // 6AEFklhIGQIc0FvsmAjit5bfd7Ini2KHzJhu1VaQZ0uE1hG/OREM13b2Snk+3406
        // YoNF0LG6JXGZcbJihCftlBt9cmh8xacU1xZKDLy5ke/Ey0iLGU457jloPZ7DBzIJ
        // B1+L4wa+EjvJOyfxgiDx5Ej+bOAKzIkLRCoKzBggm0xOBnEkTreHHjxcP6Qi1Ns=
        // =hgHu
        // -----END PGP SIGNATURE-----

        if (false === $signature = file_get_contents($detachedSignatureFile)) {
            throw new \Exception("Can not load file \"$detachedSignatureFile\".");
        }

        $temp  = tempnam(sys_get_temp_dir(), 'GpgTest::');
        $lines = explode(PHP_EOL, $signature);
        $index = count($lines)-5;
        $lineToModify = str_split($lines[$index]);
        $where = rand(0, count($lineToModify)-1);
        $lineToModify[$where] = '0' == $lineToModify[$where] ? '1' : '0';
        $lines[$index] = implode('', $lineToModify);

        if (false === file_put_contents($temp, implode(PHP_EOL, $lines))) {
            throw new \Exception("Can not write into file \"$temp\".");
        }

        // ---------------------------------------------------------
        // Verify the signature again... The CRC is wrong.
        // This should throw an exception!
        // ---------------------------------------------------------

        $this->expectException(\Exception::class);
        $warning = null;
        Gpg::verifyDetachedSignedFile($temp, $input, $warning);
    }



    private function __unlink($inPath) {
        if (file_exists($inPath)) {
            if (false === unlink($inPath)) {
                throw new \Exception("Can not unlink the file <$inPath>");
            }
        }
    }
}


