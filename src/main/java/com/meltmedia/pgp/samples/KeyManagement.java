package com.meltmedia.pgp.samples;

import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.base.Strings;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.Iterators;
import com.google.common.collect.Lists;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.SecureRandom;
import java.security.Security;
import java.util.*;
import java.util.concurrent.ExecutionException;

import static org.apache.commons.codec.binary.Hex.encodeHexString;
import static org.apache.commons.io.IOUtils.closeQuietly;

/**
 * This is just a prototype explaining encryption using PGP Public key.
 * Pleas modify this class to suit your application needs.
 */
public class KeyManagement {

  static final Logger logger = LoggerFactory.getLogger(KeyManagement.class);
  static final int PAYLOAD_ENCRYPTION_ALG = PGPEncryptedData.AES_128;
  static final int BUFFER_SIZE = 512; // For encryption
  static final List<String> DEFAULT_FINGER_PRINTS = Collections.emptyList();

  public static final String DEFAULT_KEY_SERVER = "https://pgp.mit.edu";
  public static final String DEFAULT_CACHE_SPEC = "maximumSize=10,expireAfterWrite=6h,concurrencyLevel=5";

  protected String keyServer;

  protected LoadingCache<String, PGPPublicKey> cache;

  protected Set<String> validMasterFingerprints;

  public KeyManagement(Collection<String> validMasterFingerPrints) {
    this(validMasterFingerPrints, DEFAULT_KEY_SERVER, null);
  }

  public KeyManagement(Collection<String> validMasterFingerPrints, String keyServer, String cacheSpec) {
    this.keyServer = keyServer;

    this.validMasterFingerprints = new TreeSet<String>(validMasterFingerPrints == null ?
        DEFAULT_FINGER_PRINTS: validMasterFingerPrints);
    cacheSpec = Strings.isNullOrEmpty(cacheSpec) ? DEFAULT_CACHE_SPEC : cacheSpec;
    this.cache = CacheBuilder.from(cacheSpec)
        .build(new CacheLoader<String, PGPPublicKey>() {
          @Override
          public PGPPublicKey load(String keyId) throws Exception {
            return fetchKey(keyId);
          }
        });
  }

  protected static class PublicKeyComparator implements Comparator<PGPPublicKey> {

    @Override
    public int compare(PGPPublicKey key1, PGPPublicKey key2) {
      return key2.getCreationTime().compareTo(key1.getCreationTime());
    }
  }

  public PGPPublicKey readPublicKey(String key) throws IOException, PGPException {
    // Convert key to binary
    InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(key.getBytes("UTF-8")));

    //Initialize key ring for public key
    PGPPublicKeyRing pgpPub = new PGPPublicKeyRing(in, new JcaKeyFingerprintCalculator());

    //Check if master key is not expired
    long masterKeyExpiry = pgpPub.getPublicKey().getCreationTime().getTime() +
        pgpPub.getPublicKey().getValidSeconds() * 1000;
    Preconditions.checkState(pgpPub.getPublicKey().getValidSeconds() == 0 ||
            masterKeyExpiry > System.currentTimeMillis(),
        "Master key is expired: ");

    //Check if master key is not revoked
    Preconditions.checkState(!pgpPub.getPublicKey().hasRevocation(), "Master key has been revoked");
    String masterKeyFingerPrint = encodeHexString(pgpPub.getPublicKey().getFingerprint());
    logger.info("Loaded PGP key Fingerprint: {}", masterKeyFingerPrint);

    //Check if fingerprint of master public key is one of the valid fingerprints
    Preconditions.checkState(validMasterFingerprints.isEmpty() ||
            validMasterFingerprints.contains(masterKeyFingerPrint),
        String.format("Not expecting master key with fingerprint: %s", masterKeyFingerPrint));

    Set<PGPPublicKey> validKeys = new TreeSet<PGPPublicKey>(new PublicKeyComparator());

    // Load all subkeys and sort them in descending order of creation date.
    Iterators.addAll(validKeys, Iterators.filter(pgpPub.getPublicKeys(), new Predicate<PGPPublicKey>() {
      @Override
      public boolean apply(PGPPublicKey input) {
        long subkeyExpiry = input.getCreationTime().getTime() + input.getValidSeconds() * 1000;
        return input.isEncryptionKey() && !input.hasRevocation() && !input.isMasterKey() &&
            (input.getValidSeconds() == 0 || subkeyExpiry > System.currentTimeMillis());
      }
    }));

    // There should be at-least one subkey available for encryption.
    Preconditions.checkState(!validKeys.isEmpty(), "No valid subkey found for encryption");

    // Return the most recently added , non expired , non revoked encryption subkey
    return validKeys.iterator().next();
  }

  public String fetchKeyRaw(String keyId) throws UnirestException {
    HttpResponse<String> response = Unirest.get(keyServer + "/pks/lookup")
        .queryString("op", "get")
        .queryString("search", keyId)
        .queryString("options", "mr")
        .asString();
    String raw = response.getBody();
    Preconditions.checkState(response.getStatus() == HttpStatus.SC_OK,
        String.format("Error happened while trying to fetch key: %s. Key server responded with status: %s. " +
            "response: %s", keyId, response.getStatus(), raw));
    return raw;
  }

  public PGPPublicKey fetchKey(String keyId) throws UnirestException, IOException, PGPException {
    // Uncomment below to fetch from key server rather using hardcoded value.
    //String rawKey = fetchKeyRaw(keyId);
    String rawKey =  "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "Version: SKS 1.1.5\n" +
        "Comment: Hostname: pgp.mit.edu\n" +
        "\n" +
        "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\n" +
        "=cilC\n" +
        "-----END PGP PUBLIC KEY BLOCK-----";
    return readPublicKey(rawKey);
  }

  /**
   * Encrypt using cached version of key. If key is not found in cache, an attempt will be made to fetch from KeyServer.
   *
   * @param keyId
   * @param payload
   * @return
   * @throws ExecutionException
   * @throws IOException
   * @throws PGPException
   */
  public String encrypt(String keyId, String payload)
      throws ExecutionException, IOException, PGPException {
    return encrypt(cache.get(keyId), payload);
  }

  /**
   * Encrypt using given payload and PGPPublic Key
   *
   * @param payload
   * @param pgpPublicKey
   * @return
   * @throws ExecutionException
   * @throws IOException
   * @throws PGPException
   */
  public String encrypt(PGPPublicKey pgpPublicKey, String payload)
      throws ExecutionException, IOException, PGPException {
    // write data out using "ascii-armor" encoding.  This is the
    // normal PGP text output.
    // create an encrypted payload and set the public key on the data generator
    JcePGPDataEncryptorBuilder builder =
        new JcePGPDataEncryptorBuilder(PAYLOAD_ENCRYPTION_ALG)
            .setProvider("BC")
            .setWithIntegrityPacket(true)
            .setSecureRandom(new SecureRandom());
    PGPEncryptedDataGenerator encryptGen = new PGPEncryptedDataGenerator(builder);
    encryptGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey).setProvider("BC"));
    // compress data.  we are building layers of output streams.  we want to compress here
    // because this is "before" encryption, and you get far better compression on
    // unencrypted data.
    PGPCompressedDataGenerator compressor = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);


    PGPLiteralDataGenerator literalGen = new PGPLiteralDataGenerator();
    ByteArrayOutputStream outputStream = null;
    ArmoredOutputStream armoredOutputStream  = null;
    OutputStream encryptedOut = null;
    OutputStream compressedOut = null;
    OutputStream literalOut = null;
    try {
      outputStream = new ByteArrayOutputStream();
      armoredOutputStream = new ArmoredOutputStream(outputStream);

      // open an output stream connected to the encrypted data generator
      // and have the generator write its data out to the ascii-encoding stream
      encryptedOut = encryptGen.open(armoredOutputStream, new byte[BUFFER_SIZE]);
      compressedOut = compressor.open(encryptedOut);

      // now we have a stream connected to a data compressor, which is connected to
      // a data encryptor, which is connected to an ascii-encoder.
      // into that we want to write a PGP "literal" object, which is just a named
      // piece of data (as opposed to a specially-formatted key, signature, etc)
      literalOut = literalGen.open(compressedOut, PGPLiteralDataGenerator.TEXT,
          "form-data", new Date(), new byte[BUFFER_SIZE]);

      literalOut.write(payload.getBytes("UTF-8"));
    } finally {
      closeQuietly(literalOut);
      closeQuietly(compressedOut);
      closeQuietly(encryptedOut);
      closeQuietly(armoredOutputStream);
      closeQuietly(outputStream);
    }
    return outputStream.toString("UTF-8");
  }

  public static void main(String... args) throws UnirestException, IOException, PGPException, ExecutionException {
    //Add BountyCastleProvider to security
    Security.addProvider(new BouncyCastleProvider());

    // Get the list of key fingerprints from various authors. This saves manual validation.
    // Note: This is fingerprint for master keys only. We do not validate fingerprint for subkeys as it was signed
    // by master key. THis allows us to rotate subkeys w/o a need to modify subkeys.
    KeyManagement km = new KeyManagement(Lists.newArrayList("ac4e99716d8b06e77d6048b65548a5975823ab99"));

    // Encrypt: Get key id from author
    String keyId = "0x5548a5975823ab99";
    String payload = "{\"field1\": \"value1\", \"field2\": \"value2\"}";
    logger.info("Encrypted Text: \n{}", km.encrypt(keyId, payload));
  }
}
