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

    this.validMasterFingerprints = new TreeSet<>(validMasterFingerPrints == null ?
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

    Set<PGPPublicKey> validKeys = new TreeSet<>(new PublicKeyComparator());

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
    return readPublicKey(fetchKeyRaw(keyId));
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
    try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
      try (
          ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream);
          // open an output stream connected to the encrypted data generator
          // and have the generator write its data out to the ascii-encoding stream
          OutputStream encryptedOut = encryptGen.open(armoredOutputStream, new byte[BUFFER_SIZE]);
          OutputStream compressedOut = compressor.open(encryptedOut);

          // now we have a stream connected to a data compressor, which is connected to
          // a data encryptor, which is connected to an ascii-encoder.
          // into that we want to write a PGP "literal" object, which is just a named
          // piece of data (as opposed to a specially-formatted key, signature, etc)
          OutputStream literalOut = literalGen.open(compressedOut, PGPLiteralDataGenerator.TEXT,
              "form-data", new Date(), new byte[BUFFER_SIZE])
      ) {
        literalOut.write(payload.getBytes("UTF-8"));
      }
      return outputStream.toString("UTF-8");
    }
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
