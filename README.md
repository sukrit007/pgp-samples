# pgp-samples
PGP Encryption example (using java7)

This is just a sample  demonstrating encryption using PGP using java7. For production usage, you might need better caching 
strategy.

## Running Sample
```
./gradlew run
```

## Creating Distribution
```
./gradlew distZip   
```

This will create distribution at location: `build/distribution/pgp-samples-1.0.zip`.  You can extract this distribution and run
```
java -jar pgp-samples-1.0.jar
```

**Note:**  All depedendent jar can be found in libs folder of distribution. 

## Modifying example

Here is snippet of code that sets keyId, fingerprint and payload to be encrypted.
[/src/main/java/com/meltmedia/pgp/samples/KeyManagement.java#L211-L215](/src/main/java/com/meltmedia/pgp/samples/KeyManagement.java#L211-L215).

