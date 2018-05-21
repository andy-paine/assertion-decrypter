## Assertion Decrypter

This tool is a utility for decrypting assertions based on GOV.UK Verify's saml-serializers library

To use the tool, you will need access to Verify's Artifactory instance or be able to build saml-serializers library

`./gradlew run decryption-key.pk8 encrypted-assertion.xml`
