package uk.gov.ida.assertiondecrypter;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.crypto.KeySupport;
import org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.EncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.CollectionKeyInfoCredentialResolver;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;
import uk.gov.ida.saml.deserializers.OpenSamlXMLObjectUnmarshaller;
import uk.gov.ida.saml.deserializers.parser.SamlObjectParser;
import uk.gov.ida.saml.serializers.XmlObjectToBase64EncodedStringTransformer;

import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static java.nio.file.Files.readAllBytes;
import static java.util.Collections.singletonList;

public class AssertionDecrypter {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, KeyException, DecryptionException, UnmarshallingException, XMLParserException, URISyntaxException, IOException, ParserConfigurationException, SAXException, InitializationException {
        if (args.length != 2) {
            System.out.println("Usage: [app] decryption-key.pk8 encrypted-assertion.xml");
            System.exit(1);
        }
        ((Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME)).setLevel(Level.OFF);
        InitializationService.initialize();

        KeySpec keySpec = new PKCS8EncodedKeySpec(readAllBytes(Paths.get(args[0])));
        KeyFactory keyFactory;

        keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        BasicCredential credential = new BasicCredential(KeySupport.derivePublicKey(privateKey), privateKey);
        credential.setUsageType(UsageType.ENCRYPTION);

        KeyInfoCredentialResolver kekResolver = new CollectionKeyInfoCredentialResolver(singletonList(credential));

        EncryptedElementTypeEncryptedKeyResolver encryptedElementTypeEncryptedKeyResolver = new EncryptedElementTypeEncryptedKeyResolver();
        List<EncryptedKeyResolver> encKeyResolvers = Arrays.asList(encryptedElementTypeEncryptedKeyResolver, new InlineEncryptedKeyResolver());

        ChainingEncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver(encKeyResolvers);
        Decrypter decrypter = new Decrypter(null, kekResolver, encryptedKeyResolver);

        OpenSamlXMLObjectUnmarshaller<EncryptedAssertion> xmlObjectUnmarshaller = new OpenSamlXMLObjectUnmarshaller<>(new SamlObjectParser());
        EncryptedAssertion encryptedAssertion = xmlObjectUnmarshaller.fromString(new String(readAllBytes(Paths.get(args[1]))));

        String base64Assertion = new XmlObjectToBase64EncodedStringTransformer().apply(decrypter.decrypt(encryptedAssertion));
        System.out.println(new String(Base64.getDecoder().decode(base64Assertion)));
    }
}
