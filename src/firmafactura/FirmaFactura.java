package firmafactura;

/**
 *
 *  
 */
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.*;

public class FirmaFactura {

    private static final String KEYSTORE_TYPE = "PKCS12";

    /**
     * @param args the command line arguments
     * @throws java.lang.Exception
     */
    public static void main(String[] args) throws Exception {
        /*
         * Usage: java -jar /path/.jar /path/invoice /path/certificate privatekey privatealias"
        */

        String FACTURA_PATH = args[0];
        String SIGNED_FACTURA_PATH = args[0];
        String KEYSTORE_FILE = args[1];
        String KEYSTORE_PASSWORD = args[2];
        String PRIVATE_KEY_PASSWORD = args[2];
        String PRIVATE_KEY_ALIAS = args[3];

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        Reference ref = fac.newReference("", fac.newDigestMethod(DigestMethod.SHA1, null),
                Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
                null, null);

        SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                (C14NMethodParameterSpec) null),
                fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
                Collections.singletonList(ref));

        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        ks.load(new FileInputStream(KEYSTORE_FILE), KEYSTORE_PASSWORD.toCharArray());
        KeyStore.PrivateKeyEntry keyEntry
                = (KeyStore.PrivateKeyEntry) ks.getEntry(PRIVATE_KEY_ALIAS, new KeyStore.PasswordProtection(PRIVATE_KEY_PASSWORD.toCharArray()));

        X509Certificate cert = (X509Certificate) keyEntry.getCertificate();

        KeyInfoFactory kif = fac.getKeyInfoFactory();
        List x509Content = new ArrayList();
        x509Content.add(cert.getSubjectX500Principal().getName());
        x509Content.add(cert);
        X509Data xd = kif.newX509Data(x509Content);
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(FACTURA_PATH));

        //Vamo a localizar el nodo
        NodeList nodes = doc.getDocumentElement().getElementsByTagNameNS("*", "ExtensionContent");

        DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), nodes.item(1));

        XMLSignature signature = fac.newXMLSignature(si, ki, null, "SignatureGian", null);

        signature.sign(dsc);

        OutputStream os = new FileOutputStream(SIGNED_FACTURA_PATH);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(os));

    }
}
