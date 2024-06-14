package com.example.test_token_nats;

import io.nats.client.Connection;
import io.nats.client.ConnectionListener;
import io.nats.client.Nats;
import io.nats.client.Options;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@Slf4j
@Component
public class TestTokenNats {

    @Value("${ca.cert}")
    private String caCertPath;

    @Value("${client.key}")
    private String clientKeyPath;

    @Value("${client.cert}")
    private String clientCertPath;

    @PostConstruct
    public void init() throws Exception {
        String subject = "test.token.cert";
        String message = "Message from Java";
        String serverURL = "nats://nats.awto.pro:4222";

        Options options = new Options.Builder()
                .server(serverURL)
                .sslContext(createSSLContext())
                .connectionListener((conn, type) -> {
                    if (type == ConnectionListener.Events.CONNECTED) {
                        log.info("[TEST-TOKEN-NATS] Connected to NATS");
                    }
                }).
                build();

        try (Connection nc = Nats.connect(options)) {
            nc.publish(subject, message.getBytes());
            log.info("[TEST-TOKEN-NATS] Message publish at {}", subject);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private SSLContext createSSLContext() throws Exception {
        // Carga el archivo CA
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        // Crea un KeyStore para el CA
        KeyStore caKeyStore = createKeyStore(certificateFactory);

        // Crea un TrustManagerFactory con el KeyStore CA
        TrustManager[] trustManagers = createTrustManagers(caKeyStore);

        // Generando certificado
        Certificate certificate = generateCertificate(certificateFactory);
        Certificate[] certificates = new Certificate[]{certificate};

        // Carga el certificado y la clave del cliente
        KeyStore keyStore = createClientKeyStore(certificates);

        // Crea un KeyManagerFactory con el KeyStore del cliente
        KeyManagerFactory keyManagerFactory = createKeyManagerFactory(keyStore);

        // Crea un SSLContext con los TrustManagers y KeyManagers
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagers, new SecureRandom());

        return sslContext;
    }

    private KeyManagerFactory createKeyManagerFactory(KeyStore keyStore) throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, null);

        return keyManagerFactory;
    }

    private KeyStore createClientKeyStore(Certificate[] certificates) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PrivateKey privateKey = getPrivateKey(Paths.get(clientKeyPath));

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setCertificateEntry("clientCert", certificates[0]);
        keyStore.setKeyEntry("clientKey", privateKey, null, certificates);

        return keyStore;
    }

    private Certificate generateCertificate(CertificateFactory certificateFactory) throws IOException, CertificateException {
        InputStream inputStream = Files.newInputStream(Paths.get(clientCertPath));
        return certificateFactory.generateCertificate(inputStream);
    }

    private TrustManager[] createTrustManagers(KeyStore caKeyStore) throws NoSuchAlgorithmException, KeyStoreException {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(caKeyStore);

        return tmf.getTrustManagers();
    }

    private KeyStore createKeyStore(CertificateFactory certificateFactory) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        Certificate caCert = certificateFactory.generateCertificate(Files.newInputStream(Paths.get(caCertPath)));
        KeyStore caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        caKeyStore.load(null, null);
        caKeyStore.setCertificateEntry("caCert", caCert);

        return caKeyStore;
    }

    private PrivateKey getPrivateKey(Path keyFilePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String key = new String(Files.readAllBytes(keyFilePath));
        String privateKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(keySpec);
    }
}
