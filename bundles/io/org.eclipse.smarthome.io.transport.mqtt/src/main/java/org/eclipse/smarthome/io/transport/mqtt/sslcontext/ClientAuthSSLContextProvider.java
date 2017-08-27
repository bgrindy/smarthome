/**
 * Copyright (c) 2014-2017 by the respective copyright holders.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.eclipse.smarthome.io.transport.mqtt.sslcontext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.ConfigurationException;
import javax.net.ssl.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * This SSLContextProvider returns an {@link SSLContext} that authenticates using a
 * client certificate/key and validates connections using the provided certificate authority.
 * This implementation forces a TLS v1.2 {@link SSLContext} instance.
 *
 * @author Ben Grindy - Initial contribution
 */
public class ClientAuthSSLContextProvider implements SSLContextProvider {
    private final Logger logger = LoggerFactory.getLogger(ClientAuthSSLContextProvider.class);


    private final String clientKeyPath;
    private final String clientCertPath;
    private final String caCertPath;

    public ClientAuthSSLContextProvider(String clientKeyPath, String clientCertPath, String caCertPath) {
        this.clientKeyPath = clientKeyPath;
        this.clientCertPath = clientCertPath;
        this.caCertPath = caCertPath;
    }

    @Override
    public SSLContext getContext() throws ConfigurationException {
        try {
            Key clientKey;
            X509Certificate clientCert, caCert;

            KeyFactory kf = KeyFactory.getInstance("RSA");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            try (FileInputStream clientCertFis = new FileInputStream(clientCertPath);
                 FileInputStream caCertFis = new FileInputStream(caCertPath)) {
                clientKey = kf.generatePrivate(getKeySpec(clientKeyPath));
                clientCert = (X509Certificate) cf.generateCertificate(clientCertFis);
                caCert = (X509Certificate) cf.generateCertificate(caCertFis);
            }

            // Configure trustStore with certificate authority
            KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
            ts.load(null, null);
            ts.setCertificateEntry("ca", caCert);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);

            // Configure keyStore with client key/cert
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            ks.setCertificateEntry("cert", clientCert);
            ks.setKeyEntry("key", clientKey, null, new Certificate[]{clientCert});
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, null);

            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            return sslContext;
        } catch (InvalidKeySpecException | CertificateException | IOException | KeyStoreException | UnrecoverableKeyException | KeyManagementException | NoSuchAlgorithmException e) {
            logger.warn("SSL configuration failed", e);
            throw new ConfigurationException(e.getMessage());
        }
    }

    private KeySpec getKeySpec(String clientPemKeyPath) throws IOException {
        String b64PemKey = new String(Files.readAllBytes(Paths.get(clientPemKeyPath)));
        b64PemKey = b64PemKey.replace("-----BEGIN PRIVATE KEY-----\n", "");
        b64PemKey = b64PemKey.replace("-----END PRIVATE KEY-----", "");
        byte[] pemKeyBytes = Base64.getDecoder().decode(b64PemKey);
        return new PKCS8EncodedKeySpec(pemKeyBytes);
    }
}
