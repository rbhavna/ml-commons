/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.ml.engine.encryptor;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.opensearch.ml.common.CommonValue.MASTER_KEY;
import static org.opensearch.ml.common.CommonValue.ML_CONFIG_INDEX;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.spec.SecretKeySpec;

import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.LatchedActionListener;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.ml.common.exception.MLException;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;

import lombok.extern.log4j.Log4j2;
import org.opensearch.ml.common.transport.register.MLRegisterModelResponse;

@Log4j2
public class EncryptorImpl implements Encryptor {

    public static final String MASTER_KEY_NOT_READY_ERROR =
        "The ML encryption master key has not been initialized yet. Please retry after waiting for 10 seconds.";
    private ClusterService clusterService;
    private Client client;
    private volatile String masterKey;

    public EncryptorImpl(ClusterService clusterService, Client client) {
        this.masterKey = null;
        this.clusterService = clusterService;
        this.client = client;
    }

    public EncryptorImpl(String masterKey) {
        this.masterKey = masterKey;
    }

    @Override
    public void setMasterKey(String masterKey) {
        this.masterKey = masterKey;
    }

    @Override
    public String getMasterKey() {
        return masterKey;
    }

    @Override
    public void encrypt(String plainText, ActionListener<String> listener) {
        initMasterKey(new ActionListener<>() {
            @Override
            public void onResponse(Void unused) {
                try {
                    final AwsCrypto crypto = AwsCrypto.builder()
                        .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
                        .build();
                    byte[] bytes = Base64.getDecoder().decode(masterKey);
                    JceMasterKey jceMasterKey = JceMasterKey.getInstance(
                        new SecretKeySpec(bytes, "AES"), "Custom", "", "AES/GCM/NOPADDING");

                    final CryptoResult<byte[], JceMasterKey> encryptResult = crypto
                        .encryptData(jceMasterKey, plainText.getBytes(StandardCharsets.UTF_8));
                    listener.onResponse(Base64.getEncoder().encodeToString(encryptResult.getResult()));
                } catch (Exception e) {
                    listener.onFailure(e);
                }
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });
//        initMasterKey();
//        final AwsCrypto crypto = AwsCrypto.builder().withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt).build();
//        byte[] bytes = Base64.getDecoder().decode(masterKey);
//        // https://github.com/aws/aws-encryption-sdk-java/issues/1879
//        JceMasterKey jceMasterKey = JceMasterKey.getInstance(new SecretKeySpec(bytes, "AES"), "Custom", "", "AES/GCM/NOPADDING");
//
//        final CryptoResult<byte[], JceMasterKey> encryptResult = crypto
//            .encryptData(jceMasterKey, plainText.getBytes(StandardCharsets.UTF_8));
//        return Base64.getEncoder().encodeToString(encryptResult.getResult());
    }

    @Override
    public void decrypt(String encryptedText, ActionListener<String> listener) {
        initMasterKey(new ActionListener<>() {
            @Override
            public void onResponse(Void unused) {
                try {
                    final AwsCrypto crypto = AwsCrypto.builder().withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt).build();

                    byte[] bytes = Base64.getDecoder().decode(masterKey);
                    JceMasterKey jceMasterKey = JceMasterKey.getInstance(new SecretKeySpec(bytes, "AES"), "Custom", "", "AES/GCM/NOPADDING");

                    final CryptoResult<byte[], JceMasterKey> decryptedResult = crypto
                        .decryptData(jceMasterKey, Base64.getDecoder().decode(encryptedText));
                    listener.onResponse(new String(decryptedResult.getResult()));
                } catch (Exception e) {
                    listener.onFailure(e);
                }
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });

//        initMasterKey(listener);
//        final AwsCrypto crypto = AwsCrypto.builder().withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt).build();
//
//        byte[] bytes = Base64.getDecoder().decode(masterKey);
//        JceMasterKey jceMasterKey = JceMasterKey.getInstance(new SecretKeySpec(bytes, "AES"), "Custom", "", "AES/GCM/NOPADDING");
//
//        final CryptoResult<byte[], JceMasterKey> decryptedResult = crypto
//            .decryptData(jceMasterKey, Base64.getDecoder().decode(encryptedText));
//        return new String(decryptedResult.getResult());
    }

    @Override
    public String generateMasterKey() {
        byte[] keyBytes = new byte[32];
        new SecureRandom().nextBytes(keyBytes);
        String base64Key = Base64.getEncoder().encodeToString(keyBytes);
        return base64Key;
    }

    private void initMasterKey(ActionListener<Void> listener) {
        if (masterKey != null) {
            listener.onResponse(null);
            return;
        }
//        AtomicReference<Exception> exceptionRef = new AtomicReference<>();
        Boolean mlConfig = clusterService.state().metadata().hasIndex(ML_CONFIG_INDEX);

//        CountDownLatch latch = new CountDownLatch(1);
        if (clusterService.state().metadata().hasIndex(ML_CONFIG_INDEX)) {
            try (ThreadContext.StoredContext context = client.threadPool().getThreadContext().stashContext()) {
                GetRequest getRequest = new GetRequest(ML_CONFIG_INDEX).id(MASTER_KEY);
                client.get(getRequest, ActionListener.wrap(response -> {
                    if (response.isExists()) {
                        String retrievedMasterKey = (String) response.getSourceAsMap().get(MASTER_KEY);
                        this.masterKey = retrievedMasterKey;
                        listener.onResponse(null);
                    } else {
                        listener.onFailure(new ResourceNotFoundException(MASTER_KEY_NOT_READY_ERROR));
                    }
                }, e -> {
                    log.error("Failed to get ML encryption master key", e);
                    listener.onFailure(e);
                }));
            } catch (Exception e) {
                log.error("Failed to get encryption master key", e);
                listener.onFailure(e);
            }
        } else {
            listener.onFailure(new ResourceNotFoundException(MASTER_KEY_NOT_READY_ERROR));
        }

//        try {
//            latch.await(5, SECONDS);
//        } catch (InterruptedException e) {
//            throw new IllegalStateException(e);
//        }

//        if (exceptionRef.get() != null) {
//            log.debug("Failed to init master key", exceptionRef.get());
//            if (exceptionRef.get() instanceof RuntimeException) {
//                throw (RuntimeException) exceptionRef.get();
//            } else {
//                throw new MLException(exceptionRef.get());
//            }
//        }
//        if (masterKey == null) {
//            throw new ResourceNotFoundException(MASTER_KEY_NOT_READY_ERROR);
//        }
    }
}
