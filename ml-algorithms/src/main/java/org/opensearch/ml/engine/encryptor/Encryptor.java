/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.ml.engine.encryptor;

import org.opensearch.core.action.ActionListener;

import java.util.Map;

public interface Encryptor {

    /**
     * Takes plaintext and returns encrypted text.
     *
     * @param credentials plainText.
     * @return String encryptedText.
     */
    void encrypt(Map<String, String> credentials, ActionListener<Map<String, String>> listener);

    /**
     * Takes encryptedText and returns plain text.
     *
     * @param encryptedText encryptedText.
     * @return String plainText.
     */
    void decrypt(Map<String, String> credentials, ActionListener<Map<String, String>> listener);

    /**
     * Set up the masterKey for dynamic updating
     *
     * @param masterKey masterKey to be set.
     */
    void setMasterKey(String masterKey);

    String getMasterKey();

    String generateMasterKey();

}
