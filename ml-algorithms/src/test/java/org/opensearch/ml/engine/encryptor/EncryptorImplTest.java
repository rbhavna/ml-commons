package org.opensearch.ml.engine.encryptor;

import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.opensearch.ml.common.CommonValue.CREATE_TIME_FIELD;
import static org.opensearch.ml.common.CommonValue.MASTER_KEY;
import static org.opensearch.ml.common.CommonValue.ML_CONFIG_INDEX;
import static org.opensearch.ml.engine.encryptor.EncryptorImpl.MASTER_KEY_NOT_READY_ERROR;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.Version;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.commons.ConfigConstants;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.ml.engine.indices.MLIndicesHandler;
import org.opensearch.threadpool.ThreadPool;

import com.google.common.collect.ImmutableMap;

public class EncryptorImplTest {
    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

    @Mock
    Client client;

    @Mock
    ClusterService clusterService;

    @Mock
    ClusterState clusterState;

    @Mock
    private MLIndicesHandler mlIndicesHandler;

    @Mock
    ActionListener<Map<String,String>> listener;

    String masterKey;

    Map<String, String> credentials = new HashMap<>();

    Map<String, String> encrypted = new HashMap<>();

    @Mock
    ThreadPool threadPool;
    ThreadContext threadContext;
    final String USER_STRING = "myuser|role1,role2|myTenant";

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        masterKey = "m+dWmfmnNRiNlOdej/QelEkvMTyH//frS2TBeS2BP4w=";

        doAnswer(invocation -> {
            ActionListener<GetResponse> listener = invocation.getArgument(1);
            GetResponse response = mock(GetResponse.class);
            when(response.isExists()).thenReturn(true);
            when(response.getSourceAsMap())
                .thenReturn(ImmutableMap.of(MASTER_KEY, masterKey, CREATE_TIME_FIELD, Instant.now().toEpochMilli()));
            listener.onResponse(response);
            return null;
        }).when(client).get(any(), any());

        when(clusterService.state()).thenReturn(clusterState);

        Metadata metadata = new Metadata.Builder()
            .indices(
                ImmutableMap
                    .<String, IndexMetadata>builder()
                    .put(
                        ML_CONFIG_INDEX,
                        IndexMetadata
                            .builder(ML_CONFIG_INDEX)
                            .settings(
                                Settings
                                    .builder()
                                    .put("index.number_of_shards", 1)
                                    .put("index.number_of_replicas", 1)
                                    .put("index.version.created", Version.CURRENT.id)
                            )
                            .build()
                    )
                    .build()
            )
            .build();
        when(clusterState.metadata()).thenReturn(metadata);

        Settings settings = Settings.builder().build();
        threadContext = new ThreadContext(settings);
        threadContext.putTransient(ConfigConstants.OPENSEARCH_SECURITY_USER_INFO_THREAD_CONTEXT, USER_STRING);
        when(client.threadPool()).thenReturn(threadPool);
        when(threadPool.getThreadContext()).thenReturn(threadContext);

        doAnswer(invocation -> {
            ActionListener<Boolean> listener = invocation.getArgument(0);
            listener.onResponse(true);
            return null;
        }).when(mlIndicesHandler).initMLConfigIndex(any());
    }

    @Test
    public void encrypt_success() {
        Encryptor encryptor = new EncryptorImpl(clusterService, client, mlIndicesHandler);
        assertNull(encryptor.getMasterKey());
        credentials.put("key1", "value1");
        credentials.put("key2", "value2");
        encryptor.encrypt(credentials, listener);

        ArgumentCaptor<Map<String,String>> argumentCaptor = ArgumentCaptor.forClass(HashMap.class);
        verify(listener).onResponse(argumentCaptor.capture());
        Assert.assertNotNull(argumentCaptor.getValue());
        Assert.assertEquals(masterKey, encryptor.getMasterKey());
    }

    @Test
    public void encrypt_failed() {
        doAnswer(invocation -> {
            ActionListener<GetResponse> listener = invocation.getArgument(1);
            listener.onFailure(new ResourceNotFoundException("test error"));
            return null;
        }).when(client).get(any(), any());

        Encryptor encryptor = new EncryptorImpl(clusterService, client, mlIndicesHandler);

        credentials.put("key1", "value1");
        credentials.put("key2", "value2");
        encryptor.encrypt(credentials, listener);

        ArgumentCaptor<Exception> argumentCaptor = ArgumentCaptor.forClass(Exception.class);
        verify(listener).onFailure(argumentCaptor.capture());
        Assert.assertEquals(MASTER_KEY_NOT_READY_ERROR, argumentCaptor.getValue().getMessage());
    }

    @Test
    public void decrypt_success() {
        Encryptor encryptor = new EncryptorImpl(clusterService, client, mlIndicesHandler);
        ActionListener<Map<String,String>> encryptListener = mock(ActionListener.class);

        doAnswer(invocation -> {
            encrypted.put("key1", "encrypted_value1");
            encrypted.put("key2", "encrypted_value2");
            encryptor.decrypt(encrypted, listener);
            return null;
        }).when(encryptListener).onResponse(any());

        credentials.put("key1", "value1");
        credentials.put("key2", "value2");
        encryptor.encrypt(credentials, encryptListener);

        ArgumentCaptor<Map<String,String>> argumentCaptor = ArgumentCaptor.forClass(HashMap.class);
        verify(listener).onResponse(argumentCaptor.capture());
        Assert.assertEquals("text", argumentCaptor.getValue());
    }

    @Test
    public void decrypt_failed() {
        doAnswer(invocation -> {
            ActionListener<GetResponse> listener = invocation.getArgument(1);
            listener.onFailure(new ResourceNotFoundException("test error"));
            return null;
        }).when(client).get(any(), any());

        Encryptor encryptor = new EncryptorImpl(clusterService, client, mlIndicesHandler);
        encryptor.decrypt(encrypted, listener);

        ArgumentCaptor<Exception> argumentCaptor = ArgumentCaptor.forClass(Exception.class);
        verify(listener).onFailure(argumentCaptor.capture());
        Assert.assertEquals(MASTER_KEY_NOT_READY_ERROR, argumentCaptor.getValue().getMessage());
    }

    @Test
    public void encrypt_withVersionConflictException() {

        doAnswer(invocation -> {
            ActionListener<GetResponse> listener = invocation.getArgument(1);
            listener.onResponse(null);
            return null;
        }).when(client).get(any(), any());

        doAnswer(invocation -> {
            ActionListener<IndexResponse> listener = invocation.getArgument(1);
            listener.onFailure(new VersionConflictEngineException(mock(StreamInput.class)));
            return null;
        }).when(client).index(any(), any());

        doAnswer(invocation -> {
            ActionListener<GetResponse> listener = invocation.getArgument(1);
            GetResponse response = mock(GetResponse.class);
            when(response.isExists()).thenReturn(true);
            when(response.getSourceAsMap())
                .thenReturn(ImmutableMap.of(MASTER_KEY, masterKey, CREATE_TIME_FIELD, Instant.now().toEpochMilli()));
            listener.onResponse(response);
            return null;
        }).when(client).get(any(), any());

        Encryptor encryptor = new EncryptorImpl(clusterService, client, mlIndicesHandler);
        credentials.put("key1", "value1");
        credentials.put("key2", "value2");
        encryptor.encrypt(credentials, listener);

        ArgumentCaptor<Map<String,String>> argumentCaptor = ArgumentCaptor.forClass(HashMap.class);
        verify(listener).onResponse(argumentCaptor.capture());

        Assert.assertEquals(masterKey, encryptor.getMasterKey());
    }

    @Test
    public void decrypt_withUnexpectedException() {
        doAnswer(invocation -> {
            ActionListener<GetResponse> listener = invocation.getArgument(1);
            listener.onFailure(new RuntimeException("unexpected error"));
            return null;
        }).when(client).get(any(), any());

        Encryptor encryptor = new EncryptorImpl(clusterService, client, mlIndicesHandler);
        encryptor.decrypt(encrypted, listener);

        ArgumentCaptor<Exception> argumentCaptor = ArgumentCaptor.forClass(Exception.class);
        verify(listener).onFailure(argumentCaptor.capture());
        Assert.assertEquals("unexpected error", argumentCaptor.getValue().getMessage());
    }

    @Test
    public void initMasterKey_success() {
        Encryptor encryptor = new EncryptorImpl(clusterService, client, mlIndicesHandler);
        ActionListener<Boolean> initListener = mock(ActionListener.class);

        credentials.put("key1", "value1");
        credentials.put("key2", "value2");
        encryptor.encrypt(credentials, listener);

        ArgumentCaptor<Boolean> argumentCaptor = ArgumentCaptor.forClass(Boolean.class);
        verify(initListener).onResponse(argumentCaptor.capture());
        Assert.assertTrue(argumentCaptor.getValue());
    }

    @Test
    public void initMasterKey_failed() {
        doAnswer(invocation -> {
            ActionListener<GetResponse> listener = invocation.getArgument(1);
            listener.onFailure(new ResourceNotFoundException("test error"));
            return null;
        }).when(client).get(any(), any());

        Encryptor encryptor = new EncryptorImpl(clusterService, client, mlIndicesHandler);
        ActionListener<Boolean> initListener = mock(ActionListener.class);

        credentials.put("key1", "value1");
        credentials.put("key2", "value2");
        encryptor.encrypt(credentials, listener);

        ArgumentCaptor<Exception> argumentCaptor = ArgumentCaptor.forClass(Exception.class);
        verify(initListener).onFailure(argumentCaptor.capture());
        Assert.assertEquals(MASTER_KEY_NOT_READY_ERROR, argumentCaptor.getValue().getMessage());
    }

    @Test
    public void generateMasterKey_success() {
        Encryptor encryptor = new EncryptorImpl(clusterService, client, mlIndicesHandler);
        String generatedMasterKey = encryptor.generateMasterKey();

        Assert.assertNotNull(generatedMasterKey);
        Assert.assertEquals(44, generatedMasterKey.length()); // Base64 encoded 32 bytes key should be 44 characters long
    }
}
