/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.ml.rest;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.OpenSearchParseException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.ParsingException;
import org.opensearch.core.common.Strings;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.ml.common.controller.MLController;
import org.opensearch.ml.common.settings.MLFeatureEnabledSetting;
import org.opensearch.ml.common.transport.controller.MLCreateControllerAction;
import org.opensearch.ml.common.transport.controller.MLCreateControllerRequest;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.threadpool.TestThreadPool;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.node.NodeClient;

public class RestMLCreateControllerActionTests extends OpenSearchTestCase {
    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

    private RestMLCreateControllerAction restMLCreateControllerAction;
    private NodeClient client;
    private ThreadPool threadPool;

    @Mock
    MLFeatureEnabledSetting mlFeatureEnabledSetting;

    @Mock
    RestChannel channel;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);
        threadPool = new TestThreadPool(this.getClass().getSimpleName() + "ThreadPool");
        client = spy(new NodeClient(Settings.EMPTY, threadPool));
        when(mlFeatureEnabledSetting.isControllerEnabled()).thenReturn(true);
        restMLCreateControllerAction = new RestMLCreateControllerAction(mlFeatureEnabledSetting);
        doAnswer(invocation -> {
            invocation.getArgument(2);
            return null;
        }).when(client).execute(eq(MLCreateControllerAction.INSTANCE), any(), any());
    }

    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        threadPool.shutdown();
        client.close();
    }

    @Test
    public void testConstructor() {
        RestMLCreateControllerAction CreateModelAction = new RestMLCreateControllerAction(mlFeatureEnabledSetting);
        assertNotNull(CreateModelAction);
    }

    @Test
    public void testGetName() {
        String actionName = restMLCreateControllerAction.getName();
        assertFalse(Strings.isNullOrEmpty(actionName));
        assertEquals("ml_create_controller_action", actionName);
    }

    @Test
    public void testRoutes() {
        List<RestHandler.Route> routes = restMLCreateControllerAction.routes();
        assertNotNull(routes);
        assertFalse(routes.isEmpty());
        RestHandler.Route route = routes.get(0);
        assertEquals(RestRequest.Method.POST, route.getMethod());
        assertEquals("/_plugins/_ml/controllers/{model_id}", route.getPath());
    }

    @Test
    public void testCreateControllerRequest() throws Exception {
        RestRequest request = getRestRequest();
        restMLCreateControllerAction.handleRequest(request, channel, client);
        ArgumentCaptor<MLCreateControllerRequest> argumentCaptor = ArgumentCaptor.forClass(MLCreateControllerRequest.class);
        verify(client, times(1)).execute(eq(MLCreateControllerAction.INSTANCE), argumentCaptor.capture(), any());
        MLController createControllerInput = argumentCaptor.getValue().getControllerInput();
        assertEquals("testModelId", createControllerInput.getModelId());
    }

    @Test
    public void testCreateControllerRequestWithEmptyContent() throws Exception {
        exceptionRule.expect(OpenSearchParseException.class);
        exceptionRule.expectMessage("Create model controller request has empty body");
        RestRequest request = getRestRequestWithEmptyContent();
        restMLCreateControllerAction.handleRequest(request, channel, client);
    }

    @Test
    public void testCreateControllerRequestWithNullModelId() throws Exception {
        exceptionRule.expect(IllegalArgumentException.class);
        exceptionRule.expectMessage("Request should contain model_id");
        RestRequest request = getRestRequestWithNullModelId();
        restMLCreateControllerAction.handleRequest(request, channel, client);
    }

    @Test
    public void testCreateControllerRequestWithNullField() throws Exception {
        exceptionRule.expect(ParsingException.class);
        exceptionRule.expectMessage("expecting token of type [START_OBJECT] but found [VALUE_NULL]");
        RestRequest request = getRestRequestWithNullField();
        restMLCreateControllerAction.handleRequest(request, channel, client);
    }

    @Test
    public void testCreateControllerRequestWithControllerDisabled() throws Exception {
        exceptionRule.expect(IllegalStateException.class);
        exceptionRule
            .expectMessage(
                "Controller is currently disabled. To enable it, update the setting \"plugins.ml_commons.controller_enabled\" to true."
            );
        when(mlFeatureEnabledSetting.isControllerEnabled()).thenReturn(false);
        RestRequest request = getRestRequest();
        restMLCreateControllerAction.handleRequest(request, channel, client);
    }

    private RestRequest getRestRequest() {
        RestRequest.Method method = RestRequest.Method.POST;
        String requestContent = "{\"user_rate_limiter\":{\"testUser\":{}}}";
        Map<String, String> params = Map.of("model_id", "testModelId");
        RestRequest request = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
            .withMethod(method)
            .withPath("/_plugins/_ml/controllers/{model_id}")
            .withParams(params)
            .withContent(new BytesArray(requestContent), XContentType.JSON)
            .build();
        return request;
    }

    private RestRequest getRestRequestWithEmptyContent() {
        RestRequest.Method method = RestRequest.Method.POST;
        Map<String, String> params = Map.of("model_id", "testModelId");
        RestRequest request = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
            .withMethod(method)
            .withPath("/_plugins/_ml/controllers/{model_id}")
            .withParams(params)
            .withContent(new BytesArray(""), XContentType.JSON)
            .build();
        return request;
    }

    private RestRequest getRestRequestWithNullModelId() {
        RestRequest.Method method = RestRequest.Method.POST;
        String requestContent = "{\"user_rate_limiter\":{\"testUser\":{}}}";
        Map<String, String> params = new HashMap<>();
        RestRequest request = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
            .withMethod(method)
            .withPath("/_plugins/_ml/controllers/{model_id}")
            .withParams(params)
            .withContent(new BytesArray(requestContent), XContentType.JSON)
            .build();
        return request;
    }

    private RestRequest getRestRequestWithNullField() {
        RestRequest.Method method = RestRequest.Method.POST;
        String requestContent = "{\"user_rate_limiter\":{\"testUser\":null}}";
        Map<String, String> params = new HashMap<>();
        params.put("model_id", "testModelId");
        RestRequest request = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
            .withMethod(method)
            .withPath("/_plugins/_ml/controllers/{model_id}")
            .withParams(params)
            .withContent(new BytesArray(requestContent), XContentType.JSON)
            .build();
        return request;
    }
}
