/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.ml.engine.tools;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.log4j.Log4j2;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.ml.common.FunctionName;
import org.opensearch.ml.common.dataset.remote.RemoteInferenceInputDataSet;
import org.opensearch.ml.common.input.MLInput;
import org.opensearch.ml.common.output.model.ModelTensor;
import org.opensearch.ml.common.output.model.ModelTensorOutput;
import org.opensearch.ml.common.output.model.ModelTensors;
import org.opensearch.ml.common.spi.tools.Parser;
import org.opensearch.ml.common.spi.tools.Tool;
import org.opensearch.ml.common.spi.tools.ToolAnnotation;
import org.opensearch.ml.common.transport.MLTaskResponse;
import org.opensearch.ml.common.transport.prediction.MLPredictionTaskAction;
import org.opensearch.ml.common.transport.prediction.MLPredictionTaskRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.apache.commons.text.StringEscapeUtils.escapeJson;
import static org.opensearch.ml.common.utils.StringUtils.gson;

/**
 * This tool supports running any ml-commons model.
 */
@Log4j2
@ToolAnnotation(RAGTool.TYPE)
public class RAGTool implements Tool {
    public static final String TYPE = "RAGTool";

    private static String DEFAULT_DESCRIPTION = "Use this tool to run any model.";

    @Setter
    @Getter
    private String name = TYPE;
    @Getter
    @Setter
    private String description = DEFAULT_DESCRIPTION;
    private Client client;
    private String modelId;

    private NamedXContentRegistry xContentRegistry;
    private String index;
    private String embeddingField;
    private String[] sourceFields;
    private String embeddingModelId;
    private Integer docSize;
    private Integer k;
    @Setter
    private Parser inputParser;
    @Setter
    private Parser outputParser;

    @Builder
    public RAGTool(
        Client client,
        NamedXContentRegistry xContentRegistry,
        String index,
        String embeddingField,
        String[] sourceFields,
        Integer k,
        Integer docSize,
        String embeddingModelId,
        String modelId
    ) {
        this.client = client;
        this.xContentRegistry = xContentRegistry;
        this.index = index;
        this.embeddingField = embeddingField;
        this.sourceFields = sourceFields;
        this.embeddingModelId = embeddingModelId;
        this.docSize = docSize == null ? 2 : docSize;
        this.k = k == null ? 10 : k;
        this.modelId = modelId;

        outputParser = new Parser() {
            @Override
            public Object parse(Object o) {
                List<ModelTensors> mlModelOutputs = (List<ModelTensors>) o;
                return mlModelOutputs.get(0).getMlModelTensors().get(0).getDataAsMap().get("response");
            }
        };
    }

    @Override
    public <T> void run(Map<String, String> parameters, ActionListener<T> listener) {
        try {
            String question = parameters.get("input");
            try {
                question = gson.fromJson(question, String.class);
            } catch (Exception e) {
                // throw new IllegalArgumentException("wrong input");
            }
            String query = "{\"query\":{\"neural\":{\""
                + embeddingField
                + "\":{\"query_text\":\""
                + question
                + "\",\"model_id\":\""
                + embeddingModelId
                + "\",\"k\":"
                + k
                + "}}}"
                + " }";

            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            XContentParser queryParser = XContentType.JSON
                .xContent()
                .createParser(xContentRegistry, LoggingDeprecationHandler.INSTANCE, query);
            searchSourceBuilder.parseXContent(queryParser);
            searchSourceBuilder.fetchSource(sourceFields, null);
            searchSourceBuilder.size(docSize);
            SearchRequest searchRequest = new SearchRequest().source(searchSourceBuilder).indices(index);
            ActionListener actionListener = ActionListener.<SearchResponse>wrap(r -> {
                SearchHit[] hits = r.getHits().getHits();
                T vectorDBToolOutput;

                if (hits != null && hits.length > 0) {
                    StringBuilder contextBuilder = new StringBuilder();
                    for (int i = 0; i < hits.length; i++) {
                        SearchHit hit = hits[i];
                        String doc = AccessController.doPrivileged((PrivilegedExceptionAction<String>) () -> {
                            Map<String, Object> docContent = new HashMap<>();
                            docContent.put("_id", hit.getId());
                            docContent.put("_source", hit.getSourceAsMap());
                            return gson.toJson(docContent);
                        });
                        contextBuilder.append(doc).append("\n");
                    }
                    vectorDBToolOutput = (T) gson.toJson(contextBuilder.toString());
                } else {
                    vectorDBToolOutput = (T) "";
                }

                Map<String, String> tmpParameters = new HashMap<>();
                tmpParameters.putAll(parameters);

                if (vectorDBToolOutput instanceof List
                    && !((List) vectorDBToolOutput).isEmpty()
                    && ((List) vectorDBToolOutput).get(0) instanceof ModelTensors) {
                    ModelTensors tensors = (ModelTensors) ((List) vectorDBToolOutput).get(0);
                    Object response = tensors.getMlModelTensors().get(0).getDataAsMap().get("response");
                    tmpParameters.put("output", response + "");
                } else if (vectorDBToolOutput instanceof ModelTensor) {
                    tmpParameters.put("output", escapeJson(toJson(((ModelTensor) vectorDBToolOutput).getDataAsMap())));
                } else {
                    if (vectorDBToolOutput instanceof String) {
                        tmpParameters.put("output", (String) vectorDBToolOutput);
                    } else {
                        tmpParameters.put("output", escapeJson(toJson(vectorDBToolOutput.toString())));
                    }
                }

                RemoteInferenceInputDataSet inputDataSet = RemoteInferenceInputDataSet.builder().parameters(tmpParameters).build();
                ActionRequest request = new MLPredictionTaskRequest(
                    modelId,
                    MLInput.builder().algorithm(FunctionName.REMOTE).inputDataset(inputDataSet).build()
                );
                client.execute(MLPredictionTaskAction.INSTANCE, request, ActionListener.<MLTaskResponse>wrap(resp -> {
                    ModelTensorOutput modelTensorOutput = (ModelTensorOutput) resp.getOutput();
                    modelTensorOutput.getMlModelOutputs();
                    if (outputParser == null) {
                        listener.onResponse((T) modelTensorOutput.getMlModelOutputs());
                    } else {
                        listener.onResponse((T) outputParser.parse(modelTensorOutput.getMlModelOutputs()));
                    }
                }, e -> {
                    log.error("Failed to run model " + modelId, e);
                    listener.onFailure(e);
                }));
            }, e -> {
                log.error("Failed to search index", e);
                listener.onFailure(e);
            });
            client.search(searchRequest, actionListener);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public String getVersion() {
        return null;
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public void setName(String s) {
        this.name = s;
    }

    @Override
    public boolean validate(Map<String, String> parameters) {
        if (parameters == null || parameters.size() == 0) {
            return false;
        }
        String question = parameters.get("input");
        return question != null;
    }

    public static class Factory implements Tool.Factory<RAGTool> {
        private Client client;
        private NamedXContentRegistry xContentRegistry;

        private static Factory INSTANCE;

        public static Factory getInstance() {
            if (INSTANCE != null) {
                return INSTANCE;
            }
            synchronized (RAGTool.class) {
                if (INSTANCE != null) {
                    return INSTANCE;
                }
                INSTANCE = new Factory();
                return INSTANCE;
            }
        }

        public void init(Client client, NamedXContentRegistry xContentRegistry) {
            this.client = client;
            this.xContentRegistry = xContentRegistry;
        }

        @Override
        public RAGTool create(Map<String, Object> params) {
            String embeddingModelId = (String) params.get("embedding_model_id");
            String index = (String) params.get("index");
            String embeddingField = (String) params.get("embedding_field");
            String[] sourceFields = gson.fromJson((String) params.get("source_field"), String[].class);
            String modelId = (String) params.get("model_id");
            Integer docSize = params.containsKey("doc_size") ? Integer.parseInt((String) params.get("doc_size")) : 2;
            return RAGTool
                .builder()
                .client(client)
                .xContentRegistry(xContentRegistry)
                .index(index)
                .embeddingField(embeddingField)
                .sourceFields(sourceFields)
                .embeddingModelId(embeddingModelId)
                .docSize(docSize)
                .modelId(modelId)
                .build();
        }

        @Override
        public String getDefaultDescription() {
            return DEFAULT_DESCRIPTION;
        }
    }

    private String toJson(Object value) {
        try {
            return AccessController.doPrivileged((PrivilegedExceptionAction<String>) () -> {
                if (value instanceof String) {
                    return (String) value;
                } else {
                    return gson.toJson(value);
                }
            });
        } catch (PrivilegedActionException e) {
            throw new RuntimeException(e);
        }
    }
}
