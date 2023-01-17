/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.ml.action.tasks;

import static org.opensearch.common.xcontent.XContentParserUtils.ensureExpectedToken;
import static org.opensearch.ml.common.CommonValue.ML_TASK_INDEX;
import static org.opensearch.ml.utils.MLNodeUtils.createXContentParserFromRegistry;

import lombok.extern.log4j.Log4j2;

import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.ml.common.MLTask;
import org.opensearch.ml.common.MLTaskState;
import org.opensearch.ml.common.exception.MLResourceNotFoundException;
import org.opensearch.ml.common.transport.task.MLTaskDeleteAction;
import org.opensearch.ml.common.transport.task.MLTaskDeleteRequest;
import org.opensearch.ml.common.transport.task.MLTaskGetRequest;
import org.opensearch.ml.common.transport.task.MLTaskGetResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

@Log4j2
public class DeleteTaskTransportAction extends HandledTransportAction<ActionRequest, DeleteResponse> {

    Client client;
    NamedXContentRegistry xContentRegistry;

    @Inject
    public DeleteTaskTransportAction(TransportService transportService, ActionFilters actionFilters, Client client, NamedXContentRegistry xContentRegistry) {
        super(MLTaskDeleteAction.NAME, transportService, actionFilters, MLTaskDeleteRequest::new);
        this.client = client;
        this.xContentRegistry = xContentRegistry;
    }

    @Override
    protected void doExecute(Task task, ActionRequest request, ActionListener<DeleteResponse> actionListener) {
        MLTaskDeleteRequest mlTaskDeleteRequest = MLTaskDeleteRequest.fromActionRequest(request);
        String taskId = mlTaskDeleteRequest.getTaskId();
        MLTaskGetRequest mlTaskGetRequest = new MLTaskGetRequest(taskId);
        GetRequest getRequest = new GetRequest(ML_TASK_INDEX).id(taskId);

        try (ThreadContext.StoredContext context = client.threadPool().getThreadContext().stashContext()) {
            client.get(getRequest, ActionListener.wrap(r -> {
                log.debug("Completed Get Task Request, id:{}", taskId);

                if (r != null && r.isExists()) {
                    try (XContentParser parser = createXContentParserFromRegistry(xContentRegistry, r.getSourceAsBytesRef())) {
                        ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
                        MLTask mlTask = MLTask.parse(parser);
                        MLTaskState mlTaskState = mlTask.getState();
                        if (mlTaskState.equals(MLTaskState.RUNNING)) {
                            actionListener.onFailure(new Exception("Task cannot be deleted in running state"));
                        } else {
                            deleteTask(taskId, actionListener);
                        }
                    } catch (Exception e) {
                        log.error("Failed to parse ml task" + r.getId(), e);
                        actionListener.onFailure(e);
                    }
                } else {
                    actionListener.onFailure(new MLResourceNotFoundException("Fail to find task"));
                }
            }, e -> {
                if (e instanceof IndexNotFoundException) {
                    actionListener.onFailure(new MLResourceNotFoundException("Fail to find task"));
                } else {
                    log.error("Failed to get ML task " + taskId, e);
                    actionListener.onFailure(e);
                }
            }));
        } catch (Exception e) {
            log.error("Failed to get ML task " + taskId, e);
            actionListener.onFailure(e);
        }
    }
    private void deleteTask(String taskId, ActionListener<DeleteResponse> actionListener) {
        DeleteRequest deleteRequest = new DeleteRequest(ML_TASK_INDEX, taskId);

        try (ThreadContext.StoredContext context = client.threadPool().getThreadContext().stashContext()) {
            client.delete(deleteRequest, new ActionListener<DeleteResponse>() {
                @Override
                public void onResponse(DeleteResponse deleteResponse) {
                    log.debug("Completed Delete Task Request, task id:{} deleted", taskId);
                    actionListener.onResponse(deleteResponse);
                }

                @Override
                public void onFailure(Exception e) {
                    log.error("Failed to delete ML Task " + taskId, e);
                    actionListener.onFailure(e);
                }
            });
        } catch (Exception e) {
            log.error("Failed to delete ML task " + taskId, e);
            actionListener.onFailure(e);
        }
    }
}
