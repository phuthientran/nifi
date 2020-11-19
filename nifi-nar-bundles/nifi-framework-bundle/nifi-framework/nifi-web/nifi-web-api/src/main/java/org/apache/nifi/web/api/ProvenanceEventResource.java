/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.nifi.web.api;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;

import org.apache.nifi.cluster.coordination.ClusterCoordinator;
import org.apache.nifi.cluster.coordination.http.replication.RequestReplicator;
import org.apache.nifi.cluster.protocol.NodeIdentifier;
import org.apache.nifi.controller.repository.claim.ContentDirection;
import org.apache.nifi.provenance.ProvenanceEventType;
import org.apache.nifi.provenance.SearchableFields;
import org.apache.nifi.stream.io.StreamUtils;
import org.apache.nifi.web.DownloadableContent;
import org.apache.nifi.web.NiFiServiceFacade;
import org.apache.nifi.web.api.dto.provenance.ProvenanceDTO;
import org.apache.nifi.web.api.dto.provenance.ProvenanceEventDTO;
import org.apache.nifi.web.api.dto.provenance.ProvenanceRequestDTO;
import org.apache.nifi.web.api.entity.ProvenanceEntity;
import org.apache.nifi.web.api.entity.ProvenanceEventEntity;
import org.apache.nifi.web.api.entity.SubmitComponentReplayRequestEntity;
import org.apache.nifi.web.api.entity.SubmitReplayRequestEntity;
import org.apache.nifi.web.api.request.LongParameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.JsonProcessingException;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.StreamingOutput;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


/**
 * RESTful endpoint for querying data provenance.
 */
@Path("/provenance-events")
@Api(
        value = "/provenance-events",
        description = "Endpoint for accessing data flow provenance."
)
public class ProvenanceEventResource extends ApplicationResource {
    
    private static final Logger logger = LoggerFactory.getLogger(ProvenanceEventResource.class);

    private NiFiServiceFacade serviceFacade;

    /**
     * Gets the content for the input of the specified event.
     *
     * @param clusterNodeId The id of the node within the cluster this content is on. Required if clustered.
     * @param id            The id of the provenance event associated with this content.
     * @return The content stream
     */
    @GET
    @Consumes(MediaType.WILDCARD)
    @Produces(MediaType.WILDCARD)
    @Path("{id}/content/input")
    @ApiOperation(
            value = "Gets the input content for a provenance event",
            response = StreamingOutput.class,
            authorizations = {
                    @Authorization(value = "Read Component Provenance Data - /provenance-data/{component-type}/{uuid}"),
                    @Authorization(value = "Read Component Data - /data/{component-type}/{uuid}")
            }
    )
    @ApiResponses(
            value = {
                    @ApiResponse(code = 400, message = "NiFi was unable to complete the request because it was invalid. The request should not be retried without modification."),
                    @ApiResponse(code = 401, message = "Client could not be authenticated."),
                    @ApiResponse(code = 403, message = "Client is not authorized to make this request."),
                    @ApiResponse(code = 404, message = "The specified resource could not be found."),
                    @ApiResponse(code = 409, message = "The request was valid but NiFi was not in the appropriate state to process it. Retrying the same request later may be successful.")
            }
    )
    public Response getInputContent(
            @ApiParam(
                    value = "The id of the node where the content exists if clustered.",
                    required = false
            )
            @QueryParam("clusterNodeId") final String clusterNodeId,
            @ApiParam(
                    value = "The provenance event id.",
                    required = true
            )
            @PathParam("id") final LongParameter id) {

        // ensure proper input
        if (id == null) {
            throw new IllegalArgumentException("The event id must be specified.");
        }

        // replicate if cluster manager
        if (isReplicateRequest()) {
            // determine where this request should be sent
            if (clusterNodeId == null) {
                throw new IllegalArgumentException("The id of the node in the cluster is required.");
            } else {
                return replicate(HttpMethod.GET, clusterNodeId);
            }
        }

        // get the uri of the request
        final String uri = generateResourceUri("provenance", "events", String.valueOf(id.getLong()), "content", "input");

        // get an input stream to the content
        final DownloadableContent content = serviceFacade.getContent(id.getLong(), uri, ContentDirection.INPUT);

        // generate a streaming response
        final StreamingOutput response = new StreamingOutput() {
            @Override
            public void write(OutputStream output) throws IOException, WebApplicationException {
                try (InputStream is = content.getContent()) {
                    // stream the content to the response
                    StreamUtils.copy(is, output);

                    // flush the response
                    output.flush();
                }
            }
        };

        // use the appropriate content type
        String contentType = content.getType();
        if (contentType == null) {
            contentType = MediaType.APPLICATION_OCTET_STREAM;
        }

        return generateOkResponse(response).type(contentType).header("Content-Disposition", String.format("attachment; filename=\"%s\"", content.getFilename())).build();
    }

    /**
     * Gets the content for the output of the specified event.
     *
     * @param clusterNodeId The id of the node within the cluster this content is on. Required if clustered.
     * @param id            The id of the provenance event associated with this content.
     * @return The content stream
     */
    @GET
    @Consumes(MediaType.WILDCARD)
    @Produces(MediaType.WILDCARD)
    @Path("{id}/content/output")
    @ApiOperation(
            value = "Gets the output content for a provenance event",
            response = StreamingOutput.class,
            authorizations = {
                    @Authorization(value = "Read Component Provenance Data - /provenance-data/{component-type}/{uuid}"),
                    @Authorization(value = "Read Component Data - /data/{component-type}/{uuid}")
            }
    )
    @ApiResponses(
            value = {
                    @ApiResponse(code = 400, message = "NiFi was unable to complete the request because it was invalid. The request should not be retried without modification."),
                    @ApiResponse(code = 401, message = "Client could not be authenticated."),
                    @ApiResponse(code = 403, message = "Client is not authorized to make this request."),
                    @ApiResponse(code = 404, message = "The specified resource could not be found."),
                    @ApiResponse(code = 409, message = "The request was valid but NiFi was not in the appropriate state to process it. Retrying the same request later may be successful.")
            }
    )
    public Response getOutputContent(
            @ApiParam(
                    value = "The id of the node where the content exists if clustered.",
                    required = false
            )
            @QueryParam("clusterNodeId") final String clusterNodeId,
            @ApiParam(
                    value = "The provenance event id.",
                    required = true
            )
            @PathParam("id") final LongParameter id) {

        // ensure proper input
        if (id == null) {
            throw new IllegalArgumentException("The event id must be specified.");
        }

        // replicate if cluster manager
        if (isReplicateRequest()) {
            // determine where this request should be sent
            if (clusterNodeId == null) {
                throw new IllegalArgumentException("The id of the node in the cluster is required.");
            } else {
                return replicate(HttpMethod.GET, clusterNodeId);
            }
        }

        // get the uri of the request
        final String uri = generateResourceUri("provenance", "events", String.valueOf(id.getLong()), "content", "output");

        // get an input stream to the content
        final DownloadableContent content = serviceFacade.getContent(id.getLong(), uri, ContentDirection.OUTPUT);

        // generate a streaming response
        final StreamingOutput response = new StreamingOutput() {
            @Override
            public void write(OutputStream output) throws IOException, WebApplicationException {
                try (InputStream is = content.getContent()) {
                    // stream the content to the response
                    StreamUtils.copy(is, output);

                    // flush the response
                    output.flush();
                }
            }
        };

        // use the appropriate content type
        String contentType = content.getType();
        if (contentType == null) {
            contentType = MediaType.APPLICATION_OCTET_STREAM;
        }

        return generateOkResponse(response).type(contentType).header("Content-Disposition", String.format("attachment; filename=\"%s\"", content.getFilename())).build();
    }

    /**
     * Gets the details for a provenance event.
     *
     * @param id            The id of the event
     * @param clusterNodeId The id of node in the cluster that the event/flowfile originated from. This is only required when clustered.
     * @return A provenanceEventEntity
     */
    @GET
    @Consumes(MediaType.WILDCARD)
    @Produces(MediaType.APPLICATION_JSON)
    @Path("{id}")
    @ApiOperation(
            value = "Gets a provenance event",
            response = ProvenanceEventEntity.class,
            authorizations = {
                    @Authorization(value = "Read Component Provenance Data - /provenance-data/{component-type}/{uuid}")
            }
    )
    @ApiResponses(
            value = {
                    @ApiResponse(code = 400, message = "NiFi was unable to complete the request because it was invalid. The request should not be retried without modification."),
                    @ApiResponse(code = 401, message = "Client could not be authenticated."),
                    @ApiResponse(code = 403, message = "Client is not authorized to make this request."),
                    @ApiResponse(code = 404, message = "The specified resource could not be found."),
                    @ApiResponse(code = 409, message = "The request was valid but NiFi was not in the appropriate state to process it. Retrying the same request later may be successful.")
            }
    )
    public Response getProvenanceEvent(
            @ApiParam(
                    value = "The id of the node where this event exists if clustered.",
                    required = false
            )
            @QueryParam("clusterNodeId") final String clusterNodeId,
            @ApiParam(
                    value = "The provenance event id.",
                    required = true
            )
            @PathParam("id") final LongParameter id) {

        // ensure the id is specified
        if (id == null) {
            throw new IllegalArgumentException("Provenance event id must be specified.");
        }

        // replicate if cluster manager
        if (isReplicateRequest()) {
            // since we're cluster we must specify the cluster node identifier
            if (clusterNodeId == null) {
                throw new IllegalArgumentException("The cluster node identifier must be specified.");
            }

            return replicate(HttpMethod.GET, clusterNodeId);
        }

        // get the provenance event
        final ProvenanceEventDTO event = serviceFacade.getProvenanceEvent(id.getLong());
        event.setClusterNodeId(clusterNodeId);

        // populate the cluster node address
        final ClusterCoordinator coordinator = getClusterCoordinator();
        if (coordinator != null && clusterNodeId != null) {
            final NodeIdentifier nodeId = coordinator.getNodeIdentifier(clusterNodeId);

            if (nodeId != null) {
                event.setClusterNodeAddress(nodeId.getApiAddress() + ":" + nodeId.getApiPort());
            }
        }

        // create a response entity
        final ProvenanceEventEntity entity = new ProvenanceEventEntity();
        entity.setProvenanceEvent(event);

        // generate the response
        return generateOkResponse(entity).build();
    }

    /**
     * Creates a new replay request for the content associated with the specified provenance event id.
     *
     * @param httpServletRequest  request
     * @param replayRequestEntity The replay request
     * @return A provenanceEventEntity
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Path("replays")
    @ApiOperation(
            value = "Replays content from a provenance event",
            response = ProvenanceEventEntity.class,
            authorizations = {
                    @Authorization(value = "Read Component Provenance Data - /provenance-data/{component-type}/{uuid}"),
                    @Authorization(value = "Read Component Data - /data/{component-type}/{uuid}"),
                    @Authorization(value = "Write Component Data - /data/{component-type}/{uuid}")
            }
    )
    @ApiResponses(
            value = {
                    @ApiResponse(code = 400, message = "NiFi was unable to complete the request because it was invalid. The request should not be retried without modification."),
                    @ApiResponse(code = 401, message = "Client could not be authenticated."),
                    @ApiResponse(code = 403, message = "Client is not authorized to make this request."),
                    @ApiResponse(code = 404, message = "The specified resource could not be found."),
                    @ApiResponse(code = 409, message = "The request was valid but NiFi was not in the appropriate state to process it. Retrying the same request later may be successful.")
            }
    )
    public Response submitReplay(
            @Context final HttpServletRequest httpServletRequest,
            @ApiParam(
                    value = "The replay request.",
                    required = true
            ) final SubmitReplayRequestEntity replayRequestEntity) {

        // ensure the event id is specified
        if (replayRequestEntity == null || replayRequestEntity.getEventId() == null) {
            throw new IllegalArgumentException("The id of the event must be specified.");
        }

        // replicate if cluster manager
        if (isReplicateRequest()) {
            // determine where this request should be sent
            if (replayRequestEntity.getClusterNodeId() == null) {
                throw new IllegalArgumentException("The id of the node in the cluster is required.");
            } else {
                return replicate(HttpMethod.POST, replayRequestEntity, replayRequestEntity.getClusterNodeId());
            }
        }

        // handle expects request (usually from the cluster manager)
        final String expects = httpServletRequest.getHeader(RequestReplicator.REQUEST_VALIDATION_HTTP_HEADER);
        if (expects != null) {
            return generateContinueResponse().build();
        }

        // submit the provenance replay request
        final ProvenanceEventDTO event = serviceFacade.submitReplay(replayRequestEntity.getEventId());
        event.setClusterNodeId(replayRequestEntity.getClusterNodeId());

        // populate the cluster node address
        final ClusterCoordinator coordinator = getClusterCoordinator();
        if (coordinator != null) {
            final NodeIdentifier nodeId = coordinator.getNodeIdentifier(replayRequestEntity.getClusterNodeId());
            event.setClusterNodeAddress(nodeId.getApiAddress() + ":" + nodeId.getApiPort());
        }

        // create a response entity
        final ProvenanceEventEntity entity = new ProvenanceEventEntity();
        entity.setProvenanceEvent(event);

        // generate the response
        URI uri = URI.create(generateResourceUri("provenance-events", event.getId()));
        return generateCreatedResponse(uri, entity).build();
    }
    
    /**
     * Creates a new replay request for every {@link SubmitReplayRequestEntity} provided.
     * This endpoint can be used to conveniently submit multiple replay requests with one call.
     * It accepts one or multiple provenance events to replay.
     * 
     * @param httpServletRequest  request
     * @param replayRequestEntities list of replay request(s)
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("replays/multiple")
    @ApiOperation(
            value = "Replays content from a provenance event(s)",
            authorizations = {
                    @Authorization(value = "Read Component Provenance Data - /provenance-data/{component-type}/{uuid}"),
                    @Authorization(value = "Read Component Data - /data/{component-type}/{uuid}"),
                    @Authorization(value = "Write Component Data - /data/{component-type}/{uuid}")
            }
    )
    public void submitMultipleReplays(
            @Context final HttpServletRequest httpServletRequest,
            @ApiParam(
                    value = "The replay request(s).",
                    required = true
            ) final List<SubmitReplayRequestEntity> replayRequestEntities) {

        for (SubmitReplayRequestEntity entity: replayRequestEntities) {
            // submit replay utilizing existing code and cluster handling
            this.submitReplay(httpServletRequest, entity);
        }
    }
 
    /**
     * Queries data provenance and submits replay requests for every flowfile that was
     * dropped within the provided date range if the content is available for replay. 
     * If the content is not available for replay, the flowfile is skipped over. 
     * 
     * @param httpServletRequest
     * @param replayRequestEntity {@link SubmitComponentReplayRequestEntity}
     * @return list of dropped events that were replayed
     * @throws JsonProcessingException
     * @throws RestClientException
     * @throws URISyntaxException
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Path("replays/component")
    @ApiOperation(
            value = "Replays flowfiles dropped from component within the provided date range.",
            response = ProvenanceEntity.class,
            authorizations = {
                    @Authorization(value = "Read Component Provenance Data - /provenance-data/{component-type}/{uuid}"),
                    @Authorization(value = "Read Component Data - /data/{component-type}/{uuid}"),
                    @Authorization(value = "Write Component Data - /data/{component-type}/{uuid}")
            }
    )
    public Response submitComponentReplay(@Context final HttpServletRequest httpServletRequest,
            @ApiParam(
                    value = "The component search parameters.", 
                    required = true
                    ) final SubmitComponentReplayRequestEntity replayRequestEntity) 
                            throws JsonProcessingException, RestClientException, URISyntaxException {

        if (replayRequestEntity == null || replayRequestEntity.getComponentId() == null
                || replayRequestEntity.getStartDate() == null || replayRequestEntity.getEndDate() == null
                || replayRequestEntity.getMaxResults() == null) {
            throw new IllegalArgumentException("Component replay request entity and required fields cannot be null "
                    + "[componentId, startDate, endDate, maxResults] required.");
        }

        // create provenance request to query data provenance for dropped files
        ProvenanceRequestDTO provenanceRequest = new ProvenanceRequestDTO();
        provenanceRequest.setClusterNodeId(replayRequestEntity.getClusterNodeId());
        provenanceRequest.setStartDate(replayRequestEntity.getStartDate());
        provenanceRequest.setEndDate(replayRequestEntity.getEndDate());
        provenanceRequest.setIncrementalResults(false);
        provenanceRequest.setMaxResults(replayRequestEntity.getMaxResults());
        provenanceRequest.setSummarize(false);
        Map<String, String> searchTerms = new HashMap<>();
        searchTerms.put(SearchableFields.EventType.getIdentifier(), ProvenanceEventType.DROP.toString());
        searchTerms.put(SearchableFields.ComponentID.getIdentifier(), replayRequestEntity.getComponentId());
        provenanceRequest.setSearchTerms(searchTerms);

        ProvenanceDTO provenance = new ProvenanceDTO();
        provenance.setRequest(provenanceRequest);

        ProvenanceEntity provenanceEntity = new ProvenanceEntity();
        provenanceEntity.setProvenance(provenance);

        // setup url to query data provenance
        String requestUrl = httpServletRequest.getRequestURL().toString();
        String contextPath = httpServletRequest.getContextPath();
        String baseUrl = requestUrl.substring(0, requestUrl.indexOf(contextPath)+ contextPath.length());
        String provenanceUrl = String.format("%s/%s", baseUrl, "provenance");

        // setup rest template
        RestTemplate template = new RestTemplate();
        MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter();
        logger.info("Querying data provenance using query: {}", 
                converter.getObjectMapper().writeValueAsString(provenanceEntity));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(org.springframework.http.MediaType.APPLICATION_JSON);
        headers.setAccept(Arrays.asList(org.springframework.http.MediaType.APPLICATION_JSON));
        headers.setContentLength(converter.getObjectMapper().writeValueAsBytes(provenanceEntity).length);
        template.setMessageConverters(Arrays.asList(converter));
        HttpEntity<ProvenanceEntity> entity = new HttpEntity<>(provenanceEntity, headers);

        // query data provenance
        ProvenanceEntity results = template.exchange(new URI(provenanceUrl), 
                org.springframework.http.HttpMethod.POST, entity, ProvenanceEntity.class).getBody();

        // log number of total events returned and events with content replay available
        List<ProvenanceEventDTO> eventsWithReplayAvailable = results.getProvenance().getResults().getProvenanceEvents()
                .stream()
                .filter(event -> event.getReplayAvailable())
                .collect(Collectors.toList());
        logger.info("Total events returned [{}], submitting replay for [{}] drop events from component {}", 
                results.getProvenance().getResults().getTotal(),
                eventsWithReplayAvailable.size(),
                replayRequestEntity.getComponentId());

        // submit replay events
        for (ProvenanceEventDTO provenanceEvent: eventsWithReplayAvailable) {
            SubmitReplayRequestEntity replayEntity = new SubmitReplayRequestEntity();
            replayEntity.setEventId(provenanceEvent.getEventId());
            replayEntity.setClusterNodeId(provenanceEvent.getClusterNodeId());
            this.submitReplay(httpServletRequest, replayEntity);
        }

        // return replayed events
        URI uri = URI.create(generateResourceUri("/replays/queue"));
        return generateCreatedResponse(uri, eventsWithReplayAvailable).build();
    }

    // setters
    public void setServiceFacade(NiFiServiceFacade serviceFacade) {
        this.serviceFacade = serviceFacade;
    }
}
