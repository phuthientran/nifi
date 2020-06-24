package org.apache.nifi.web.api.entity;

import java.util.Date;

import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import com.fasterxml.jackson.annotation.JsonFormat;
import org.apache.nifi.web.api.dto.util.DateTimeAdapter;

/**
 * A serialized representation of this class can be placed in the entity body of
 * a request to the API to replay items from the specified component that were
 * dropped within the provided date range.
 * 
 * The clusterNodeId can remain null if the NiFi instance is not running in a cluster.
 */
@XmlRootElement(name = "componentReplayRequestEntity")
public class SubmitComponentReplayRequestEntity {

    private String componentId;
    private String clusterNodeId;
    private Date startDate;
    private Date endDate;
    private Integer maxResults;

	public String getComponentId() {
		return componentId;
	}

	public void setComponentId(String queueId) {
		this.componentId = queueId;
	}

	public String getClusterNodeId() {
		return clusterNodeId;
	}

	public void setClusterNodeId(String clusterNodeId) {
		this.clusterNodeId = clusterNodeId;
	}

	@XmlJavaTypeAdapter(DateTimeAdapter.class)
	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern=DateTimeAdapter.DEFAULT_DATE_TIME_FORMAT)
	public Date getStartDate() {
		return startDate;
	}

	public void setStartDate(Date startDate) {
		this.startDate = startDate;
	}

	@XmlJavaTypeAdapter(DateTimeAdapter.class)
	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern=DateTimeAdapter.DEFAULT_DATE_TIME_FORMAT)
	public Date getEndDate() {
		return endDate;
	}

	public void setEndDate(Date endDate) {
		this.endDate = endDate;
	}

	public Integer getMaxResults() {
		return maxResults;
	}

	public void setMaxResults(Integer maxResults) {
		this.maxResults = maxResults;
	}
}
