package com.phenom.lightsaber.partitionmanagers;

import org.apache.kafka.clients.producer.Partitioner;
import org.apache.kafka.common.Cluster;
import org.apache.kafka.common.PartitionInfo;
import org.json.JSONObject;

import java.util.List;
import java.util.Map;

public class LightSaberPartitioner implements Partitioner {

    @Override
    public int partition(String topic, Object objectKey, byte[] keyBytes, Object objectValue, byte[] valueBytes, Cluster cluster) {
        final List<PartitionInfo> partitionInfoList = cluster.availablePartitionsForTopic(topic);
        final int partitionCount = partitionInfoList.size();
        final int nonKeyPartitionCount = partitionCount - 1;

        JSONObject eventJson = new JSONObject(objectValue.toString());
        String emailKey = eventJson.has("emailId") ? eventJson.getString("emailId") : "";
        String uidKey = eventJson.has("uid") ? eventJson.getString("uid") : "";
        if (!emailKey.equals("") || !uidKey.equals("")) {
            String eventKey = emailKey.equals("") ? uidKey : emailKey;
            return Math.abs(eventKey.hashCode()) % nonKeyPartitionCount;
        } else {
            return Math.abs(objectValue.hashCode()) % nonKeyPartitionCount;
        }
    }

    @Override
    public void close() {

    }

    @Override
    public void configure(Map<String, ?> map) {

    }
}
