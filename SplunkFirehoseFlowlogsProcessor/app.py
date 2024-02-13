import base64
import json
import boto3
import json
import asyncio
import aiohttp
import logging
import requests
import gzip
import sys

# Configure logging
logging.basicConfig(level=logging.DEBUG)

def transformLogEvent(log_event, owner, arn, log_group, log_stream, subscription_filter):
    """Transform each log event.

    The default implementation below extracts the message, parses it as JSON, and ensures it's valid before returning.

    Args:
    log_event (dict): The original log event. Structure is {"id": str, "timestamp": long, "message": str}
    owner (str): The owner of the log event.
    arn (str): The ARN of the log event.
    log_group (str): The log group of the log event.
    log_stream (str): The log stream of the log event.
    subscription_filter (str): The subscription filter of the log event.

    Returns:
    str: The transformed log event if valid, otherwise an empty string.
    """
    logging.debug(f"Transforming log event {log_event['message']}")
    transformed_event = {}
    transformed_event["event"] = log_event['message']
    if "cloudtrail" in log_group:
        # Add sourcetype for Splunk
        transformed_event["sourcetype"] = "aws:cloudtrail"  
    if "securityhub" in log_group:
        # Add sourcetype for Splunk
        transformed_event["sourcetype"] = "aws:securityhub:finding"
        # Strip the CloudWatch event envelope and just send the finding
        transformed_event["event"] = json.dumps(json.loads(log_event['message'])["detail"]["findings"][0])

    return json.dumps(transformed_event)
    try:
        message = log_event['message']
        logging.debug(f'Transforming event {message}')
        parsed_message = json.loads(message)
        transformed_message = json.dumps(parsed_message)
        logging.debug(f'Transformed message: {message}')
        return log_event
    except (json.JSONDecodeError, KeyError):
        return ''
    
def processRecords(records):
    logging.debug(f"Number of records: {len(records)}")
    for r in records:
        recId = r['recordId']
        logging.debug(f'Processing record {recId}')
        data = base64.b64decode(r['data'])
        logging.debug(f'Data: {data[:100]}')
        
        # Check if data is gzip compressed
        if data[:2] == b'\x1f\x8b':
            data = gzip.decompress(data)
            #logging.debug(f'Decompressed Data: {data}')
        
        data = json.loads(data.decode('utf8'))
        #logging.debug(f'JSON Data: {data}')

        joinedData = ''.join([transformLogEvent(e,data['owner'],"fake_arn",data['logGroup'],data['logStream'],data['subscriptionFilters'][0]) for e in data['logEvents']])
        logging.debug(f'Joined data: {joinedData}')
        dataBytes = joinedData.encode("utf-8")
        encodedData = base64.b64encode(dataBytes)
        yield {
            'data': encodedData,
            'result': 'Ok',
            'recordId': recId
        }

def sendEventsToSplunk(records):
    logging.debug(f"Sending events to Splunk {records}")
    for record in records:
        response = sendEventToSplunk(record)
        logging.debug(f"Response: {response}")
        if response != 200:
            logging.debug(f"Failed to send event to Splunk: {record}")
            record["result"] = "Failed"
    return records
   
def sendEventToSplunk(record):
    logging.debug(f"Sending event to Splunk: {record}")
    splunk_url = "https://localhost:8088/services/collector/event"
    splunk_token = "a9d40f5de-1d4d-4852-aad4-1b9e2c3f0166"

    headers = {
        "Authorization": "Splunk " + splunk_token,
        "Content-Type": "application/json"
    }

    payload =  base64.b64decode(record["data"]).decode('utf-8')
    logging.debug(f'Sending payload')

    response = requests.post(splunk_url, headers=headers, data=payload,verify=False)
    response.raise_for_status()
    logging.debug(f"Response: {response.status_code} - {response.text}")
    return response.status_code

def putRecordsToFirehoseStream(streamName, records, client, attemptsMade, maxAttempts):
    logging.debug("Putting records to Firehose stream")
    failedRecords = []
    codes = []
    errMsg = ''
    # if put_record_batch throws for whatever reason, response['xx'] will error out, adding a check for a valid
    # response will prevent this
    response = None
    try:
        response = client.put_record_batch(DeliveryStreamName=streamName, Records=records)
    except Exception as e:
        failedRecords = records
        errMsg = str(e)

    # if there are no failedRecords (put_record_batch succeeded), iterate over the response to gather results
    if not failedRecords and response and response['FailedPutCount'] > 0:
        for idx, res in enumerate(response['RequestResponses']):
            # (if the result does not have a key 'ErrorCode' OR if it does and is empty) => we do not need to re-ingest
            if 'ErrorCode' not in res or not res['ErrorCode']:
                continue

            codes.append(res['ErrorCode'])
            failedRecords.append(records[idx])

        errMsg = 'Individual error codes: ' + ','.join(codes)

    if len(failedRecords) > 0:
        if attemptsMade + 1 < maxAttempts:
            logging.debug('Some records failed while calling PutRecordBatch to Firehose stream, retrying. %s' % (errMsg))
            putRecordsToFirehoseStream(streamName, failedRecords, client, attemptsMade + 1, maxAttempts)
        else:
            raise RuntimeError('Could not put records after %s attempts. %s' % (str(maxAttempts), errMsg))

def createReingestionRecord(originalRecord):
    logging.debug("Creating re-ingestion record")
    return {'data': base64.b64decode(originalRecord['data'])}


def getReingestionRecord(reIngestionRecord):
    logging.debug("Getting re-ingestion record")
    return {'Data': reIngestionRecord['data']}


def lambda_handler(event, context):
    logging.debug("Lambda handler called")
    #logging.debug(f"Event: {event[:100]}")
    streamARN = event['deliveryStreamArn']
    region = streamARN.split(':')[3]
    streamName = streamARN.split('/')[1]
    logging.debug(f"Records: {event['records']}")
    records = list(processRecords(event['records']))
    projectedSize = 0
    dataByRecordId = {rec['recordId']: createReingestionRecord(rec) for rec in event['records']}
    putRecordBatches = []
    recordsToReingest = []
    totalRecordsToBeReingested = 0

    for idx, rec in enumerate(records):
        projectedSize += len(rec['data']) + len(rec['recordId'])
        # 6000000 instead of 6291456 to leave ample headroom for the stuff we didn't account for
        if projectedSize > 6000000:
            totalRecordsToBeReingested += 1
            recordsToReingest.append(
                getReingestionRecord(dataByRecordId[rec['recordId']])
            )
            records[idx]['result'] = 'Dropped'
            del(records[idx]['data'])

        # split out the record batches into multiple groups, 500 records at max per group
        if len(recordsToReingest) == 500:
            putRecordBatches.append(recordsToReingest)
            recordsToReingest = []

    if len(recordsToReingest) > 0:
        # add the last batch
        putRecordBatches.append(recordsToReingest)

    # iterate and call putRecordBatch for each group
    recordsReingestedSoFar = 0
    if len(putRecordBatches) > 0:
        client = boto3.client('firehose', region_name=region)
        for recordBatch in putRecordBatches:
            putRecordsToFirehoseStream(streamName, recordBatch, client, attemptsMade=0, maxAttempts=20)
            recordsReingestedSoFar += len(recordBatch)
            logging.debug('Reingested %d/%d records out of %d' % (recordsReingestedSoFar, totalRecordsToBeReingested, len(event['records'])))
    else:
        logging.debug('No records to be reingested')
    
    # send events to Splunk if there are any failes then set the record result to failed
    records = sendEventsToSplunk(records)
    logging.debug(f"Records: {records}")
    return {"records": records}