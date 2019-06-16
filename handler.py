import json
import time
import boto3
import logging
import iso8601
#import requests
from base64 import b64decode
from pyparsing import Word, Suppress, nums, Optional, Regex, pyparsing_common, alphanums
from syslog import LOG_DEBUG, LOG_WARNING, LOG_INFO, LOG_NOTICE
from collections import defaultdict

class Parser(object):
    def __init__(self):
        ints = Word(nums)

        # priority
        priority = Suppress("<") + ints + Suppress(">")

        # version
        version = ints

        # timestamp
        timestamp = pyparsing_common.iso8601_datetime

        # hostname
        hostname = Word(alphanums + "_" + "-" + ".")

        # source
        source = Word(alphanums + "_" + "-" + ".")

        # appname
        appname = Word(alphanums + "(" + ")" + "/" + "-" + "_" + ".") + Optional(Suppress("[") + ints + Suppress("]")) + Suppress("-")

        # message
        message = Regex(".*")

        # pattern build
        self.__pattern = priority + version + timestamp + hostname + source + appname + message

    def parse(self, line):
        parsed = self.__pattern.parseString(line)

        # https://tools.ietf.org/html/rfc5424#section-6
        # get priority/severity
        priority = int(parsed[0])
        severity = priority & 0x07
        facility = priority >> 3

        payload              = {}
        payload["priority"]  = priority
        payload["severity"]  = severity
        payload["facility"]  = facility
        payload["version"]   = parsed[1]
        payload["timestamp"] = iso8601.parse_date(parsed[2])
        payload["hostname"]  = parsed[3]
        payload["source"]    = parsed[4]
        payload["appname"]   = parsed[5]
        payload["message"]   = parsed[6]

        return payload

parser = Parser()

def respond(err, res=None):
    return {
        'statusCode': '400' if err else '200',
        'body': err.message if err else json.dumps(res),
        'headers': {
            'Content-Type': 'application/json',
        },
    }


def lambda_handler(event, context):
    print("Received event: " + json.dumps(event))
    handle_lambda_proxy_event(event)
    return {
        "isBase64Encoded": False,
        "statusCode": 200,
        "headers": {"Content-Length": 0},
    }


def handle_lambda_proxy_event(event):
    body = event['body']
    headers = event['headers']
    if "pathParameters" in event and event["pathParameters"]:
        logGroup      = event["pathParameters"]["logGroup"]
        logStreamName = event["pathParameters"]["logStream"]
    else:
        logGroup      = "heroku-default-loggroup"
        logStreamName = "heroku-default-logStreamName"

    # sanity-check source
    assert headers['X-Forwarded-Proto'] == 'https'
    assert headers['Content-Type'] == 'application/logplex-1'

    # split into chunks
    def get_chunk(payload):
        msg_len, syslog_msg_payload = payload.split(' ', maxsplit=1)
        msg_len = int(msg_len)

        # only grab msg_len bytes of syslog_msg
        syslog_msg = syslog_msg_payload[0:msg_len]
        next_payload = syslog_msg_payload[msg_len:]

        yield syslog_msg

        if next_payload:
            yield from get_chunk(next_payload)


    log_events = []
    chunk_count = 0
    for chunk in get_chunk(body):
        chunk_count += 1
        evt = parser.parse(chunk)
        line = "{}: {}".format(evt["timestamp"], evt["message"])
        timestamp = int(round(time.time() * 1000))
        log_events.append({"timestamp": timestamp, "message": line })
        
    if len(log_events) > 0:
        cwl = boto3.client('logs')
        stream_info = setup_log_stream(cwl, logGroup, logStreamName)
        send_to_cloudwatch(cwl, logGroup, logStreamName, log_events, stream_info)

    # sanity-check number of parsed messages
    assert int(headers['Logplex-Msg-Count']) == chunk_count

    return ""


def setup_log_stream(cwl, logGroup, logGroupStream):
    stream_info = {}
    stream_infos = []
    try:
        stream_infos = cwl.describe_log_streams(logGroupName=logGroup, logStreamNamePrefix=logGroupStream)["logStreams"]
    except cwl.exceptions.ResourceNotFoundException:
        try:
            cwl.create_log_group(logGroupName=logGroup)
        except cwl.exceptions.ResourceAlreadyExistsException:
            print("Ignoring already existing log group - possible raise condition between lambda handlers")
            
    if len(stream_infos) > 0:
        stream_info = stream_infos[0]
    else:
        try:
            cwl.create_log_stream(logGroupName=logGroup, logStreamName=logGroupStream)
        except cwl.exceptions.ResourceAlreadyExistsException:
            print("Ignoring already existing log stream  - possible raise condition between lambda handlers")
    return stream_info


def send_to_cloudwatch(cwl, logGroup, logGroupStream, log_events, stream_info):
    try:
        if 'uploadSequenceToken' not in stream_info:
            cwl.put_log_events( logGroupName=logGroup, logStreamName=logGroupStream, logEvents=log_events )
        else:
            cwl.put_log_events( logGroupName=logGroup, logStreamName=logGroupStream, logEvents=log_events, sequenceToken=stream_info["uploadSequenceToken"] )
    except cwl.exceptions.DataAlreadyAcceptedException:
        print("Ignoring log event already sent to loggroup {} and logstream {}".format(logGroup, logGroupStream))
        
        

