import {
  APIGatewayProxyEventV2,
  APIGatewayProxyResultV2,
  Handler,
} from 'aws-lambda';
import { Logger } from '@aws-lambda-powertools/logger';
import {
  DynamoDBClient,
  PutItemCommand,
  QueryCommand,
  UpdateItemCommand
} from '@aws-sdk/client-dynamodb';
import {
  Route53Client,
  ListResourceRecordSetsCommand,
  ChangeResourceRecordSetsCommand
} from '@aws-sdk/client-route-53';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import crypto from 'crypto';

const logger = new Logger();

const ddb = new DynamoDBClient({});
const r53 = new Route53Client({});
const sns = new SNSClient({});

const DDNS_TABLE_NAME = process.env.DDNS_TABLE_NAME!;
const IP_COUNT_TABLE = process.env.IP_COUNT_TABLE!;
const TOPIC_ARN = process.env.TOPIC_ARN!;
const HOSTED_ZONE_ID = process.env.HOSTED_ZONE_ID!;

interface RequestBody {
  hostname: string;
  validationHash: string;
}

export const handler: Handler<APIGatewayProxyEventV2, APIGatewayProxyResultV2> = async (
  event: APIGatewayProxyEventV2
): Promise<APIGatewayProxyResultV2> => {
  const THIRTY_DAYS = 60 * 60 * 24 * 30; // 30 days in seconds

  // Extract source IP, attach to logger context for all logs
  const sourceIp = event.requestContext?.http?.sourceIp || 'unknown';
  logger.appendKeys({ sourceIp });

  // Enforce POST method
  if (event.requestContext.http.method !== 'POST') {
    logger.error('Invalid HTTP method', {
      method: event.requestContext.http.method,
    });
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  // Validate payload
  let body: RequestBody;
  try {
    body = JSON.parse(event.body || '');
  } catch {
    logger.error('Invalid JSON payload');
    return { statusCode: 400, body: 'Invalid JSON' };
  }

  const { hostname, validationHash } = body;
  if (!hostname || !validationHash) {
    logger.error('Missing required fields', { body });
    return { statusCode: 400, body: 'Missing hostname or validationHash' };
  }

  try {
    // Query for the latest record by hostname
    const queryResult = await ddb.send(new QueryCommand({
      TableName: DDNS_TABLE_NAME,
      KeyConditionExpression: "hostname = :hostname",
      ExpressionAttributeValues: {
        ":hostname": { S: hostname },
      },
      ScanIndexForward: false, // newest first
      Limit: 1,
    }));

    const latest = queryResult.Items?.[0];
    if (!latest) {
      logger.error('Hostname not found in DDB', { hostname });
      return { statusCode: 404, body: 'Hostname not found' };
    }

    const secret = latest.sharedSecret.S!;
    const lastIp = latest.ipAddress?.S;   

    // Verify hash
    const expectedHash = crypto.createHash('sha256')
      .update(`${sourceIp}|${hostname}|${secret}`)
      .digest('hex');

    if (expectedHash !== validationHash) {
      logger.error('Invalid validation hash', {
        expectedHash,
        received: validationHash,
      });

      await sns.send(new PublishCommand({
        TopicArn: TOPIC_ARN,
        Subject: `DDNS Authorization Error: Invalid Hash for ${hostname}`,
        Message: `Received hash: ${validationHash}\nExpected hash: ${expectedHash}\nSource IP: ${sourceIp}`,
      }));

      return { statusCode: 403, body: 'Invalid validation hash' };
    }

    // Query Route 53 for current record
    const r53Resp = await r53.send(new ListResourceRecordSetsCommand({
      HostedZoneId: HOSTED_ZONE_ID,
      StartRecordName: hostname,
      StartRecordType: 'A',
      MaxItems: 1,
    }));

    const currentR53Ip = r53Resp.ResourceRecordSets?.[0]?.ResourceRecords?.[0]?.Value;
    logger.info('Route 53 A record fetched', {
      currentR53Ip,
      lastIp,
    });

    // Detect drift & alert if needed
    if (currentR53Ip && lastIp && currentR53Ip !== lastIp) {
      logger.warn('Drift detected between Route 53 and DynamoDB', {
        route53: currentR53Ip,
        ddb: lastIp,
      });

      await sns.send(new PublishCommand({
        TopicArn: TOPIC_ARN,
        Subject: `DDNS Drift Alert: ${hostname}`,
        Message: `Route 53 IP: ${currentR53Ip}\nDynamoDB IP: ${lastIp}`,
      }));

      await ddb.send(new PutItemCommand({
        TableName: DDNS_TABLE_NAME,
        Item: {
          hostname: { S: hostname },
          timestamp: { S: new Date().toISOString() },
          ipAddress: { S: currentR53Ip },
          sharedSecret: { S: secret },
          ttl: { N: (Math.floor(Date.now() / 1000) + THIRTY_DAYS).toString() },
        },
      }));
    }

    // If Route 53 differs from *current* client IP, update it
    if (currentR53Ip !== sourceIp) {
      logger.info('Updating Route 53 record', {
        old: currentR53Ip,
        new: sourceIp,
      });

      await r53.send(new ChangeResourceRecordSetsCommand({
        HostedZoneId: HOSTED_ZONE_ID,
        ChangeBatch: {
          Changes: [{
            Action: 'UPSERT',
            ResourceRecordSet: {
              Name: hostname,
              Type: 'A',
              TTL: 600,
              ResourceRecords: [{ Value: sourceIp }],
            },
          }],
        },
      }));
  

      // Store new time series record with TTL
      const now = new Date();
      const nowIso = now.toISOString();
      const ttlSeconds = Math.floor(now.getTime() / 1000) + THIRTY_DAYS; // expire in 30 days

      await ddb.send(new PutItemCommand({
        TableName: DDNS_TABLE_NAME,
        Item: {
          hostname: { S: hostname },
          timestamp: { S: nowIso },
          ipAddress: { S: sourceIp },
          sharedSecret: { S: secret },
          ttl: { N: ttlSeconds.toString() },
        },
      }));

      // Atomically increment IP usage counter
      await ddb.send(new UpdateItemCommand({
        TableName: IP_COUNT_TABLE,
        Key: { ipAddress: { S: sourceIp } },
        UpdateExpression: "ADD #c :incr",
        ExpressionAttributeNames: { "#c": "count" },
        ExpressionAttributeValues: { ":incr": { N: "1" } },
      }));

      logger.info('DDNS update completed successfully');

      return {
        statusCode: 200,
        body: JSON.stringify({ message: 'Updated OK' }),
      };
     } 
     
    // No Update needed, check and update TTL if necessary
    const ttl = parseInt(latest.ttl?.N!);
    
    // Store new time series record with TTL
    const now = new Date();
    const nowEpochTime = Math.floor(now.getTime() / 1000);
    const THIRTY_MINS = 60 * 30; // expire in 30 minutes

    // If TTL is within 30 minutes, extend it
    if (ttl - nowEpochTime <= THIRTY_MINS) {
      const newTtl = nowEpochTime + THIRTY_DAYS; // expire in 30 days
      
      await ddb.send(new UpdateItemCommand({
        TableName: DDNS_TABLE_NAME,
        Key: { hostname: { S: hostname }, timestamp: { S: latest.timestamp.S! } },
        UpdateExpression: "SET ttl = :newttl",
        ExpressionAttributeValues: {
          ":newttl": { N: newTtl.toString() },
        },
      }));
      

      logger.info('TTL extended for existing DDB record; Route 53 already matches client IP', {
        currentR53Ip,
        hostname,
      });
    
      return {
        statusCode: 200,
        body: JSON.stringify({ message: 'No update required, but DDB TTL extended' }),
      };
    }

    logger.info('No update needed', {
      currentR53Ip,
      lastIp,
      hostname,
    });

    return {
      statusCode: 200,
      body: JSON.stringify({ message: 'No update required' }),
    };
  } catch (error) {
    logger.error('Unhandled error', { error });
    await sns.send(new PublishCommand({
      TopicArn: TOPIC_ARN,
      Subject: `DDNS Fatal Error`,
      Message: `Error: ${JSON.stringify(error)}`,
    }));
    return {
      statusCode: 500,
      body: 'Internal Server Error',
    };
  }
};