import {
  APIGatewayProxyEventV2,
  APIGatewayProxyResultV2,
  Handler,
} from 'aws-lambda';
import { Logger } from '@aws-lambda-powertools/logger';
import {
  DynamoDBClient,
  QueryCommand,
  PutItemCommand,
  UpdateItemCommand,
} from '@aws-sdk/client-dynamodb';
import {
  Route53Client,
  ListResourceRecordSetsCommand,
  ChangeResourceRecordSetsCommand,
} from '@aws-sdk/client-route-53';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import crypto from 'node:crypto';
import { log } from 'node:console';

const logger = new Logger();

const ddb = new DynamoDBClient({});
const r53 = new Route53Client({});
const sns = new SNSClient();

const {
  DDNS_TABLE_NAME,
  IP_COUNT_TABLE,
  TOPIC_ARN,
  HOSTED_ZONE_ID,
  ALLOWED_TIMESTAMP_DRIFT = '300',
} = process.env;

const THIRTY_DAYS_SEC = 60 * 60 * 24 * 30;
const THIRTY_MIN_SEC = 60 * 30;
const ALLOWED_SKEW = parseInt(ALLOWED_TIMESTAMP_DRIFT);

interface RequestBody {
  ipAddress: string;
  hostname: string;
  timestamp: string;
  validationHmac: string;
}

export const handler: Handler<
  APIGatewayProxyEventV2,
  APIGatewayProxyResultV2
> = async (event) => {
  const sourceIp = event.requestContext?.http?.sourceIp || 'unknown';
  logger.appendKeys({ sourceIp });
  
  logger.debug('Received request', {
    method: event.requestContext.http.method,
    body: event.body,
    headers: event.headers,
  });


  if (event.requestContext.http.method !== 'POST') {
    return respond(405, 'Method Not Allowed');
  }

  let body: RequestBody;
  try {
    body = JSON.parse(event.body || '');
  } catch {
    return respond(400, 'Invalid JSON');
  }

  const { ipAddress, hostname, timestamp, validationHmac } = body;
  if (!ipAddress || !hostname || !timestamp || !validationHmac) {
    return respond(400, 'Missing fields');
  }

  if (sourceIp !== ipAddress) {
    const suspiciousActivityPrefix = 'Suspicious Activity';
    logger.warn(`${suspiciousActivityPrefix} - Source IP does not match provided IP`, { ipAddress });
    await alert(`${suspiciousActivityPrefix} - IP Mismatch for ${hostname}`, `Source IP: ${sourceIp}\nProvided IP: ${ipAddress}`);
    return respond(403, 'Source IP does not match provided IP');
  }

  try {
    // Load secret for this hostname
    const query = await ddb.send(new QueryCommand({
      TableName: DDNS_TABLE_NAME!,
      KeyConditionExpression: "hostname = :h",
      ExpressionAttributeValues: { ":h": { S: hostname } },
      ScanIndexForward: false,  // get latest entry for hostname
      Limit: 1,
    }));
    const latest = query.Items?.[0];
    if (!latest) return respond(404, 'Hostname not found');

    const secret = latest.sharedSecret.S!;
    const dnsRecordTtl = latest.dnsRecordTtl?.N ? parseInt(latest.dnsRecordTtl.N) : 600;

    // Validate timestamp & HMAC
    const nowEpoch = Math.floor(Date.now() / 1000);
    const tsEpoch = Math.floor(new Date(timestamp).getTime() / 1000);
    if (Math.abs(nowEpoch - tsEpoch) > ALLOWED_SKEW) {
      return respond(400, 'Invalid timestamp');
    }

    const expectedHmac = crypto.createHmac('sha256', secret)
      .update(`${ipAddress}|${hostname}|${timestamp}`)
      .digest('hex');

    if (!safeEqual(expectedHmac, validationHmac)) {
      logger.critical('Invalid HMAC');
      await alert(`Auth Error for ${hostname}`, `Bad HMAC from IP: ${sourceIp}`);
      return respond(403, 'Invalid HMAC');
    }

    // Get current A record
    const r53Resp = await r53.send(new ListResourceRecordSetsCommand({
      HostedZoneId: HOSTED_ZONE_ID!,
      StartRecordName: hostname,
      StartRecordType: 'A',
      MaxItems: 1,
    }));
    const currentR53Ip = r53Resp.ResourceRecordSets?.[0]?.ResourceRecords?.[0]?.Value;
    const lastIp = latest.ipAddress?.S;

    // Drift check
    if (currentR53Ip && lastIp && currentR53Ip !== lastIp) {
      logger.warn('Drift detected', { route53: currentR53Ip, ddb: lastIp });
      await alert(`Drift Alert: ${hostname}`, `Route53: ${currentR53Ip}\nDDB: ${lastIp}`);
      await saveIp(hostname, currentR53Ip, secret);
    }

    // If IP differs, update
    if (currentR53Ip !== sourceIp) {
      await updateRoute53(hostname, sourceIp, dnsRecordTtl);
      await saveIp(hostname, sourceIp, secret);
      await incrementIpCount(sourceIp);
      return respond(200, 'Updated OK');
    }

    // Otherwise, extend DDB record's TTL if nearly expired
    const ttl = parseInt(latest.ttl?.N!);
    if (ttl - nowEpoch <= THIRTY_MIN_SEC) {
      await extendTtl(hostname, latest.timestamp.S!, nowEpoch + THIRTY_DAYS_SEC);
      return respond(200, 'No update, TTL extended');
    }

    return respond(200, 'No update needed');

  } catch (err: Error | unknown) {
    logger.error('Unhandled error', { err });
    if (err instanceof Error) {
      await alert('DDNS Fatal Error', `${err.name}: ${err.message}\n${err.stack}`);
    } else {
      await alert('DDNS Fatal Error', `Non-error thrown: ${JSON.stringify(err)}`);
    }
    
    return respond(500, 'Internal Server Error');
  }
};

function respond(code: number, msg: string): APIGatewayProxyResultV2 {
  logger.info('Response', { code, msg });
  return { statusCode: code, body: JSON.stringify({ message: msg }) };
}

function safeEqual(a: string, b: string) {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
}

async function alert(subject: string, msg: string) {
  logger.warn('Alerting via SNS', { subject, msg });
  await sns.send(new PublishCommand({
    TopicArn: TOPIC_ARN!,
    Subject: subject,
    Message: msg,
  }));
  logger.info('Alert sent', { subject });
}

async function updateRoute53(name: string, ip: string, ttl: number = 600) {
  logger.debug('Updating Route53 record', { name, ttl });
  await r53.send(new ChangeResourceRecordSetsCommand({
    HostedZoneId: HOSTED_ZONE_ID!,
    ChangeBatch: {
      Changes: [{
        Action: 'UPSERT',
        ResourceRecordSet: {
          Name: name,
          Type: 'A',
          TTL: ttl,
          ResourceRecords: [{ Value: ip }],
        },
      }],
    },
  }));
  logger.info('Route53 record updated', { name, ttl });
}

async function saveIp(hostname: string, ip: string, secret: string) {
  const now = new Date();
  const ttl = Math.floor(now.getTime() / 1000) + THIRTY_DAYS_SEC;
  logger.debug('Saving new IP to DDB', { hostname, ttl });
  await ddb.send(new PutItemCommand({
    TableName: DDNS_TABLE_NAME!,
    Item: {
      hostname: { S: hostname },
      timestamp: { S: now.toISOString() },
      ipAddress: { S: ip },
      sharedSecret: { S: secret },
      ttl: { N: ttl.toString() },
    },
  }));
  logger.info('New IP saved to DDB', { hostname, ttl });
}

async function incrementIpCount(ip: string) {
  logger.debug('Incrementing IP count');
  await ddb.send(new UpdateItemCommand({
    TableName: IP_COUNT_TABLE!,
    Key: { ipAddress: { S: ip } },
    UpdateExpression: "ADD #c :incr",
    ExpressionAttributeNames: { "#c": "count" },
    ExpressionAttributeValues: { ":incr": { N: "1" } },
  }));
  logger.info('IP count incremented');
}

async function extendTtl(hostname: string, timestamp: string, newTtl: number) {
  logger.debug('Extending TTL for hostname', { hostname, timestamp, newTtl });
  await ddb.send(new UpdateItemCommand({
    TableName: DDNS_TABLE_NAME!,
    Key: { hostname: { S: hostname }, timestamp: { S: timestamp } },
    UpdateExpression: "SET ttl = :ttl",
    ExpressionAttributeValues: { ":ttl": { N: newTtl.toString() } },
  }));
  logger.info('TTL extended for hostname', { hostname, newTtl });
}
