import { Stack, StackProps, CfnOutput } from 'aws-cdk-lib';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
import { Runtime, FunctionUrlAuthType, HttpMethod } from 'aws-cdk-lib/aws-lambda';
import { RetentionDays } from 'aws-cdk-lib/aws-logs';
import { PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { ITable } from 'aws-cdk-lib/aws-dynamodb';
import { ITopic } from 'aws-cdk-lib/aws-sns';
import { IHostedZone } from 'aws-cdk-lib/aws-route53';
import { Construct } from 'constructs';
import * as path from 'path';

interface StatelessStackProps extends StackProps {
  table: ITable;
  ipCountTable: ITable;
  topic: ITopic;
  hostedZone: IHostedZone;
}

export class StatelessStack extends Stack {
  constructor(scope: Construct, id: string, props: StatelessStackProps) {
    super(scope, id, props);

    const fn = new NodejsFunction(this, 'DDNSFunction', {
      runtime: Runtime.NODEJS_22_X,
      entry: path.join(__dirname, '../../lambda/handler.ts'),
      environment: {
        DDNS_TABLE_NAME: props.table.tableName,
        IP_COUNT_TABLE: props.ipCountTable.tableName,
        TOPIC_ARN: props.topic.topicArn,
        HOSTED_ZONE_ID: props.hostedZone.hostedZoneId,
        ALLOWED_TIMESTAMP_DRIFT: '300', // 5 minutes
        POWERTOOLS_SERVICE_NAME: 'DDNSFunction',
        POWERTOOLS_LOG_LEVEL: 'INFO',
        POWERTOOLS_LOGGER_LOG_EVENT: 'true',  // Only works if you inject context in the handler
      },
      logRetention: RetentionDays.ONE_MONTH,
    });

    props.table.grantReadWriteData(fn);
    props.ipCountTable.grantReadWriteData(fn);
    props.topic.grantPublish(fn);

    fn.addToRolePolicy(new PolicyStatement({
      actions: ['route53:ChangeResourceRecordSets', 'route53:ListResourceRecordSets'],
      resources: [props.hostedZone.hostedZoneArn],
    }));

    const fnUrl = fn.addFunctionUrl({
      authType: FunctionUrlAuthType.NONE,
      cors: {
        allowedOrigins: ['*'],
        allowedMethods: [HttpMethod.POST],
      },
    });

    new CfnOutput(this, 'FunctionUrl', { value: fnUrl.url });
  }
}
