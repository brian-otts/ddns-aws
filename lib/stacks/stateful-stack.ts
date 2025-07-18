import { RemovalPolicy, Stack, StackProps } from 'aws-cdk-lib';
import { Table, AttributeType, BillingMode } from 'aws-cdk-lib/aws-dynamodb';
import { HostedZone, IHostedZone } from 'aws-cdk-lib/aws-route53';
import { Construct } from 'constructs';

interface StatefulStackProps extends StackProps {
  domainName: string;
}

export class StatefulStack extends Stack {
  readonly table: Table;
  readonly ipCountTable: Table;
  readonly hostedZone: IHostedZone;

  constructor(scope: Construct, id: string, props: StatefulStackProps) {
    super(scope, id, props);

    this.hostedZone = HostedZone.fromLookup(this, 'HostedZone', {
      domainName: props.domainName,
    });

    this.table = new Table(this, 'DDNSTable', {
      tableName: "DDNS",
      partitionKey: { name: 'hostname', type: AttributeType.STRING },
      sortKey: { name: 'timestamp', type: AttributeType.STRING },
      timeToLiveAttribute: 'ttl',
      billingMode: BillingMode.PAY_PER_REQUEST,
      removalPolicy: RemovalPolicy.DESTROY
    });

    this.ipCountTable = new Table(this, 'IpCountTable', {
      tableName: "IpCount",
      partitionKey: { name: 'ipAddress', type: AttributeType.STRING },
      billingMode: BillingMode.PAY_PER_REQUEST,
      removalPolicy: RemovalPolicy.DESTROY
    });
  }
}
