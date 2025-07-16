#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import { StatefulStack, StatelessStack } from "../lib/stacks";

const env: cdk.Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
};

const app = new cdk.App();

const notificationEmail =
  app.node.tryGetContext("notificationEmail") || process.env.NOTIFICATION_EMAIL;
const domainName =
  app.node.tryGetContext("domainName") || process.env.DOMAIN_NAME;

if (!notificationEmail || !domainName) {
  throw new Error(
    "Missing context: notificationEmail and domainName are required."
  );
}

const stateful = new StatefulStack(app, "DdnsStatefulStack", {
  env,
  domainName,
});

new StatelessStack(app, "DdnsStatelessStack", {
  env,
  table: stateful.table,
  ipCountTable: stateful.ipCountTable,
  notificationEmail,
  hostedZone: stateful.hostedZone,
});
