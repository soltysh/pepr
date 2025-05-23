// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023-Present The Pepr Authors

import { kind, KubernetesObject } from "kubernetes-fluent-client";
import { Capability } from "../core/capability";
import { shouldSkipRequest } from "../filter/filter";
import { ValidateResponse } from "../k8s";
import { Binding } from "../types";
import Log from "../telemetry/logger";
import { convertFromBase64Map } from "../utils";
import { PeprValidateRequest } from "../validate-request";
import { ModuleConfig } from "../types";
import { resolveIgnoreNamespaces } from "../assets/ignoredNamespaces";
import { MeasureWebhookTimeout } from "../telemetry/webhookTimeouts";
import { WebhookType } from "../enums";
import { AdmissionRequest } from "../common-types";

export async function processRequest(
  binding: Binding,
  actionMetadata: Record<string, string>,
  peprValidateRequest: PeprValidateRequest<KubernetesObject>,
): Promise<ValidateResponse> {
  const label = binding.validateCallback!.name;
  Log.info(actionMetadata, `Processing validation action (${label})`);

  const valResp: ValidateResponse = {
    uid: peprValidateRequest.Request.uid,
    allowed: true, // Assume it's allowed until a validation check fails
  };

  try {
    // Run the validation callback, if it fails set allowed to false
    const callbackResp = await binding.validateCallback!(peprValidateRequest);
    valResp.allowed = callbackResp.allowed;

    // If the validation callback returned a status code or message, set it in the Response
    if (callbackResp.statusCode || callbackResp.statusMessage) {
      valResp.status = {
        code: callbackResp.statusCode || 400,
        message:
          callbackResp.statusMessage ||
          `Validation failed for ${peprValidateRequest.Request.kind.kind.toLowerCase()}/${peprValidateRequest.Request.name}${peprValidateRequest.Request.namespace ? ` in ${peprValidateRequest.Request.namespace} namespace.` : ""}`,
      };
    }

    // Transfer any warnings from the callback response to the validation response
    if (callbackResp.warnings && callbackResp.warnings.length > 0) {
      valResp.warnings = callbackResp.warnings;
    }

    Log.info(
      actionMetadata,
      `Validation action complete (${label}): ${callbackResp.allowed ? "allowed" : "denied"}`,
    );
    return valResp;
  } catch (e) {
    // If any validation throws an error, note the failure in the Response
    Log.error(actionMetadata, `Action failed: ${JSON.stringify(e)}`);
    valResp.allowed = false;
    valResp.status = {
      code: 500,
      message: `Action failed with error: ${JSON.stringify(e)}`,
    };
    return valResp;
  }
}

export async function validateProcessor(
  config: ModuleConfig,
  capabilities: Capability[],
  req: AdmissionRequest,
  reqMetadata: Record<string, string>,
): Promise<ValidateResponse[]> {
  const webhookTimer = new MeasureWebhookTimeout(WebhookType.VALIDATE);
  webhookTimer.start(config.webhookTimeout);
  const wrapped = new PeprValidateRequest(req);
  const response: ValidateResponse[] = [];

  // If the resource is a secret, decode the data
  if (req.kind.version === "v1" && req.kind.kind === "Secret") {
    convertFromBase64Map(wrapped.Raw as unknown as kind.Secret);
  }

  Log.info(reqMetadata, `Processing validation request`);

  for (const { name, bindings, namespaces } of capabilities) {
    const actionMetadata = { ...reqMetadata, name };

    for (const binding of bindings) {
      // Skip this action if it's not a validation action
      if (!binding.validateCallback) {
        continue;
      }

      // Continue to the next action without doing anything if this one should be skipped
      const shouldSkip = shouldSkipRequest(
        binding,
        req,
        namespaces,
        resolveIgnoreNamespaces(
          config?.alwaysIgnore?.namespaces?.length
            ? config?.alwaysIgnore?.namespaces
            : config?.admission?.alwaysIgnore?.namespaces,
        ),
      );
      if (shouldSkip !== "") {
        Log.debug(shouldSkip);
        continue;
      }

      const resp = await processRequest(binding, actionMetadata, wrapped);
      response.push(resp);
    }
  }
  webhookTimer.stop();
  return response;
}
