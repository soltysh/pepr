// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023-Present The Pepr Authors

import Log from "./telemetry/logger";
import { Binding, CapabilityExport } from "./types";
import { sanitizeResourceName } from "../sdk/sdk";

export function matchesRegex(pattern: string, testString: string): boolean {
  return new RegExp(pattern).test(testString);
}

export class ValidationError extends Error {}

export function validateCapabilityNames(capabilities: CapabilityExport[] | undefined): void {
  if (capabilities && capabilities.length > 0) {
    for (let i = 0; i < capabilities.length; i++) {
      if (capabilities[i].name !== sanitizeResourceName(capabilities[i].name)) {
        throw new ValidationError(
          `Capability name is not a valid Kubernetes resource name: ${capabilities[i].name}`,
        );
      }
    }
  }
}

export function validateHash(expectedHash: string): void {
  // Require the hash to be a valid SHA-256 hash (64 characters, hexadecimal)
  const sha256Regex = /^[a-f0-9]{64}$/i;
  if (!expectedHash || !sha256Regex.test(expectedHash)) {
    Log.error(`Invalid hash. Expected a valid SHA-256 hash, got ${expectedHash}`);
    throw new ValidationError("Invalid hash");
  }
}

type RBACMap = {
  [key: string]: {
    verbs: string[];
    plural: string;
  };
};

export function createRBACMap(capabilities: CapabilityExport[]): RBACMap {
  return capabilities.reduce((acc: RBACMap, capability: CapabilityExport) => {
    capability.bindings.forEach(binding => {
      const key = `${binding.kind.group}/${binding.kind.version}/${binding.kind.kind}`;

      acc["pepr.dev/v1/peprstore"] = {
        verbs: ["create", "get", "patch", "watch"],
        plural: "peprstores",
      };

      acc["apiextensions.k8s.io/v1/customresourcedefinition"] = {
        verbs: ["patch", "create"],
        plural: "customresourcedefinitions",
      };

      if (!acc[key] && binding.isWatch) {
        acc[key] = {
          verbs: ["watch"],
          plural: binding.kind.plural || `${binding.kind.kind.toLowerCase()}s`,
        };
      }

      // Add finalizer rbac
      if (binding.isFinalize) {
        acc[key] = {
          verbs: ["patch"],
          plural: binding.kind.plural || `${binding.kind.kind.toLowerCase()}s`,
        };
      }
    });

    return acc;
  }, {});
}

export function hasEveryOverlap<T>(array1: T[], array2: T[]): boolean {
  if (!Array.isArray(array1) || !Array.isArray(array2)) {
    return false;
  }

  return array1.every(element => array2.includes(element));
}

export function hasAnyOverlap<T>(array1: T[], array2: T[]): boolean {
  if (!Array.isArray(array1) || !Array.isArray(array2)) {
    return false;
  }

  return array1.some(element => array2.includes(element));
}

export function ignoredNamespaceConflict(
  ignoreNamespaces: string[],
  bindingNamespaces: string[],
): boolean {
  return hasAnyOverlap(bindingNamespaces, ignoreNamespaces);
}

export function bindingAndCapabilityNSConflict(
  bindingNamespaces: string[],
  capabilityNamespaces: string[],
): boolean {
  if (!capabilityNamespaces) {
    return false;
  }
  return (
    capabilityNamespaces.length !== 0 && !hasEveryOverlap(bindingNamespaces, capabilityNamespaces)
  );
}

export function generateWatchNamespaceError(
  ignoredNamespaces: string[],
  bindingNamespaces: string[],
  capabilityNamespaces: string[],
): string {
  let err = "";

  // check if binding uses an ignored namespace
  if (ignoredNamespaceConflict(ignoredNamespaces, bindingNamespaces)) {
    err += `Binding uses a Pepr ignored namespace: ignoredNamespaces: [${ignoredNamespaces.join(
      ", ",
    )}] bindingNamespaces: [${bindingNamespaces.join(", ")}].`;
  }

  // ensure filter namespaces are part of capability namespaces
  if (bindingAndCapabilityNSConflict(bindingNamespaces, capabilityNamespaces)) {
    err += `Binding uses namespace not governed by capability: bindingNamespaces: [${bindingNamespaces.join(
      ", ",
    )}] capabilityNamespaces: [${capabilityNamespaces.join(", ")}].`;
  }

  // add a space if there is a period in the middle of the string
  return err.replace(/\.([^ ])/g, ". $1");
}

// namespaceComplianceValidator ensures that capability bindings respect ignored and capability namespaces
export function namespaceComplianceValidator(
  capability: CapabilityExport,
  ignoredNamespaces?: string[],
  watch?: boolean,
): void {
  const { namespaces: capabilityNamespaces, bindings, name } = capability;

  const shouldInclude = (binding: Binding): boolean => {
    if (watch === true) return !!binding.isWatch;
    if (watch === false) return !!binding.isMutate;
    return true;
  };

  const bindingNamespaces: string[] = bindings.flatMap(binding =>
    shouldInclude(binding) ? binding.filters.namespaces || [] : [],
  );

  const bindingRegexNamespaces: string[] = bindings.flatMap(binding =>
    shouldInclude(binding) ? binding.filters.regexNamespaces || [] : [],
  );

  const namespaceError = generateWatchNamespaceError(
    ignoredNamespaces ?? [],
    bindingNamespaces,
    capabilityNamespaces ?? [],
  );

  if (namespaceError !== "") {
    throw new Error(
      `Error in ${name} capability. A binding violates namespace rules. Please check ignoredNamespaces and capability namespaces: ${namespaceError}`,
    );
  }

  // Ensure that each regexNamespace matches a capabilityNamespace
  matchRegexToCapababilityNamespace(bindingRegexNamespaces, capabilityNamespaces);
  // ensure regexNamespaces do not match ignored ns
  checkRegexNamespaces(bindingRegexNamespaces, ignoredNamespaces);
}

const matchRegexToCapababilityNamespace = (
  bindingRegexNamespaces: string[],
  capabilityNamespaces: string[] | undefined,
): void => {
  if (
    bindingRegexNamespaces.length > 0 &&
    capabilityNamespaces &&
    capabilityNamespaces.length > 0
  ) {
    for (const regexNamespace of bindingRegexNamespaces) {
      let matches = false;
      matches =
        regexNamespace !== "" &&
        capabilityNamespaces.some(capabilityNamespace =>
          matchesRegex(regexNamespace, capabilityNamespace),
        );
      if (!matches) {
        throw new Error(
          `Ignoring Watch Callback: Object namespace does not match any capability namespace with regex ${regexNamespace}.`,
        );
      }
    }
  }
};

const checkRegexNamespaces = (
  bindingRegexNamespaces: string[],
  ignoredNamespaces: string[] | undefined,
): void => {
  if (bindingRegexNamespaces.length > 0 && ignoredNamespaces && ignoredNamespaces.length > 0) {
    for (const regexNamespace of bindingRegexNamespaces) {
      const matchedNS = ignoredNamespaces.find(ignoredNS =>
        matchesRegex(regexNamespace, ignoredNS),
      );
      if (matchedNS) {
        throw new Error(
          `Ignoring Watch Callback: Regex namespace: ${regexNamespace}, is an ignored namespace: ${matchedNS}.`,
        );
      }
    }
  }
};

// check if secret is over the size limit
export function secretOverLimit(str: string): boolean {
  const encoder = new TextEncoder();
  const encoded = encoder.encode(str);
  const sizeInBytes = encoded.length;
  const oneMiBInBytes = 1048576;
  return sizeInBytes > oneMiBInBytes;
}

export const parseTimeout = (value: string): number => {
  const parsedValue = parseInt(value, 10);
  const floatValue = parseFloat(value);
  if (isNaN(parsedValue)) {
    throw new Error("Not a number.");
  } else if (parsedValue !== floatValue) {
    throw new Error("Value must be an integer.");
  } else if (parsedValue < 1 || parsedValue > 30) {
    throw new Error("Number must be between 1 and 30.");
  }
  return parsedValue;
};

// Remove leading whitespace while keeping format of file
export function dedent(file: string): string {
  // Check if the first line is empty and remove it
  const lines = file.split("\n");
  if (lines[0].trim() === "") {
    lines.shift(); // Remove the first line if it's empty
    file = lines.join("\n"); // Rejoin the remaining lines back into a single string
  }

  const match = file.match(/^[ \t]*(?=\S)/gm);
  const indent = match && Math.min(...match.map(el => el.length));
  if (indent && indent > 0) {
    const re = new RegExp(`^[ \\t]{${indent}}`, "gm");
    return file.replace(re, "");
  }
  return file;
}

export function replaceString(str: string, stringA: string, stringB: string): string {
  // eslint-disable-next-line no-useless-escape
  const escapedStringA = stringA.replace(/[-\/\\^$*+?.()|[\]{}]/g, "\\$&");
  const regExp = new RegExp(escapedStringA, "g");
  return str.replace(regExp, stringB);
}
