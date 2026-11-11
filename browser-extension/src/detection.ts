import type { DetectionResult, ProtectedApplication } from "./types.js";

export function detectProtectedApplication(url: string, applications: ProtectedApplication[]): DetectionResult {
  for (const application of applications) {
    if (matchesPattern(url, application.originPattern)) {
      return { protected: true, application };
    }
  }
  return { protected: false };
}

export function matchesPattern(url: string, pattern: string): boolean {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`).test(url);
}
