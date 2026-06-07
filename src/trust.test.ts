import { describe, expect, it } from "vitest";

import { DEFAULT_TRUST_INPUTS, computeTrust, levelForScore } from "./trust.js";

describe("trust", () => {
  it("base score is medium", () => {
    expect(computeTrust(DEFAULT_TRUST_INPUTS)).toEqual({ score: 50, level: "medium" });
  });

  it("healthy device is verified", () => {
    expect(
      computeTrust({
        firmwareVerified: true,
        verifiedTelemetryEvents: 100,
        anomalyDetected: false,
        keyRotatedWithin7Days: true,
        heartbeatCount: 200,
      }),
    ).toEqual({ score: 95, level: "verified" });
  });

  it("anomaly subtracts 20", () => {
    expect(
      computeTrust({
        ...DEFAULT_TRUST_INPUTS,
        firmwareVerified: true,
        verifiedTelemetryEvents: 1,
        anomalyDetected: true,
      }),
    ).toEqual({ score: 45, level: "medium" });
  });

  it("telemetry bonus is capped", () => {
    expect(
      computeTrust({ ...DEFAULT_TRUST_INPUTS, verifiedTelemetryEvents: 1_000_000 }).score,
    ).toBe(70);
  });

  it("level thresholds", () => {
    expect(levelForScore(0)).toBe("critical");
    expect(levelForScore(20)).toBe("critical");
    expect(levelForScore(21)).toBe("low");
    expect(levelForScore(60)).toBe("medium");
    expect(levelForScore(80)).toBe("high");
    expect(levelForScore(81)).toBe("verified");
  });
});
