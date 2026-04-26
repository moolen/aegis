import http from "k6/http";
import { check, sleep } from "k6";

const vus = Number(__ENV.VUS || "10");
const duration = __ENV.DURATION || "30s";
const expectedStatus = Number(__ENV.EXPECTED_STATUS || "204");
const resultDir = __ENV.RESULT_DIR || ".";
const proxyURL = __ENV.PROXY_URL || __ENV.HTTPS_PROXY || __ENV.https_proxy || "";
const targetURL =
  __ENV.TARGET_URL ||
  `https://${__ENV.TARGET_HOST || "127.0.0.1"}:${__ENV.TARGET_PORT || "18443"}${__ENV.TARGET_PATH || "/allowed"}`;

function requireProxyEnv() {
  if (!proxyURL) {
    throw new Error("PROXY_URL or HTTPS_PROXY must be set");
  }
  if ((__ENV.HTTPS_PROXY || __ENV.https_proxy || "") !== proxyURL) {
    throw new Error("HTTPS_PROXY must match PROXY_URL for the CONNECT passthrough scenario");
  }
}

export const options = {
  scenarios: {
    local_connect_passthrough: {
      executor: "constant-vus",
      vus,
      duration,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    checks: ["rate>0.99"],
  },
  insecureSkipTLSVerify: true,
  summaryTrendStats: ["avg", "min", "med", "p(90)", "p(95)", "max"],
};

export default function () {
  requireProxyEnv();
  const response = http.get(targetURL, {
    tags: {
      scenario: "local-connect-passthrough",
      target: targetURL,
      proxy: proxyURL,
    },
  });

  check(response, {
    "status matches expected": (res) => res.status === expectedStatus,
  });

  sleep(Number(__ENV.SLEEP_SECONDS || "1"));
}

function metricValue(data, name, stat) {
  if (!data.metrics[name] || !data.metrics[name].values) {
    return "n/a";
  }

  const value = data.metrics[name].values[stat];
  return value === undefined ? "n/a" : value;
}

function renderSummary(data) {
  return [
    "Aegis local CONNECT passthrough scenario",
    `target=${targetURL}`,
    `proxy=${proxyURL || "unset"}`,
    `iterations=${metricValue(data, "iterations", "count")}`,
    `checks_rate=${metricValue(data, "checks", "rate")}`,
    `http_req_failed=${metricValue(data, "http_req_failed", "rate")}`,
    `http_req_duration_p95=${metricValue(data, "http_req_duration", "p(95)")}`,
    "",
  ].join("\n");
}

export function handleSummary(data) {
  return {
    [`${resultDir}/summary.json`]: JSON.stringify(data, null, 2),
    stdout: renderSummary(data),
  };
}
