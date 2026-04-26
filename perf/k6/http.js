import http from "k6/http";
import { check, sleep } from "k6";

const vus = Number(__ENV.VUS || "10");
const duration = __ENV.DURATION || "30s";
const expectedStatus = Number(__ENV.EXPECTED_STATUS || "204");
const resultDir = __ENV.RESULT_DIR || ".";
const proxyURL = __ENV.PROXY_URL || __ENV.HTTP_PROXY || __ENV.http_proxy || "";
const targetURL =
  __ENV.TARGET_URL ||
  `http://${__ENV.TARGET_HOST || "127.0.0.1"}:${__ENV.TARGET_PORT || "18080"}${__ENV.TARGET_PATH || "/allowed"}`;

function requireProxyEnv() {
  if (!proxyURL) {
    throw new Error("PROXY_URL or HTTP_PROXY must be set");
  }
  if ((__ENV.HTTP_PROXY || __ENV.http_proxy || "") !== proxyURL) {
    throw new Error("HTTP_PROXY must match PROXY_URL for the HTTP scenario");
  }
}

export const options = {
  scenarios: {
    local_http: {
      executor: "constant-vus",
      vus,
      duration,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    checks: ["rate>0.99"],
  },
  summaryTrendStats: ["avg", "min", "med", "p(90)", "p(95)", "max"],
};

export default function () {
  requireProxyEnv();
  const response = http.get(targetURL, {
    tags: {
      scenario: "local-http",
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
    "Aegis local HTTP scenario",
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
